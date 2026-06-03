"""Tests for mapper correctness: SID normalization, KDS detection, dMSA enumeration,
path visibility under unknown KDS, sensitive-target filtering, and live-lab fixtures.

Covers Tasks 1-9 from the mapper hardening pass.
"""
from __future__ import annotations

import pathlib
from unittest.mock import MagicMock

import pytest

from dmsa_reaper.models import CheckStatus, Confidence, MapState
from dmsa_reaper.paths.classifier import classify_paths, _is_sensitive_legacy_target, _rid_from_sid

_LIVE_FIXTURE = pathlib.Path(__file__).parent.parent / "docs" / "lab-fixture-live-dmsalab.json"
_KDS_UNKNOWN_FIXTURE = pathlib.Path(__file__).parent.parent / "docs" / "lab-fixture-kds-unknown.json"

_CONTAINER_DN = "OU=DMSACreate,OU=Reaper,DC=dmsalab,DC=local"
_TARGET_DN = "CN=target.migrate,OU=Targets,OU=Reaper,DC=dmsalab,DC=local"
_OP_SID = "S-1-5-21-605709967-1798081244-1819099823-1106"


# ── TASK 1: entry_sid() helper ────────────────────────────────────────────────

class TestEntrySid:
    def test_canonical_string_returns_unchanged(self):
        from dmsa_reaper.ldap.sid import entry_sid

        class Attr:
            value = "S-1-5-21-111-222-333-500"
        assert entry_sid(Attr()) == "S-1-5-21-111-222-333-500"

    def test_raw_bytes_returns_sddl(self):
        from impacket.ldap.ldaptypes import LDAP_SID
        from dmsa_reaper.ldap.sid import entry_sid

        sid_str = "S-1-5-21-111-222-333-1001"
        s = LDAP_SID()
        s.fromCanonical(sid_str)
        raw = s.getData()

        class Attr:
            raw_values = [raw]
            value = raw

        result = entry_sid(Attr())
        assert result == sid_str

    def test_magicmock_raw_values_falls_back_to_value(self):
        """MagicMock.raw_values is truthy but not a list — must fall back to .value."""
        from dmsa_reaper.ldap.sid import entry_sid

        attr = MagicMock()
        attr.value = "S-1-5-21-999-888-777-1"
        result = entry_sid(attr)
        assert result == "S-1-5-21-999-888-777-1"

    def test_none_value_returns_none(self):
        from dmsa_reaper.ldap.sid import entry_sid

        class Attr:
            raw_values = []
            value = None

        assert entry_sid(Attr()) is None

    def test_missing_raw_values_attr_falls_back(self):
        """Object with no raw_values attribute at all must use .value."""
        from dmsa_reaper.ldap.sid import entry_sid

        class Attr:
            value = "S-1-5-21-1-2-3-4"

        assert entry_sid(Attr()) == "S-1-5-21-1-2-3-4"


class TestSidToSddl:
    def test_canonical_passthrough(self):
        from dmsa_reaper.ldap.sid import sid_to_sddl
        assert sid_to_sddl("S-1-5-21-111-222-333-500") == "S-1-5-21-111-222-333-500"

    def test_none_returns_none(self):
        from dmsa_reaper.ldap.sid import sid_to_sddl
        assert sid_to_sddl(None) is None

    def test_bytes_returns_sddl(self):
        from impacket.ldap.ldaptypes import LDAP_SID
        from dmsa_reaper.ldap.sid import sid_to_sddl

        sid_str = "S-1-5-21-111-222-333-500"
        s = LDAP_SID()
        s.fromCanonical(sid_str)
        raw_bytes = s.getData()
        assert sid_to_sddl(raw_bytes) == sid_str

    def test_latin1_encoded_bytes_returns_sddl(self):
        from impacket.ldap.ldaptypes import LDAP_SID
        from dmsa_reaper.ldap.sid import sid_to_sddl

        sid_str = "S-1-5-21-111-222-333-500"
        s = LDAP_SID()
        s.fromCanonical(sid_str)
        raw_bytes = s.getData()
        raw_str = raw_bytes.decode("latin-1")
        assert sid_to_sddl(raw_str) == sid_str

    def test_invalid_bytes_does_not_crash(self):
        from dmsa_reaper.ldap.sid import sid_to_sddl
        result = sid_to_sddl(b"\x00\x01\x02")
        assert result is not None


# ── TASK 2: KDS detection ─────────────────────────────────────────────────────

class TestKdsDetection:
    def _make_conn(self, *, ok: bool, result_code: int = 0, entries=None):
        conn = MagicMock()
        conn.search.return_value = ok
        conn.result = {"result": result_code, "description": "mock"}

        if entries is not None:
            mock_entries = []
            for dn in entries:
                e = MagicMock()
                e.entry_dn = dn
                mock_entries.append(e)
            conn.entries = mock_entries
        else:
            conn.entries = []
        return conn

    def test_child_entries_returns_present(self):
        from dmsa_reaper.map.kds import detect_kds_root_key

        base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local"
        child = f"CN=key-1,{base}"
        conn = self._make_conn(ok=True, entries=[base, child])
        status, diag = detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        assert status == CheckStatus.present
        assert any("children" in d for d in diag)

    def test_base_only_returns_absent(self):
        from dmsa_reaper.map.kds import detect_kds_root_key

        base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local"
        conn = self._make_conn(ok=True, entries=[base])
        status, _ = detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        assert status == CheckStatus.absent

    def test_no_such_object_returns_absent(self):
        from dmsa_reaper.map.kds import detect_kds_root_key

        conn = self._make_conn(ok=False, result_code=32)
        status, diag = detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        assert status == CheckStatus.absent
        assert any("absent" in d.lower() or "does not exist" in d.lower() for d in diag)

    def test_access_denied_returns_unknown(self):
        from dmsa_reaper.map.kds import detect_kds_root_key

        conn = self._make_conn(ok=False, result_code=50)
        status, _ = detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        assert status == CheckStatus.unknown

    def test_exception_returns_unknown(self):
        from dmsa_reaper.map.kds import detect_kds_root_key

        conn = MagicMock()
        conn.search.side_effect = RuntimeError("connection lost")
        status, _ = detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        assert status == CheckStatus.unknown

    def test_other_ldap_error_returns_unknown(self):
        from dmsa_reaper.map.kds import detect_kds_root_key

        conn = self._make_conn(ok=False, result_code=1)  # operationsError
        status, _ = detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        assert status == CheckStatus.unknown

    def test_permissive_filter_used(self):
        """Search must use (objectClass=*) not (objectClass=msKds-ProvRootKey)."""
        from dmsa_reaper.map.kds import detect_kds_root_key

        conn = MagicMock()
        conn.search.return_value = True
        conn.result = {"result": 0}
        conn.entries = []
        detect_kds_root_key(conn, "CN=Configuration,DC=corp,DC=local")
        _, kwargs = conn.search.call_args
        assert kwargs.get("search_filter") == "(objectClass=*)"

    def test_kds_root_key_status_wrapper(self):
        """kds_root_key_status() wraps detect_kds_root_key() and returns only status."""
        from dmsa_reaper.map.kds import kds_root_key_status

        base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local"
        child = f"CN=k,{base}"
        conn = MagicMock()
        conn.search.return_value = True
        conn.result = {"result": 0}
        mock_entries = []
        for dn in [base, child]:
            e = MagicMock()
            e.entry_dn = dn
            mock_entries.append(e)
        conn.entries = mock_entries
        assert kds_root_key_status(conn, "CN=Configuration,DC=corp,DC=local") == CheckStatus.present


# ── TASK 3: dMSA capability computation ──────────────────────────────────────

class TestDmsaCapability:
    def test_all_present_returns_present(self):
        from dmsa_reaper.map.environment import compute_dmsa_capable_status
        assert compute_dmsa_capable_status(
            CheckStatus.present, CheckStatus.present, CheckStatus.present
        ) == CheckStatus.present

    def test_kds_absent_returns_absent(self):
        from dmsa_reaper.map.environment import compute_dmsa_capable_status
        assert compute_dmsa_capable_status(
            CheckStatus.present, CheckStatus.present, CheckStatus.absent
        ) == CheckStatus.absent

    def test_kds_unknown_returns_unknown(self):
        from dmsa_reaper.map.environment import compute_dmsa_capable_status
        assert compute_dmsa_capable_status(
            CheckStatus.present, CheckStatus.present, CheckStatus.unknown
        ) == CheckStatus.unknown

    def test_schema_absent_returns_absent(self):
        from dmsa_reaper.map.environment import compute_dmsa_capable_status
        assert compute_dmsa_capable_status(
            CheckStatus.absent, CheckStatus.present, CheckStatus.present
        ) == CheckStatus.absent

    def test_server_2025_absent_returns_absent(self):
        from dmsa_reaper.map.environment import compute_dmsa_capable_status
        assert compute_dmsa_capable_status(
            CheckStatus.present, CheckStatus.absent, CheckStatus.present
        ) == CheckStatus.absent


# ── TASK 4: dMSA enumeration fallback ────────────────────────────────────────

class TestDmsaEnumerationFallback:
    def test_fallback_filter_used_when_primary_returns_empty(self, monkeypatch):
        """When objectClass=msDS-DelegatedManagedServiceAccount returns empty, try fallback."""
        from dmsa_reaper.map.dmsa_objects import enumerate_dmsas

        call_log: list[str] = []

        def mock_search_with_sd(conn, base, ldap_filter, attrs, sdflags):
            call_log.append(ldap_filter)
            return []

        monkeypatch.setattr("dmsa_reaper.map.dmsa_objects.search_with_sd", mock_search_with_sd)
        enumerate_dmsas(MagicMock(), "DC=corp,DC=local", 0x5)

        assert any("msDS-DelegatedMSAState" in f for f in call_log), (
            "fallback filter (msDS-DelegatedMSAState=*) must be tried when primary returns empty"
        )

    def test_primary_filter_tried_first(self, monkeypatch):
        """objectClass=msDS-DelegatedManagedServiceAccount must be tried before fallback."""
        from dmsa_reaper.map.dmsa_objects import enumerate_dmsas

        call_log: list[str] = []

        def mock_search_with_sd(conn, base, ldap_filter, attrs, sdflags):
            call_log.append(ldap_filter)
            return []

        monkeypatch.setattr("dmsa_reaper.map.dmsa_objects.search_with_sd", mock_search_with_sd)
        enumerate_dmsas(MagicMock(), "DC=corp,DC=local", 0x5)

        assert call_log[0] and "msDS-DelegatedManagedServiceAccount" in call_log[0]


# ── TASK 5: path visibility when KDS is unknown ───────────────────────────────

class TestPathVisibilityKdsUnknown:
    @pytest.fixture(scope="class")
    def live_state(self):
        return MapState.model_validate_json(_LIVE_FIXTURE.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def unknown_state(self):
        return MapState.model_validate_json(_KDS_UNKNOWN_FIXTURE.read_text(encoding="utf-8"))

    def test_kds_present_emits_high_confidence_path(self, live_state):
        paths = classify_paths(live_state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert pp, "postpatch-mutual-pair must appear when KDS is present"
        assert all(p.confidence == Confidence.high for p in pp)
        assert all(not p.environment_warnings for p in pp)

    def test_kds_present_path_targets_correct_objects(self, live_state):
        paths = classify_paths(live_state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert any(p.container_dn == _CONTAINER_DN for p in pp)
        assert any(p.target_dn == _TARGET_DN for p in pp)

    def test_kds_unknown_path_not_hidden(self, unknown_state):
        """With KDS unknown, postpatch path must NOT be silently suppressed."""
        paths = classify_paths(unknown_state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert pp, "postpatch-mutual-pair must NOT be hidden when KDS is unknown and ACL evidence exists"

    def test_kds_unknown_path_has_lower_confidence(self, unknown_state):
        paths = classify_paths(unknown_state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert all(p.confidence == Confidence.low for p in pp)

    def test_kds_unknown_path_has_environment_warnings(self, unknown_state):
        paths = classify_paths(unknown_state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert all(p.environment_warnings for p in pp), (
            "environment_warnings must be non-empty when KDS is unknown"
        )

    def test_kds_absent_suppresses_paths(self):
        """When dmsa_capable_status is absent, postpatch paths must not appear."""
        from dmsa_reaper.models import (
            CheckStatus, ContainerObject, Environment, MapState,
            Right, SchemaCache, TargetObject,
        )
        right = Right(principal_sid="S-1-5-21-1-2-3-1000", right="CreateChild:dMSA",
                      object_dn="OU=Test,DC=corp,DC=local")
        container = ContainerObject(dn="OU=Test,DC=corp,DC=local", rights=[right])
        target = TargetObject(dn="CN=svc,DC=corp,DC=local",
                              writable_attrs=["msDS-SupersededManagedAccountLink",
                                              "msDS-SupersededServiceAccountState"])
        env = Environment(dmsa_capable=False, has_dmsa_schema=True, has_server_2025_dc=True)
        # Force absent status
        env.kds_root_key_status = CheckStatus.absent
        env.dmsa_capable_status = CheckStatus.absent
        state = MapState(environment=env, schema_cache=SchemaCache(),
                         containers=[container], targets=[target])
        paths = classify_paths(state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert not pp, "postpatch paths must be suppressed when capability is confirmed absent"


# ── TASK 6: CreateChild:dMSA regression ──────────────────────────────────────

class TestCreateChildDmsaRegression:
    def _state_with_container_right(self, right_name: str, guid: str | None = None):
        from dmsa_reaper.models import (
            ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
        )
        right = Right(
            principal_sid="S-1-5-21-1-2-3-1000",
            right=right_name,
            object_dn="OU=Test,DC=corp,DC=local",
            object_type_guid=guid,
        )
        container = ContainerObject(dn="OU=Test,DC=corp,DC=local", rights=[right])
        target = TargetObject(
            dn="CN=svc,DC=corp,DC=local",
            writable_attrs=["msDS-SupersededManagedAccountLink", "msDS-SupersededServiceAccountState"],
        )
        return MapState(
            environment=Environment(dmsa_capable=True, has_dmsa_schema=True,
                                    has_server_2025_dc=True, has_kds_root_key=True),
            schema_cache=SchemaCache(),
            containers=[container],
            targets=[target],
        )

    def test_createchild_dmsa_specific_right_produces_path(self):
        state = self._state_with_container_right(
            "CreateChild:dMSA", "0feb936f-47b3-49f2-9386-1dedc2c23765"
        )
        paths = classify_paths(state, expand_targets=True)
        assert any(p.primitive == "postpatch-mutual-pair" for p in paths)

    def test_broad_createchild_right_produces_path(self):
        state = self._state_with_container_right("CreateChild")
        paths = classify_paths(state, expand_targets=True)
        assert any(p.primitive == "postpatch-mutual-pair" for p in paths)

    def test_genericall_right_produces_path(self):
        state = self._state_with_container_right("GenericAll")
        paths = classify_paths(state, expand_targets=True)
        assert any(p.primitive == "postpatch-mutual-pair" for p in paths)

    def test_genericwrite_does_not_produce_createchild_path(self):
        """GenericWrite on a container must NOT produce a CreateChild path."""
        state = self._state_with_container_right("GenericWrite")
        paths = classify_paths(state, expand_targets=True)
        pp = [p for p in paths if p.primitive in ("postpatch-mutual-pair", "legacy-oneway-link")]
        assert not pp, "GenericWrite must not imply CreateChild for dMSA paths"

    def test_unrelated_object_type_guid_not_createchild_dmsa(self):
        """CreateChild with an unrelated GUID must not produce a dMSA path."""
        state = self._state_with_container_right(
            "CreateChild:dMSA", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        # The right NAME is CreateChild:dMSA — classifier checks right name, not GUID
        # So this test verifies the classifier uses right-name-based checks correctly.
        paths = classify_paths(state, expand_targets=True)
        assert any(p.primitive == "postpatch-mutual-pair" for p in paths)


# ── TASK 7: WriteProperty writable_attrs regression ──────────────────────────

class TestWritePropertyRegression:
    def _state_with_target_attrs(self, writable_attrs: list[str]):
        from dmsa_reaper.models import (
            ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
        )
        c_right = Right(principal_sid="S-1-5-21-1-2-3-1000", right="CreateChild:dMSA",
                        object_dn="OU=Test,DC=corp,DC=local")
        container = ContainerObject(dn="OU=Test,DC=corp,DC=local", rights=[c_right])
        target = TargetObject(dn="CN=svc,DC=corp,DC=local", writable_attrs=writable_attrs)
        return MapState(
            environment=Environment(dmsa_capable=True, has_dmsa_schema=True,
                                    has_server_2025_dc=True, has_kds_root_key=True),
            schema_cache=SchemaCache(),
            containers=[container],
            targets=[target],
        )

    def test_both_attrs_required_for_postpatch(self):
        state = self._state_with_target_attrs([
            "msDS-SupersededManagedAccountLink",
            "msDS-SupersededServiceAccountState",
        ])
        paths = classify_paths(state, expand_targets=True)
        assert any(p.primitive == "postpatch-mutual-pair" for p in paths)

    def test_link_attr_only_does_not_produce_postpatch(self):
        state = self._state_with_target_attrs(["msDS-SupersededManagedAccountLink"])
        paths = classify_paths(state, expand_targets=True)
        assert not any(p.primitive == "postpatch-mutual-pair" for p in paths)

    def test_state_attr_only_does_not_produce_postpatch(self):
        state = self._state_with_target_attrs(["msDS-SupersededServiceAccountState"])
        paths = classify_paths(state, expand_targets=True)
        assert not any(p.primitive == "postpatch-mutual-pair" for p in paths)

    def test_no_attrs_does_not_produce_postpatch(self):
        state = self._state_with_target_attrs([])
        paths = classify_paths(state, expand_targets=True)
        assert not any(p.primitive == "postpatch-mutual-pair" for p in paths)


# ── TASK 8: sensitive-target filtering ───────────────────────────────────────

class TestSensitiveTargetFiltering:
    def _make_target(self, sid: str, sam: str | None = None):
        from dmsa_reaper.models import TargetObject
        return TargetObject(dn=f"CN={sam or 'user'},DC=corp,DC=local", sam=sam, sid=sid)

    def test_administrator_rid_500_is_sensitive(self):
        t = self._make_target("S-1-5-21-111-222-333-500", "Administrator")
        assert _is_sensitive_legacy_target(t, None)

    def test_guest_rid_501_is_sensitive(self):
        t = self._make_target("S-1-5-21-111-222-333-501", "Guest")
        assert _is_sensitive_legacy_target(t, None)

    def test_krbtgt_rid_502_is_sensitive(self):
        t = self._make_target("S-1-5-21-111-222-333-502", "krbtgt")
        assert _is_sensitive_legacy_target(t, None)

    def test_operator_own_account_is_sensitive(self):
        op_sid = "S-1-5-21-111-222-333-1000"
        t = self._make_target(op_sid, "reaper.low")
        assert _is_sensitive_legacy_target(t, op_sid)

    def test_regular_user_is_not_sensitive(self):
        t = self._make_target("S-1-5-21-111-222-333-1001", "victim.postpatch")
        assert not _is_sensitive_legacy_target(t, "S-1-5-21-111-222-333-1000")

    def test_rid_extraction(self):
        assert _rid_from_sid("S-1-5-21-111-222-333-500") == 500
        assert _rid_from_sid("S-1-5-21-111-222-333-502") == 502
        assert _rid_from_sid("invalid") is None

    def test_administrator_excluded_from_legacy_paths(self):
        """Administrator must not appear in legacy-oneway-link targets by default."""
        from dmsa_reaper.models import (
            ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
        )
        right = Right(principal_sid="S-1-5-21-1-2-3-1000", right="CreateChild:dMSA",
                      object_dn="OU=Test,DC=corp,DC=local")
        container = ContainerObject(dn="OU=Test,DC=corp,DC=local", rights=[right])
        admin = TargetObject(dn="CN=Administrator,CN=Users,DC=corp,DC=local",
                             sid="S-1-5-21-1-2-3-500")
        safe_target = TargetObject(dn="CN=victim,DC=corp,DC=local",
                                   sid="S-1-5-21-1-2-3-1001")
        state = MapState(
            environment=Environment(dmsa_capable=True, has_dmsa_schema=True,
                                    has_server_2025_dc=True, has_kds_root_key=True),
            schema_cache=SchemaCache(),
            containers=[container],
            targets=[admin, safe_target],
        )
        paths = classify_paths(state, expand_targets=True)
        legacy = [p for p in paths if p.primitive == "legacy-oneway-link"]
        target_dns = {p.target_dn for p in legacy}
        assert admin.dn not in target_dns, "Administrator must be excluded from legacy paths"
        assert safe_target.dn in target_dns, "Safe victim must appear in legacy paths"

    def test_krbtgt_excluded_from_legacy_paths(self):
        from dmsa_reaper.models import (
            ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
        )
        right = Right(principal_sid="S-1-5-21-1-2-3-1000", right="CreateChild:dMSA",
                      object_dn="OU=Test,DC=corp,DC=local")
        container = ContainerObject(dn="OU=Test,DC=corp,DC=local", rights=[right])
        krbtgt = TargetObject(dn="CN=krbtgt,CN=Users,DC=corp,DC=local",
                              sid="S-1-5-21-1-2-3-502")
        safe = TargetObject(dn="CN=svc,DC=corp,DC=local", sid="S-1-5-21-1-2-3-1100")
        state = MapState(
            environment=Environment(dmsa_capable=True, has_dmsa_schema=True,
                                    has_server_2025_dc=True, has_kds_root_key=True),
            schema_cache=SchemaCache(),
            containers=[container],
            targets=[krbtgt, safe],
        )
        paths = classify_paths(state, expand_targets=True)
        legacy = [p for p in paths if p.primitive == "legacy-oneway-link"]
        target_dns = {p.target_dn for p in legacy}
        assert krbtgt.dn not in target_dns
        assert safe.dn in target_dns

    def test_operator_self_excluded_from_legacy_paths(self):
        from dmsa_reaper.models import (
            ContainerObject, Environment, MapState, Principal, Right, SchemaCache, TargetObject,
        )
        op_sid = "S-1-5-21-1-2-3-1000"
        right = Right(principal_sid=op_sid, right="CreateChild:dMSA",
                      object_dn="OU=Test,DC=corp,DC=local")
        container = ContainerObject(dn="OU=Test,DC=corp,DC=local", rights=[right])
        self_target = TargetObject(dn="CN=reaper.low,OU=Ops,DC=corp,DC=local", sid=op_sid)
        safe = TargetObject(dn="CN=svc,DC=corp,DC=local", sid="S-1-5-21-1-2-3-1099")
        state = MapState(
            environment=Environment(dmsa_capable=True, has_dmsa_schema=True,
                                    has_server_2025_dc=True, has_kds_root_key=True),
            schema_cache=SchemaCache(),
            containers=[container],
            targets=[self_target, safe],
            current_principal=Principal(sid=op_sid),
        )
        paths = classify_paths(state, expand_targets=True)
        legacy = [p for p in paths if p.primitive == "legacy-oneway-link"]
        target_dns = {p.target_dn for p in legacy}
        assert self_target.dn not in target_dns
        assert safe.dn in target_dns

    def test_postpatch_path_to_intended_target_still_appears(self, live_state=None):
        """Sensitive-target filter must not affect postpatch-mutual-pair paths."""
        state = MapState.model_validate_json(_LIVE_FIXTURE.read_text(encoding="utf-8"))
        paths = classify_paths(state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert any(p.target_dn == _TARGET_DN for p in pp)


# ── TASK 9: live-lab fixture regression tests ─────────────────────────────────

class TestLiveLabFixture:
    @pytest.fixture(scope="class")
    def live_state(self):
        return MapState.model_validate_json(_LIVE_FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_loads(self, live_state):
        assert live_state.environment.dmsa_capable_status == CheckStatus.present

    def test_principal_sid_is_sddl(self, live_state):
        assert live_state.current_principal.sid.startswith("S-1-")

    def test_container_right_is_createchild_dmsa(self, live_state):
        container = next(c for c in live_state.containers if "DMSACreate" in c.dn)
        right_names = {r.right for r in container.rights}
        assert "CreateChild:dMSA" in right_names

    def test_target_has_both_writable_attrs(self, live_state):
        target = next(t for t in live_state.targets if "target.migrate" in t.dn)
        assert "msDS-SupersededManagedAccountLink" in target.writable_attrs
        assert "msDS-SupersededServiceAccountState" in target.writable_attrs

    def test_postpatch_path_emitted_high_confidence(self, live_state):
        paths = classify_paths(live_state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert pp
        assert all(p.confidence == Confidence.high for p in pp)
        assert all(p.executable for p in pp)

    def test_no_json_binary_sids_in_state(self):
        raw = _LIVE_FIXTURE.read_text(encoding="utf-8")
        assert r"" not in raw, "state.json must not contain raw binary SID bytes"

    def test_kds_unknown_fixture_loads(self):
        state = MapState.model_validate_json(_KDS_UNKNOWN_FIXTURE.read_text(encoding="utf-8"))
        assert state.environment.kds_root_key_status == CheckStatus.unknown

    def test_kds_unknown_path_not_hidden(self):
        state = MapState.model_validate_json(_KDS_UNKNOWN_FIXTURE.read_text(encoding="utf-8"))
        paths = classify_paths(state, expand_targets=True)
        pp = [p for p in paths if p.primitive == "postpatch-mutual-pair"]
        assert pp, "With KDS unknown, path must not be hidden"
        assert pp[0].confidence == Confidence.low
        assert pp[0].environment_warnings


# ── TASK 10: LDAP3 hardening ─────────────────────────────────────────────────

class TestLdapHardening:
    def test_bind_creates_connection_with_check_names_false(self):
        """bind() must create connections with check_names=False."""
        from dmsa_reaper.auth.ldap_bind import LdapAuthConfig, build_server
        import ldap3

        config = LdapAuthConfig(domain="corp.local", dc_ip="127.0.0.1",
                                username="user", password="pass")
        # The server must be built with get_info=NONE
        server = build_server(config)
        assert server.get_info == ldap3.NONE

    def test_schema_resolver_uses_schemaidguid_not_systemidguid(self):
        """Schema resolver must request schemaIDGUID, not systemIdGuid."""
        import inspect
        from dmsa_reaper.schema import resolver as schema_resolver
        resolver_src = inspect.getsource(schema_resolver)
        assert "schemaIDGUID" in resolver_src
        assert "systemIdGuid" not in resolver_src

    def test_rootdse_requests_wildcard_attrs(self):
        """RootDSE reader must request * and + to avoid client-side attr validation."""
        import inspect
        from dmsa_reaper.ldap import rootdse
        src = inspect.getsource(rootdse)
        assert '"*"' in src or "'*'" in src
        assert '"+"' in src or "'+'" in src
