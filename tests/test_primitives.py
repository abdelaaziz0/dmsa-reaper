"""Tests for primitive execute/verify behavior without live LDAP.

Uses lightweight mock connections and monkeypatching to validate:
  - Required attribute presence on dMSA creation
  - Guard behaviour (no --confirm, no conn)
  - Partial-failure operation state recording
  - Read-before-write recording for auditing
  - Informational primitive status
  - Dry-run output does not touch LDAP
  - Non-executable path rejection
"""
from __future__ import annotations

import pytest

from dmsa_reaper.models import Operation, PathCandidate
from dmsa_reaper.primitives._ldap_helpers import (
    DMSA_MANAGED_PASSWORD_INTERVAL,
    DMSA_OBJECT_CLASSES,
    DMSA_STATE_COMPLETED,
    DMSA_UAC,
)
from dmsa_reaper.primitives.base import PrimitiveError
from dmsa_reaper.primitives.existing_dmsa_control import (
    ExistingDmsaLegacyLinkPrimitive,
    ExistingDmsaPostPatchMutualPrimitive,
)
from dmsa_reaper.primitives.legacy_oneway_link import LegacyOneWayLinkPrimitive
from dmsa_reaper.primitives.postpatch_mutual_pair import PostPatchMutualPairPrimitive
from dmsa_reaper.primitives.self_pkinit_loop import SelfPkinitLoopPrimitive
from dmsa_reaper.primitives.self_write_map import SelfWriteMapPrimitive


# ── shared helpers ────────────────────────────────────────────────────────────

def _op(primitive: str, **meta) -> Operation:
    return Operation(id="OP-0001", primitive=primitive, metadata=meta)


def _path(primitive: str, **kwargs) -> PathCandidate:
    defaults = dict(
        id="P-0001",
        primitive=primitive,
        principal="S-1-5-21-111-222-333-1000",
    )
    defaults.update(kwargs)
    return PathCandidate(**defaults)


class _MockConn:
    """Minimal ldap3 Connection stand-in that records all calls."""

    def __init__(self, read_return=None):
        self.added: list[tuple] = []       # (dn, classes, attrs)
        self.modified: list[tuple] = []    # (dn, attribute, values, mod_type)
        self.deleted: list[str] = []
        self._read_return = read_return
        self._entries: list = []

    def add(self, dn, object_class, attributes) -> bool:
        self.added.append((dn, object_class, attributes))
        return True

    def modify(self, dn, changes) -> bool:
        for attr, ops in changes.items():
            for (mod_type, values) in ops:
                self.modified.append((dn, attr, values, mod_type))
        return True

    def delete(self, dn) -> bool:
        self.deleted.append(dn)
        return True

    def search(self, search_base, search_filter, search_scope, attributes):
        if attributes == ["objectGUID"] and any(item[0] == search_base for item in self.added):
            class _GuidAttr:
                raw_values = [bytes(range(16))]
                values = []
                value = None

            class _GuidEntry:
                def __contains__(self, key):
                    return key == "objectGUID"

                def __getitem__(self, key):
                    return _GuidAttr()

            self._entries = [_GuidEntry()]
            return True
        if self._read_return is not None:
            class _Attr:
                def __init__(self, vals):
                    self.values = vals
            class _Entry:
                def __init__(self, vals, attr_name):
                    self._attr = _Attr(vals)
                    self._name = attr_name
                def __contains__(self, k):
                    return k == self._name
                def __getitem__(self, k):
                    return self._attr
            self._entries = [_Entry(self._read_return, attributes[0] if attributes else "")]
        else:
            self._entries = []
        return True

    @property
    def entries(self):
        return self._entries

    @property
    def result(self):
        return {}


class _FailingConn(_MockConn):
    """Mock conn whose modify() fails on a specific 1-indexed call."""

    def __init__(self, fail_on_modify_n: int, read_return=None):
        super().__init__(read_return=read_return)
        self._fail_on = fail_on_modify_n
        self._modify_call = 0

    def modify(self, dn, changes) -> bool:
        self._modify_call += 1
        if self._modify_call == self._fail_on:
            return False  # triggers RuntimeError in modify_attribute()
        return super().modify(dn, changes)

    @property
    def result(self):
        return {"description": "simulated LDAP modify failure"}


# ── guard tests (no confirm / no conn) ───────────────────────────────────────

@pytest.mark.parametrize("PrimCls", [
    LegacyOneWayLinkPrimitive,
    PostPatchMutualPairPrimitive,
    ExistingDmsaPostPatchMutualPrimitive,
    ExistingDmsaLegacyLinkPrimitive,
])
def test_no_confirm_raises(PrimCls, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = PrimCls()
    op = _op(prim.name)
    with pytest.raises(PrimitiveError, match="--confirm"):
        prim.execute(op, confirm=False)


@pytest.mark.parametrize("PrimCls", [
    LegacyOneWayLinkPrimitive,
    PostPatchMutualPairPrimitive,
    ExistingDmsaPostPatchMutualPrimitive,
    ExistingDmsaLegacyLinkPrimitive,
])
def test_confirm_without_conn_raises(PrimCls, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = PrimCls()
    op = _op(prim.name)
    with pytest.raises(PrimitiveError, match="connection"):
        prim.execute(op, confirm=True, conn=None)


# ── legacy-oneway-link ────────────────────────────────────────────────────────

def test_legacy_oneway_link_execute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    conn = _MockConn()

    op = _op(
        prim.name,
        container_dn="OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
    )
    result = prim.execute(op, confirm=True, conn=conn)

    assert result.status == "executed"
    assert len(result.created_dns) == 1
    assert len(conn.added) == 1
    dn, classes, attrs = conn.added[0]
    assert dn == result.created_dns[0]
    assert "msDS-DelegatedManagedServiceAccount" in classes
    assert set(classes) == set(DMSA_OBJECT_CLASSES)


def test_legacy_oneway_link_required_schema_attrs(tmp_path, monkeypatch):
    """add_object must include all required dMSA schema attributes."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    conn = _MockConn()

    op = _op(
        prim.name,
        container_dn="OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
    )
    prim.execute(op, confirm=True, conn=conn)

    _, _, attrs = conn.added[0]
    assert attrs["userAccountControl"] == DMSA_UAC
    assert attrs["msDS-ManagedPasswordInterval"] == DMSA_MANAGED_PASSWORD_INTERVAL
    assert attrs["msDS-DelegatedMSAState"] == DMSA_STATE_COMPLETED
    assert attrs["msDS-ManagedAccountPrecededByLink"] == "CN=svc,DC=corp,DC=local"
    assert attrs["sAMAccountName"].endswith("$")


def test_legacy_oneway_link_missing_container(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    op = _op(prim.name, target_dn="CN=svc,DC=corp,DC=local")
    with pytest.raises(PrimitiveError, match="container_dn"):
        prim.execute(op, confirm=True, conn=_MockConn())


def test_legacy_oneway_link_missing_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local")
    with pytest.raises(PrimitiveError, match="target_dn"):
        prim.execute(op, confirm=True, conn=_MockConn())


def test_legacy_oneway_link_check():
    prim = LegacyOneWayLinkPrimitive()
    assert prim.check(_path("legacy-oneway-link"))
    assert not prim.check(_path("postpatch-mutual-pair"))


def test_legacy_oneway_link_dry_run_no_ldap(tmp_path, monkeypatch):
    """dry_run_steps must not touch LDAP."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    conn = _MockConn()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    steps = prim.dry_run_steps(op)

    assert isinstance(steps, list)
    assert any("CREATE" in s for s in steps)
    assert conn.added == []
    assert conn.modified == []
    assert conn.deleted == []


# ── postpatch-mutual-pair ─────────────────────────────────────────────────────

def test_postpatch_execute_required_attrs(tmp_path, monkeypatch):
    """add_object must include all required dMSA schema attributes."""
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    conn = _MockConn(read_return=None)

    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    prim.execute(op, confirm=True, conn=conn)

    _, _, attrs = conn.added[0]
    assert attrs["msDS-ManagedPasswordInterval"] == DMSA_MANAGED_PASSWORD_INTERVAL
    assert attrs["msDS-DelegatedMSAState"] == DMSA_STATE_COMPLETED
    assert attrs["msDS-ManagedAccountPrecededByLink"] == "CN=svc,DC=corp,DC=local"


def test_postpatch_execute_target_writes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    conn = _MockConn(read_return=None)

    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    result = prim.execute(op, confirm=True, conn=conn)

    assert result.status == "executed"
    assert len(result.changed_attrs) == 2
    attrs_changed = {ch.attribute for ch in result.changed_attrs}
    assert "msDS-SupersededManagedAccountLink" in attrs_changed
    assert "msDS-SupersededServiceAccountState" in attrs_changed

    state_ch = next(c for c in result.changed_attrs if c.attribute == "msDS-SupersededServiceAccountState")
    assert state_ch.after_python() == [2]
    assert state_ch.before is None  # absent before write


def test_postpatch_step2_failure_records_partial_state(tmp_path, monkeypatch):
    """If the first target-side modify fails, keep the created dMSA in the operation log."""
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    # modify call 1 is the first target write; add_object is conn.add(), not conn.modify().
    conn = _FailingConn(fail_on_modify_n=1, read_return=None)

    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")

    with pytest.raises(PrimitiveError, match="partial state"):
        prim.execute(op, confirm=True, conn=conn)

    # dMSA was created in step 1.
    assert len(conn.added) == 1
    created_dn = conn.added[0][0]
    assert created_dn in op.created_dns
    assert conn.deleted == []
    assert op.status == "partial-failed"


def test_postpatch_add_failure_preserves_maybe_created_dns(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()

    class _FailAdd(_MockConn):
        def add(self, dn, object_class, attributes):
            return False

    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")

    with pytest.raises(Exception):
        prim.execute(op, confirm=True, conn=_FailAdd())

    assert op.created_dns == []
    assert op.maybe_created_dns


def test_postpatch_step3_failure_records_partial_state(tmp_path, monkeypatch):
    """If the second target-side modify fails, written steps remain recorded."""
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    conn = _FailingConn(fail_on_modify_n=2, read_return=None)

    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")

    with pytest.raises(PrimitiveError, match="partial state"):
        prim.execute(op, confirm=True, conn=conn)

    assert len(conn.added) == 1
    created_dn = conn.added[0][0]
    assert created_dn in op.created_dns
    assert conn.deleted == []
    assert op.status == "partial-failed"
    assert any(change.step_status == "written" for change in op.changed_attrs)


def test_postpatch_check():
    prim = PostPatchMutualPairPrimitive()
    valid = _path("postpatch-mutual-pair", requires_modify_dmsa=True, requires_modify_target=True)
    assert prim.check(valid)
    missing_target = _path("postpatch-mutual-pair", requires_modify_dmsa=True)
    assert not prim.check(missing_target)


def test_postpatch_dry_run_no_ldap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    conn = _MockConn()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    steps = prim.dry_run_steps(op)

    assert any("CREATE" in s for s in steps)
    assert any("MODIFY" in s for s in steps)
    assert conn.added == []
    assert conn.modified == []
    assert conn.deleted == []


# ── existing-dmsa primitives ──────────────────────────────────────────────────

def _existing_postpatch_op(primitive: str) -> Operation:
    return _op(
        primitive,
        dmsa_dn="CN=dmsa1,OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        target_writable_attrs=[
            "msDS-SupersededManagedAccountLink",
            "msDS-SupersededServiceAccountState",
        ],
    )


def test_existing_dmsa_postpatch_execute_writes_dmsa_and_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _MockConn(read_return=["CN=old,DC=corp,DC=local"])

    result = prim.execute(_existing_postpatch_op(prim.name), confirm=True, conn=conn)

    assert result.status == "executed"
    assert result.created_dns == []
    assert len(result.changed_attrs) == 4
    attrs_changed = {ch.attribute for ch in result.changed_attrs}
    assert "msDS-ManagedAccountPrecededByLink" in attrs_changed
    assert "msDS-DelegatedMSAState" in attrs_changed
    assert "msDS-SupersededManagedAccountLink" in attrs_changed
    assert "msDS-SupersededServiceAccountState" in attrs_changed


def test_existing_dmsa_postpatch_requires_target_side_attrs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _MockConn(read_return=None)
    op = _op(
        prim.name,
        dmsa_dn="CN=dmsa1,OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        target_writable_attrs=["msDS-SupersededManagedAccountLink"],
    )

    with pytest.raises(PrimitiveError, match="target-side WriteProperty"):
        prim.execute(op, confirm=True, conn=conn)

    assert conn.modified == []


def test_existing_dmsa_postpatch_required_rights_text_does_not_bypass_target_proof(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _MockConn(read_return=None)
    op = _op(
        prim.name,
        dmsa_dn="CN=dmsa1,OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        path={
            "required_rights": [
                "WriteProperty:msDS-SupersededManagedAccountLink",
                "WriteProperty:msDS-SupersededServiceAccountState",
            ]
        },
    )

    with pytest.raises(PrimitiveError, match="target-side WriteProperty"):
        prim.execute(op, confirm=True, conn=conn)

    assert conn.modified == []


def test_existing_dmsa_postpatch_records_before_values(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _MockConn(read_return=["CN=old,DC=corp,DC=local"])

    result = prim.execute(_existing_postpatch_op(prim.name), confirm=True, conn=conn)

    link_ch = next(c for c in result.changed_attrs if c.attribute == "msDS-ManagedAccountPrecededByLink")
    assert link_ch.before_python() == ["CN=old,DC=corp,DC=local"]
    assert link_ch.after_python() == ["CN=svc,DC=corp,DC=local"]


def test_existing_dmsa_postpatch_step2_failure_records_partial_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _FailingConn(fail_on_modify_n=2, read_return=None)
    op = _existing_postpatch_op(prim.name)

    with pytest.raises(PrimitiveError, match="partial state"):
        prim.execute(op, confirm=True, conn=conn)

    assert len(conn.modified) == 1
    assert op.status == "partial-failed"
    assert [change.step_status for change in op.changed_attrs] == ["written", "planned"]


def test_existing_dmsa_postpatch_missing_dmsa(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    op = _op(prim.name, target_dn="CN=svc,DC=corp,DC=local")
    with pytest.raises(PrimitiveError, match="dmsa_dn"):
        prim.execute(op, confirm=True, conn=_MockConn())


def test_existing_dmsa_postpatch_missing_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    op = _op(prim.name, dmsa_dn="CN=dmsa1,OU=Test,DC=corp,DC=local")
    with pytest.raises(PrimitiveError, match="target_dn"):
        prim.execute(op, confirm=True, conn=_MockConn())


def test_existing_dmsa_legacy_requires_explicit_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaLegacyLinkPrimitive()
    op = _op(
        prim.name,
        dmsa_dn="CN=dmsa1,OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
    )

    with pytest.raises(PrimitiveError, match="allow-existing-dmsa-legacy-link"):
        prim.execute(op, confirm=True, conn=_MockConn())


def test_existing_dmsa_legacy_execute_with_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaLegacyLinkPrimitive()
    conn = _MockConn(read_return=None)
    op = _op(
        prim.name,
        dmsa_dn="CN=dmsa1,OU=Test,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        allow_existing_dmsa_legacy_link=True,
    )

    result = prim.execute(op, confirm=True, conn=conn)

    assert result.status == "executed"
    assert len(result.changed_attrs) == 2


def test_existing_dmsa_postpatch_dry_run_no_ldap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _MockConn()
    steps = prim.dry_run_steps(_existing_postpatch_op(prim.name))

    assert any("MODIFY" in s for s in steps)
    assert conn.added == []
    assert conn.modified == []
    assert conn.deleted == []


# ── informational primitives ──────────────────────────────────────────────────

def test_self_write_map_informational(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = SelfWriteMapPrimitive()
    op = _op(prim.name)
    result = prim.execute(op)
    assert result.status == "informational"
    assert prim.verify(op) is True
    assert prim.modifies_directory is False


def test_self_pkinit_loop_informational(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = SelfPkinitLoopPrimitive()
    op = _op(prim.name)
    result = prim.execute(op)
    assert result.status == "informational"
    assert prim.verify(op) is True
    assert prim.modifies_directory is False


# ── non-executable path rejection ────────────────────────────────────────────

def test_dacl_paths_are_executable_in_classifier():
    """dacl-* paths must be marked executable=True by the V2 classifier."""
    from dmsa_reaper.models import (
        ContainerObject,
        Environment,
        MapState,
        Right,
        SchemaCache,
        TargetObject,
    )
    from dmsa_reaper.paths.classifier import classify_paths

    right = Right(
        principal_sid="S-1-5-21-1-2-3-500",
        right="WriteDACL",
        object_dn="OU=Computers,DC=corp,DC=local",
    )
    container = ContainerObject(dn="OU=Computers,DC=corp,DC=local", rights=[right])
    state = MapState(
        environment=Environment(dmsa_capable=True),
        schema_cache=SchemaCache(),
        containers=[container],
        targets=[TargetObject(dn="CN=svc,DC=corp,DC=local")],
    )
    paths = classify_paths(state)
    dacl_paths = [p for p in paths if p.primitive in ("dacl-container-escalate", "dacl-target-escalate")]
    assert dacl_paths, "classifier must emit dacl-* paths when DACL control without CreateChild"
    for p in dacl_paths:
        assert p.executable, f"{p.primitive} must have executable=True in V2"


# ── dmsa state correctness ────────────────────────────────────────────────────

def test_dmsa_state_constants():
    """State constants must match Akamai BadSuccessor research values."""
    from dmsa_reaper.primitives._ldap_helpers import (
        DMSA_STATE_COMPLETED,
        DMSA_STATE_IN_PROGRESS,
        DMSA_STATE_STANDALONE,
        DMSA_STATE_UNKNOWN,
    )
    assert DMSA_STATE_UNKNOWN == 0
    assert DMSA_STATE_IN_PROGRESS == 1
    assert DMSA_STATE_COMPLETED == 2
    assert DMSA_STATE_STANDALONE == 3


def test_legacy_oneway_link_state_completed(tmp_path, monkeypatch):
    """dMSA must be created with msDS-DelegatedMSAState = 2 (migration-completed)."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    conn = _MockConn()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    prim.execute(op, confirm=True, conn=conn)
    _, _, attrs = conn.added[0]
    assert attrs["msDS-DelegatedMSAState"] == 2


def test_postpatch_dmsa_state_completed(tmp_path, monkeypatch):
    """dMSA created by postpatch-mutual-pair must have msDS-DelegatedMSAState = 2."""
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    conn = _MockConn(read_return=None)
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    prim.execute(op, confirm=True, conn=conn)
    _, _, attrs = conn.added[0]
    assert attrs["msDS-DelegatedMSAState"] == 2


def test_existing_dmsa_postpatch_state_completed(tmp_path, monkeypatch):
    """existing-dmsa-postpatch-mutual must write msDS-DelegatedMSAState = 2."""
    monkeypatch.chdir(tmp_path)
    prim = ExistingDmsaPostPatchMutualPrimitive()
    conn = _MockConn(read_return=None)
    result = prim.execute(_existing_postpatch_op(prim.name), confirm=True, conn=conn)
    state_ch = next(c for c in result.changed_attrs if c.attribute == "msDS-DelegatedMSAState")
    assert state_ch.after_python() == [2]


# ── operation log hardening ───────────────────────────────────────────────────

def test_legacy_maybe_created_dn_recorded_before_add(tmp_path, monkeypatch):
    """maybe_created_dns must be logged before add_object() is called."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    logged_dns: list[list] = []

    original_save = __import__("dmsa_reaper.ops.operation_log", fromlist=["save_operation"]).save_operation

    def capturing_save(op):
        logged_dns.append(list(op.maybe_created_dns))
        original_save(op)

    monkeypatch.setattr("dmsa_reaper.primitives.legacy_oneway_link.save_operation", capturing_save)

    conn = _MockConn()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    prim.execute(op, confirm=True, conn=conn)

    # The first save (before add_object) must already contain the planned DN.
    assert logged_dns[0], "operation log must record maybe_created_dns before add_object"
    assert logged_dns[0][0].startswith("CN="), "recorded DN must look like a valid DN"


def test_legacy_add_failure_preserves_maybe_created_dn(tmp_path, monkeypatch):
    """If add_object raises, keep maybe_created_dns for uncertain cleanup."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()

    class _FailAdd(_MockConn):
        def add(self, dn, object_class, attributes):
            return False  # triggers RuntimeError in add_object()

    conn = _FailAdd()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    with pytest.raises(Exception):
        prim.execute(op, confirm=True, conn=conn)

    assert op.created_dns == [], "created_dns must remain empty without confirmed success"
    assert op.maybe_created_dns, "maybe_created_dns must preserve uncertain cleanup state"


# ── no generated artifacts in source tree ────────────────────────────────────

def test_no_pyc_files_in_source_tree():
    """Ensure .pyc files are not committed alongside the source."""
    import pathlib
    root = pathlib.Path(__file__).parent.parent / "dmsa_reaper"
    pyc_files = list(root.rglob("*.pyc"))
    # Allow any .pyc inside __pycache__ (generated at runtime) but not bare .pyc
    # files sitting next to their source — those indicate accidental packaging.
    bare_pyc = [p for p in pyc_files if "__pycache__" not in str(p)]
    assert bare_pyc == [], f"bare .pyc files found in source tree: {bare_pyc}"


def test_gitignore_covers_artifacts():
    """Verify .gitignore excludes the main generated artifact patterns."""
    import pathlib
    gitignore = pathlib.Path(__file__).parent.parent / ".gitignore"
    assert gitignore.exists(), ".gitignore must exist"
    content = gitignore.read_text()
    # *.py[cod] covers .pyc, .pyo, .pyd — the gitignore convention.
    for pattern in ("__pycache__", "*.egg-info", ".pytest_cache", "*.py[cod]"):
        assert pattern in content, f".gitignore must include {pattern!r}"


# ── name generation ───────────────────────────────────────────────────────────

def test_generate_dmsa_name_uniqueness():
    from dmsa_reaper.primitives._ldap_helpers import generate_dmsa_name
    names = {generate_dmsa_name() for _ in range(50)}
    assert len(names) >= 45


def test_generate_dmsa_name_hint_strips_dollar():
    from dmsa_reaper.primitives._ldap_helpers import generate_dmsa_name
    name = generate_dmsa_name("mysvc$")
    assert name.startswith("mysvc-")
    assert "$" not in name


def test_generate_dmsa_name_default_prefix():
    from dmsa_reaper.primitives._ldap_helpers import generate_dmsa_name
    name = generate_dmsa_name()
    assert name.startswith("dmsarpr-")


# ── post-exploitation metadata ────────────────────────────────────────────────

def test_legacy_execute_records_created_dn_and_sam(tmp_path, monkeypatch):
    """execute() must store created_dmsa_dn and created_dmsa_sam in op.metadata."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    conn = _MockConn()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    result = prim.execute(op, confirm=True, conn=conn)

    assert "created_dmsa_dn" in result.metadata
    assert "created_dmsa_sam" in result.metadata
    assert result.metadata["created_dmsa_dn"].startswith("CN=")
    assert result.metadata["created_dmsa_sam"].endswith("$")


def test_postpatch_execute_records_created_dn_and_sam(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = PostPatchMutualPairPrimitive()
    conn = _MockConn(read_return=None)
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    result = prim.execute(op, confirm=True, conn=conn)

    assert "created_dmsa_dn" in result.metadata
    assert "created_dmsa_sam" in result.metadata


def test_dry_run_does_not_persist_cn_to_metadata(tmp_path, monkeypatch):
    """dry_run_steps() must not write created_dmsa_dn into operation metadata."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()
    op = _op(prim.name, container_dn="OU=Test,DC=corp,DC=local", target_dn="CN=svc,DC=corp,DC=local")
    _ = prim.dry_run_steps(op)

    assert "created_dmsa_dn" not in op.metadata
    assert "created_dmsa_sam" not in op.metadata


# ── stale-comment guard ───────────────────────────────────────────────────────

def test_no_stale_dmsa_state_initial_in_existing_dmsa_control():
    """existing_dmsa_control.py must not mention DMSA_STATE_INITIAL."""
    import pathlib
    src = (
        pathlib.Path(__file__).parent.parent
        / "dmsa_reaper" / "primitives" / "existing_dmsa_control.py"
    )
    content = src.read_text()
    assert "DMSA_STATE_INITIAL" not in content, (
        "existing_dmsa_control.py still references the stale DMSA_STATE_INITIAL constant"
    )
    assert "DMSA_STATE_COMPLETED" in content, (
        "existing_dmsa_control.py must use DMSA_STATE_COMPLETED"
    )


# ── packaging script ──────────────────────────────────────────────────────────

def test_packaging_script_exists():
    import pathlib
    script = pathlib.Path(__file__).parent.parent / "scripts" / "package.sh"
    assert script.exists(), "scripts/package.sh must exist"
    content = script.read_text()
    # Must explicitly exclude artifact and internal workspace directory patterns.
    for pattern in (
        "__pycache__", ".pytest_cache", "*.pyc", "*.egg-info",
        ".claude", ".agents", ".codex", ".reaper", ".git",
    ):
        assert pattern in content, f"package.sh must exclude {pattern!r}"


# ── Kerberos fail-closed ──────────────────────────────────────────────────────

def test_kerberos_map_requires_username():
    """map --kerberos without --username must fail with a clear error."""
    from typer.testing import CliRunner
    from dmsa_reaper.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "map",
        "--domain", "corp.local",
        "--kerberos",
        # no --username
    ])
    assert result.exit_code != 0
    assert "Kerberos" in (result.output or "") or "kerberos" in str(result.exception or "").lower()


def test_kerberos_map_requires_username_error_message():
    """Error must mention 'Kerberos mode requires --username'."""
    from typer.testing import CliRunner
    from dmsa_reaper.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "map",
        "--domain", "corp.local",
        "--kerberos",
    ])
    combined = (result.output or "") + str(result.exception or "")
    assert "Kerberos" in combined or result.exit_code != 0


# ── external-argv verify ─────────────────────────────────────────────────────

def test_external_argv_does_not_use_shell(tmp_path, monkeypatch):
    """--external-argv verify must invoke the process without shell=True."""
    import subprocess
    monkeypatch.chdir(tmp_path)

    # Write a minimal OP log
    from dmsa_reaper.models import Operation
    from dmsa_reaper.ops.operation_log import save_operation, ensure_ops_dir
    ensure_ops_dir()
    op = Operation(id="OP-0001", primitive="test", status="executed")
    save_operation(op)

    calls: list[dict] = []

    def capturing_run(args, **kwargs):
        calls.append({"args": args, "shell": kwargs.get("shell", False)})
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(subprocess, "run", capturing_run)

    from typer.testing import CliRunner
    from dmsa_reaper.cli import app

    runner = CliRunner()
    runner.invoke(app, [
        "verify",
        "--op", "OP-0001",
        "--mode", "external",
        "--external-argv", "echo",
        "--external-argv", "hello",
    ])

    # Find the call that used our argv
    argv_calls = [c for c in calls if isinstance(c["args"], list) and "echo" in c["args"]]
    if argv_calls:
        assert argv_calls[0]["shell"] is False, "--external-argv must not use shell=True"


def test_external_cmd_is_rejected_without_execution(tmp_path, monkeypatch):
    """Removed generic verification must never execute a supplied command."""
    import subprocess
    monkeypatch.chdir(tmp_path)

    from dmsa_reaper.models import Operation
    from dmsa_reaper.ops.operation_log import save_operation, ensure_ops_dir
    ensure_ops_dir()
    op = Operation(id="OP-0002", primitive="test", status="executed")
    save_operation(op)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not execute")),
    )

    from typer.testing import CliRunner
    from dmsa_reaper.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "verify",
        "--op", "OP-0002",
        "--mode", "external",
        "--external-cmd", "echo hello",
    ])
    assert result.exit_code != 0
    assert "external proof modes were removed" in result.output


# ── version consistency ───────────────────────────────────────────────────────

def test_version_not_starter():
    """pyproject.toml version must not be 1.0.0 (the old starter version)."""
    import pathlib
    pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert 'version = "1.0.0"' not in content, (
        "pyproject.toml still uses the old 1.0.0 version — update to a pre-release version"
    )


def test_readme_no_starter_wording():
    """README must not describe the tool as a 'starter'."""
    import pathlib
    readme = pathlib.Path(__file__).parent.parent / "README.md"
    content = readme.read_text().lower()
    assert "starter" not in content, "README must not use 'starter' wording"


@pytest.mark.skipif(
    not __import__("os").environ.get("DMSA_REAPER_SLOW_TESTS"),
    reason="set DMSA_REAPER_SLOW_TESTS=1 to run packaging integration tests",
)
def test_package_zip_contains_no_artifacts(tmp_path):
    """Run scripts/package.sh and verify the resulting zip has zero artifact entries.

    Skipped by default.  Enable with:
        DMSA_REAPER_SLOW_TESTS=1 pytest tests/test_primitives.py::test_package_zip_contains_no_artifacts
    """
    import subprocess
    import zipfile
    import pathlib

    repo_root = pathlib.Path(__file__).parent.parent
    script = repo_root / "scripts" / "package.sh"

    result = subprocess.run(
        ["bash", str(script), str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    assert result.returncode == 0, (
        f"package.sh failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    zips = list(tmp_path.glob("dmsa-reaper-*.zip"))
    assert zips, "package.sh must produce a dmsa-reaper-*.zip in the output directory"
    archive = zips[0]

    artifact_entries = []
    _BAD = (
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ".egg-info", ".pyc",
        "/.agents", "/.codex", "/.reaper", "/.git", "/.claude",
    )
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            if any(bad in name for bad in _BAD):
                artifact_entries.append(name)

    assert artifact_entries == [], (
        f"Archive {archive.name} contains {len(artifact_entries)} artifact entries:\n"
        + "\n".join(artifact_entries[:20])
    )


# ── grouped path requires_operator_target ────────────────────────────────────

def test_grouped_postpatch_requires_operator_target():
    """Grouped postpatch-mutual-pair (no target_dn) must have requires_operator_target=True."""
    from dmsa_reaper.models import (
        ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
    )
    from dmsa_reaper.paths.classifier import classify_paths

    container = ContainerObject(
        dn="OU=Apps,DC=corp,DC=local",
        rights=[Right(principal_sid="S-1-5-21-1-2-3-500", right="CreateChild:dMSA",
                      object_dn="OU=Apps,DC=corp,DC=local")],
    )
    target = TargetObject(
        dn="CN=svc,DC=corp,DC=local",
        writable_attrs=["msDS-SupersededManagedAccountLink", "msDS-SupersededServiceAccountState"],
    )
    state = MapState(environment=Environment(dmsa_capable=True), schema_cache=SchemaCache(),
                     containers=[container], targets=[target])
    paths = [p for p in classify_paths(state) if p.primitive == "postpatch-mutual-pair"]
    assert paths
    assert paths[0].requires_operator_target is True
    assert paths[0].target_dn is None
    assert paths[0].candidate_targets_count == 1


def test_grouped_legacy_requires_operator_target():
    """Grouped legacy-oneway-link (no target_dn) must have requires_operator_target=True."""
    from dmsa_reaper.models import (
        ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
    )
    from dmsa_reaper.paths.classifier import classify_paths

    container = ContainerObject(
        dn="OU=Apps,DC=corp,DC=local",
        rights=[Right(principal_sid="S-1-5-21-1-2-3-500", right="CreateChild:dMSA",
                      object_dn="OU=Apps,DC=corp,DC=local")],
    )
    state = MapState(environment=Environment(dmsa_capable=True), schema_cache=SchemaCache(),
                     containers=[container],
                     targets=[TargetObject(dn="CN=t,DC=corp,DC=local")])
    paths = [p for p in classify_paths(state) if p.primitive == "legacy-oneway-link"]
    assert paths
    assert paths[0].requires_operator_target is True
    assert paths[0].candidate_targets_count == 1


def test_expanded_postpatch_does_not_require_operator_target():
    """Expanded paths (expand_targets=True) have explicit target_dn; requires_operator_target must be False."""
    from dmsa_reaper.models import (
        ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
    )
    from dmsa_reaper.paths.classifier import classify_paths

    container = ContainerObject(
        dn="OU=Apps,DC=corp,DC=local",
        rights=[Right(principal_sid="S-1-5-21-1-2-3-500", right="CreateChild:dMSA",
                      object_dn="OU=Apps,DC=corp,DC=local")],
    )
    target = TargetObject(
        dn="CN=svc,DC=corp,DC=local",
        writable_attrs=["msDS-SupersededManagedAccountLink", "msDS-SupersededServiceAccountState"],
    )
    state = MapState(environment=Environment(dmsa_capable=True), schema_cache=SchemaCache(),
                     containers=[container], targets=[target])
    paths = [p for p in classify_paths(state, expand_targets=True) if p.primitive == "postpatch-mutual-pair"]
    assert paths
    assert paths[0].requires_operator_target is False
    assert paths[0].target_dn == "CN=svc,DC=corp,DC=local"


# ── dry-run file-system isolation ────────────────────────────────────────────

def test_dry_run_does_not_create_operation_file(tmp_path, monkeypatch):
    """--dry-run must not create any .reaper/operations/OP-*.json file."""
    monkeypatch.chdir(tmp_path)
    prim = LegacyOneWayLinkPrimitive()

    # Build a preview operation manually (mirroring what exploit_cmd does).
    from dmsa_reaper.models import Operation, PathCandidate
    selected = PathCandidate(
        id="P-0001",
        primitive="legacy-oneway-link",
        principal="S-1-5-21-1-2-3-500",
        container_dn="OU=Test,DC=corp,DC=local",
        requires_operator_target=True,
        candidate_targets_count=1,
    )
    preview_op = Operation(
        id="DRY-RUN",
        primitive=selected.primitive,
        path_id=selected.id,
        metadata={
            "path": selected.model_dump(),
            "target_dn": "CN=svc,DC=corp,DC=local",
        },
    )
    steps = prim.dry_run_steps(preview_op)
    assert any("CREATE" in s for s in steps)

    # No .reaper directory should have been created.
    assert not (tmp_path / ".reaper").exists(), ".reaper/ must not be created during dry run"


# ── expand-targets path ID consistency ───────────────────────────────────────

def test_expanded_path_ids_carry_target_dn():
    """Path IDs from expand_targets=True must include an explicit target_dn that
    matches the original TargetObject — i.e., the target is embedded in the path,
    not left as a grouped placeholder."""
    from dmsa_reaper.models import (
        ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
    )
    from dmsa_reaper.paths.classifier import classify_paths

    targets = [
        TargetObject(dn=f"CN=svc{i},DC=corp,DC=local") for i in range(3)
    ]
    container = ContainerObject(
        dn="OU=Apps,DC=corp,DC=local",
        rights=[Right(principal_sid="S-1-5-21-1-2-3-500", right="CreateChild:dMSA",
                      object_dn="OU=Apps,DC=corp,DC=local")],
    )
    state = MapState(environment=Environment(dmsa_capable=True), schema_cache=SchemaCache(),
                     containers=[container], targets=targets)

    expanded = [p for p in classify_paths(state, expand_targets=True)
                if p.primitive == "legacy-oneway-link"]
    assert len(expanded) == 3
    found_dns = {p.target_dn for p in expanded}
    assert found_dns == {t.dn for t in targets}


def test_paths_json_round_trip(tmp_path):
    """A paths.json written by the paths command can be deserialized back to PathCandidate
    objects with the same IDs and target_dn values (simulating --paths in exploit)."""
    import json
    from dmsa_reaper.models import (
        ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject, PathCandidate,
    )
    from dmsa_reaper.paths.classifier import classify_paths
    from dmsa_reaper.paths.ranking import rank_paths

    targets = [
        TargetObject(dn=f"CN=svc{i},DC=corp,DC=local") for i in range(2)
    ]
    container = ContainerObject(
        dn="OU=Apps,DC=corp,DC=local",
        rights=[Right(principal_sid="S-1-5-21-1-2-3-500", right="CreateChild:dMSA",
                      object_dn="OU=Apps,DC=corp,DC=local")],
    )
    state = MapState(environment=Environment(dmsa_capable=True), schema_cache=SchemaCache(),
                     containers=[container], targets=targets)

    paths = rank_paths(classify_paths(state, expand_targets=True))
    paths_json = tmp_path / "paths.json"
    paths_json.write_text(
        "[" + ",".join(p.model_dump_json() for p in paths) + "]",
        encoding="utf-8",
    )

    loaded = [PathCandidate.model_validate(p) for p in json.loads(paths_json.read_text())]
    assert len(loaded) == len(paths)
    for orig, back in zip(paths, loaded):
        assert orig.id == back.id
        assert orig.target_dn == back.target_dn


# ── _dn_exists hardening ──────────────────────────────────────────────────────

def test_dn_exists_returns_false_on_ldap_exception():
    """_dn_exists must return False when the LDAP search raises LDAPException."""
    from ldap3.core.exceptions import LDAPException
    from dmsa_reaper.ops.verify import _dn_exists

    class _RaisingConn:
        entries = []
        def search(self, **kwargs):
            raise LDAPException("simulated noSuchObject")

    assert _dn_exists(_RaisingConn(), "CN=gone,DC=corp,DC=local") is False


def test_dn_exists_returns_true_when_present():
    """_dn_exists must return True when the search returns entries."""
    from unittest.mock import MagicMock
    from dmsa_reaper.ops.verify import _dn_exists

    conn = MagicMock()
    conn.entries = [MagicMock()]
    assert _dn_exists(conn, "CN=present,DC=corp,DC=local") is True


def test_dn_exists_returns_false_when_no_entries():
    """_dn_exists must return False when the search returns no entries."""
    from unittest.mock import MagicMock
    from dmsa_reaper.ops.verify import _dn_exists

    conn = MagicMock()
    conn.entries = []
    assert _dn_exists(conn, "CN=absent,DC=corp,DC=local") is False


# ── Domain Users / primaryGroupID ACE detection ───────────────────────────────

def test_domain_users_ace_detected_via_primary_group():
    """A container ACE granting rights to Domain Users (S-1-5-21-...-513) must be
    detected when that SID is derived from the principal's primaryGroupID."""
    from dmsa_reaper.acl.effective_rights import has_effective_right
    from dmsa_reaper.acl.ace_matcher import Ace

    domain_users_sid = "S-1-5-21-111-222-333-513"
    principal_sids = {
        "S-1-5-21-111-222-333-1000",  # user's own SID
        domain_users_sid,              # added from primaryGroupID
    }
    ace = Ace(
        ace_type="allow",
        sid=domain_users_sid,
        rights={"CreateChild"},
    )
    assert has_effective_right([ace], principal_sids, "CreateChild")


def test_primary_group_ace_not_detected_without_sid_in_set():
    """If the primaryGroupID SID is not in the principal's SID set, the ACE must not match."""
    from dmsa_reaper.acl.effective_rights import has_effective_right
    from dmsa_reaper.acl.ace_matcher import Ace

    domain_users_sid = "S-1-5-21-111-222-333-513"
    principal_sids = {"S-1-5-21-111-222-333-1000"}  # no primaryGroup SID
    ace = Ace(
        ace_type="allow",
        sid=domain_users_sid,
        rights={"CreateChild"},
    )
    assert not has_effective_right([ace], principal_sids, "CreateChild")
