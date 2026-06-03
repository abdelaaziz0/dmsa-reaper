"""Tests for DACL escalation primitives and the dacl_editor helper.

All tests run without live LDAP using mock connections and a minimal synthetic
self-relative security descriptor.
"""
from __future__ import annotations

import struct

import pytest

from dmsa_reaper.models import Operation, PathCandidate
from dmsa_reaper.primitives.base import PrimitiveError
from dmsa_reaper.primitives.dacl_container_escalate import DaclContainerEscalatePrimitive
from dmsa_reaper.primitives.dacl_target_escalate import DaclTargetEscalatePrimitive


# ── minimal SD builder ────────────────────────────────────────────────────────

def _make_test_sd(ace_count: int = 0) -> bytes:
    """Build a minimal self-relative SD with an empty (or near-empty) DACL.

    Layout: SD header (20) + owner SID S-1-1-0 (12) + empty DACL (8)  = 40 bytes.
    """
    # S-1-1-0 (World SID) — 12 bytes
    owner_sid = bytes([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])

    # Empty DACL: AclRevision=4, Sbz1=0, AclSize=8, AceCount=0, Sbz2=0
    dacl = struct.pack("<BBHHH", 4, 0, 8, ace_count, 0)

    # SD header
    revision = 1
    sbz1 = 0
    control = 0x8004  # SE_DACL_PRESENT | SE_SELF_RELATIVE
    offset_owner = 20
    offset_group = 0
    offset_sacl = 0
    offset_dacl = 20 + len(owner_sid)  # = 32
    header = struct.pack("<BBHIIII", revision, sbz1, control,
                         offset_owner, offset_group, offset_sacl, offset_dacl)
    return header + owner_sid + dacl


# ── dacl_editor unit tests ────────────────────────────────────────────────────

def test_add_aces_to_sd_increases_ace_count():
    """add_aces_to_sd must increment AceCount by the number of ACEs added."""
    from dmsa_reaper.ldap.dacl_editor import add_aces_to_sd

    raw_sd = _make_test_sd(ace_count=0)
    offset_dacl = struct.unpack_from("<I", raw_sd, 16)[0]
    original_ace_count = struct.unpack_from("<H", raw_sd, offset_dacl + 4)[0]

    # Build a minimal dummy ACE (type=allow, flags=0, size=8, 4-byte inner)
    dummy_ace = struct.pack("<BBH", 0x00, 0, 8) + struct.pack("<I", 0x00000001)  # CreateChild

    modified = add_aces_to_sd(raw_sd, [dummy_ace])

    new_offset_dacl = struct.unpack_from("<I", modified, 16)[0]
    new_ace_count = struct.unpack_from("<H", modified, new_offset_dacl + 4)[0]
    assert new_ace_count == original_ace_count + 1


def test_add_aces_to_sd_grows_acl_size():
    """AclSize must increase by the size of the added ACE."""
    from dmsa_reaper.ldap.dacl_editor import add_aces_to_sd

    raw_sd = _make_test_sd()
    offset_dacl = struct.unpack_from("<I", raw_sd, 16)[0]
    old_acl_size = struct.unpack_from("<H", raw_sd, offset_dacl + 2)[0]

    dummy_ace = struct.pack("<BBH", 0x00, 0, 8) + struct.pack("<I", 0x00000001)
    modified = add_aces_to_sd(raw_sd, [dummy_ace])

    new_offset_dacl = struct.unpack_from("<I", modified, 16)[0]
    new_acl_size = struct.unpack_from("<H", modified, new_offset_dacl + 2)[0]
    assert new_acl_size == old_acl_size + len(dummy_ace)


def test_add_aces_to_sd_offset_dacl_unchanged():
    """OffsetDacl in the SD header must stay the same after adding ACEs."""
    from dmsa_reaper.ldap.dacl_editor import add_aces_to_sd

    raw_sd = _make_test_sd()
    original_offset = struct.unpack_from("<I", raw_sd, 16)[0]

    dummy_ace = struct.pack("<BBH", 0x00, 0, 8) + struct.pack("<I", 0x1)
    modified = add_aces_to_sd(raw_sd, [dummy_ace])

    new_offset = struct.unpack_from("<I", modified, 16)[0]
    assert new_offset == original_offset


def test_build_allow_createchild_ace_broad():
    """Broad CreateChild ACE must use ACCESS_ALLOWED_ACE_TYPE (0x00)."""
    from dmsa_reaper.ldap.dacl_editor import build_allow_createchild_ace

    ace = build_allow_createchild_ace("S-1-5-21-111-222-333-500", object_type_guid_bytes=None)
    assert ace[0] == 0x00  # ACE type = ACCESS_ALLOWED_ACE_TYPE


def test_build_allow_createchild_ace_object_specific():
    """Object-specific CreateChild ACE must use ACCESS_ALLOWED_OBJECT_ACE_TYPE (0x05)."""
    from dmsa_reaper.ldap.dacl_editor import build_allow_createchild_ace

    guid_bytes = b"\x01" * 16  # 16-byte dummy GUID
    ace = build_allow_createchild_ace("S-1-5-21-111-222-333-500", object_type_guid_bytes=guid_bytes)
    assert ace[0] == 0x05  # ACE type = ACCESS_ALLOWED_OBJECT_ACE_TYPE


def test_build_allow_writeproperty_ace_broad():
    from dmsa_reaper.ldap.dacl_editor import build_allow_writeproperty_ace

    ace = build_allow_writeproperty_ace("S-1-5-21-111-222-333-500", attr_guid_bytes=None)
    assert ace[0] == 0x00


def test_build_allow_writeproperty_ace_object_specific():
    from dmsa_reaper.ldap.dacl_editor import build_allow_writeproperty_ace

    ace = build_allow_writeproperty_ace("S-1-5-21-111-222-333-500", attr_guid_bytes=b"\x02" * 16)
    assert ace[0] == 0x05


# ── mock connection for DACL primitives ──────────────────────────────────────

_TEST_SD = _make_test_sd()


class _DaclMockConn:
    """Mock connection that serves a raw SD on nTSecurityDescriptor reads."""

    def __init__(self, sd_bytes: bytes = _TEST_SD, fail_add: bool = False, fail_modify: int = 0):
        self.added: list[tuple] = []
        self.modified: list[tuple] = []
        self.deleted: list[str] = []
        self.controls_used: list[tuple] = []  # (dn, controls) per modify() call
        self._sd_bytes = sd_bytes
        self._fail_add = fail_add
        self._fail_modify_on = fail_modify  # 1-indexed modify call to fail
        self._modify_n = 0

    def search(self, search_base, search_filter, search_scope, attributes, controls=None):
        class _RawAttr:
            def __init__(self, raw):
                self.raw_values = [raw]
                self.values = [raw]

            def __contains__(self, k):
                return True

            def __getitem__(self, k):
                return _RawAttr(self._raw)

        class _Entry:
            def __init__(self, raw_sd, attr_name):
                self._raw_sd = raw_sd
                self._attr_name = attr_name

            def __contains__(self, k):
                return k in (self._attr_name, "nTSecurityDescriptor", "objectClass")

            def __getitem__(self, k):
                if k == "nTSecurityDescriptor":
                    class _NtsdAttr:
                        def __init__(self, raw):
                            self.raw_values = [raw]
                            self.values = [raw]
                    return _NtsdAttr(self._raw_sd)
                class _GenAttr:
                    def __init__(self, v):
                        self.values = [v]
                return _GenAttr(None)

        self._entries = [_Entry(self._sd_bytes, "nTSecurityDescriptor")]

    @property
    def entries(self):
        return self._entries

    def add(self, dn, object_class, attributes) -> bool:
        if self._fail_add:
            return False
        self.added.append((dn, object_class, attributes))
        return True

    def modify(self, dn, changes, controls=None) -> bool:
        self._modify_n += 1
        if self._fail_modify_on and self._modify_n == self._fail_modify_on:
            return False
        for attr, ops in changes.items():
            for (mod_type, values) in ops:
                self.modified.append((dn, attr, values, mod_type))
        self.controls_used.append((dn, controls))
        return True

    def delete(self, dn) -> bool:
        self.deleted.append(dn)
        return True

    @property
    def result(self):
        return {"description": "mock"}


def _op(primitive: str, **meta) -> Operation:
    if primitive in {"dacl-container-escalate", "dacl-target-escalate"}:
        meta.setdefault("lab_unsafe", True)
        if meta.get("allow_broad_dacl"):
            meta.setdefault("scope_allow_broad_dacl", True)
    return Operation(id="OP-0001", primitive=primitive, metadata=meta)


# ── dacl-container-escalate ───────────────────────────────────────────────────

def test_dacl_container_escalate_check():
    prim = DaclContainerEscalatePrimitive()
    path = PathCandidate(
        id="P-0001", primitive="dacl-container-escalate", principal="S-1-5-21-1-2-3-500",
        requires_modify_container_dacl=True,
    )
    assert prim.check(path)
    bad = PathCandidate(
        id="P-0001", primitive="dacl-container-escalate", principal="S-1-5-21-1-2-3-500",
    )
    assert not prim.check(bad)


def test_dacl_container_escalate_no_confirm_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    op = _op(prim.name)
    with pytest.raises(PrimitiveError, match="--confirm"):
        prim.execute(op, confirm=False)


def test_dacl_container_escalate_dry_run_no_ldap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
    )
    steps = prim.dry_run_steps(op)
    assert any("PHASE 1" in s for s in steps)
    assert any("PHASE 2" in s for s in steps)
    assert any("PHASE 3" in s for s in steps)
    assert conn.modified == []
    assert conn.added == []


def test_dacl_container_escalate_execute_broad(tmp_path, monkeypatch):
    """Execute with --allow-broad-dacl must write SD, then create dMSA."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    result = prim.execute(op, confirm=True, conn=conn)

    assert result.status == "executed"
    assert len(result.created_dns) == 1
    assert len(result.changed_attrs) == 1
    assert result.changed_attrs[0].attribute == "nTSecurityDescriptor"
    assert result.changed_attrs[0].before is not None
    assert result.changed_attrs[0].after is not None
    assert result.changed_attrs[0].step_name == "dacl-mod"
    # SD modify + dMSA add
    assert len(conn.modified) >= 1
    assert len(conn.added) == 1


def test_dacl_container_escalate_execute_without_guid_and_no_broad_fails(tmp_path, monkeypatch):
    """Without GUID and without --allow-broad-dacl, must fail before LDAP write."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        # no dmsa_class_guid, no allow_broad_dacl
    )
    with pytest.raises(PrimitiveError, match="allow-broad-dacl"):
        prim.execute(op, confirm=True, conn=conn)
    # No LDAP writes should have happened
    assert conn.modified == []
    assert conn.added == []


def test_dacl_container_escalate_rollback_restores_sd(tmp_path, monkeypatch):
    """If dMSA creation fails, rollback must restore the original container SD."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn(fail_add=True)  # dMSA add will fail
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    with pytest.raises(PrimitiveError, match="rolled back"):
        prim.execute(op, confirm=True, conn=conn)

    # Rollback must have issued a modify to restore the SD
    assert len(conn.modified) >= 2  # 1 to write new SD + 1 to restore original


def test_dacl_container_escalate_preflight_missing_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    path = PathCandidate(
        id="P-0001", primitive="dacl-container-escalate", principal="S-1-5-21-1-2-3-500",
        container_dn="OU=Reaper,DC=corp,DC=local",
        requires_modify_container_dacl=True,
    )
    with pytest.raises(PrimitiveError, match="target-dn"):
        prim.preflight(path, scope=None, target_dn=None)


# ── dacl-target-escalate ──────────────────────────────────────────────────────

def test_dacl_target_escalate_check():
    prim = DaclTargetEscalatePrimitive()
    path = PathCandidate(
        id="P-0001", primitive="dacl-target-escalate", principal="S-1-5-21-1-2-3-500",
        requires_modify_target_dacl=True,
    )
    assert prim.check(path)


def test_dacl_target_escalate_dry_run_no_ldap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prim = DaclTargetEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        target_dn="CN=svc,DC=corp,DC=local",
        container_dn="OU=Reaper,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
    )
    steps = prim.dry_run_steps(op)
    assert any("PHASE 1" in s for s in steps)
    assert any("PHASE 4" in s for s in steps)
    assert conn.modified == []
    assert conn.added == []


def test_dacl_target_escalate_execute_broad(tmp_path, monkeypatch):
    """Execute with --allow-broad-dacl must write SD then do postpatch steps."""
    monkeypatch.chdir(tmp_path)
    prim = DaclTargetEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        target_dn="CN=svc,DC=corp,DC=local",
        container_dn="OU=Reaper,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    result = prim.execute(op, confirm=True, conn=conn)
    assert result.status == "executed"
    assert len(result.created_dns) == 1
    # changed_attrs: SD change + msDS-SupersededManagedAccountLink + msDS-SupersededServiceAccountState
    assert len(result.changed_attrs) == 3
    sd_change = result.changed_attrs[0]
    assert sd_change.attribute == "nTSecurityDescriptor"
    assert sd_change.step_name == "dacl-mod"


def test_dacl_target_escalate_rollback_after_dacl_write(tmp_path, monkeypatch):
    """If dMSA creation fails, SD must be restored."""
    monkeypatch.chdir(tmp_path)
    prim = DaclTargetEscalatePrimitive()
    conn = _DaclMockConn(fail_add=True)
    op = _op(
        prim.name,
        target_dn="CN=svc,DC=corp,DC=local",
        container_dn="OU=Reaper,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    with pytest.raises(PrimitiveError, match="rolled back"):
        prim.execute(op, confirm=True, conn=conn)

    # At least one modify to write the SD ACE + at least one to restore
    assert len(conn.modified) >= 2


def test_dacl_target_escalate_preflight_missing_target():
    prim = DaclTargetEscalatePrimitive()
    path = PathCandidate(
        id="P-0001", primitive="dacl-target-escalate", principal="S-1-5-21-1-2-3-500",
        requires_modify_target_dacl=True,
    )
    with pytest.raises(PrimitiveError, match="target DN"):
        prim.preflight(path, scope=None, target_dn=None)


# ── AttributeValue.security_descriptor round-trip ────────────────────────────

def test_security_descriptor_attributevalue_round_trip():
    """security_descriptor AttributeValue must encode/decode to the original bytes."""
    from dmsa_reaper.models import AttributeValue

    raw = _TEST_SD
    av = AttributeValue.security_descriptor(raw)
    assert av.type == "security_descriptor"
    assert av.to_python() == raw


def test_security_descriptor_comparison_key_is_stable():
    from dmsa_reaper.models import AttributeValue

    av = AttributeValue.security_descriptor(_TEST_SD)
    k1 = av.comparison_key()
    k2 = av.comparison_key()
    assert k1 == k2


# ── classifier marks dacl paths executable=True ───────────────────────────────

def test_dacl_container_escalate_executable_in_classifier():
    """dacl-container-escalate must have executable=True in classifier output."""
    from dmsa_reaper.models import (
        ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject,
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
    dacl_paths = [p for p in classify_paths(state) if p.primitive == "dacl-container-escalate"]
    assert dacl_paths, "classifier must emit dacl-container-escalate paths"
    for p in dacl_paths:
        assert p.executable is True, f"dacl-container-escalate must be executable=True, got {p.executable}"


def test_dacl_target_escalate_executable_in_classifier():
    """dacl-target-escalate must have executable=True in classifier output."""
    from dmsa_reaper.models import (
        Environment, MapState, Right, SchemaCache, TargetObject,
    )
    from dmsa_reaper.paths.classifier import classify_paths

    right = Right(
        principal_sid="S-1-5-21-1-2-3-500",
        right="WriteDACL",
        object_dn="CN=svc,DC=corp,DC=local",
    )
    target = TargetObject(dn="CN=svc,DC=corp,DC=local", rights=[right])
    state = MapState(
        environment=Environment(dmsa_capable=True),
        schema_cache=SchemaCache(),
        containers=[],
        targets=[target],
    )
    dacl_paths = [p for p in classify_paths(state) if p.primitive == "dacl-target-escalate"]
    assert dacl_paths, "classifier must emit dacl-target-escalate paths"
    for p in dacl_paths:
        assert p.executable is True


# ── ACE correctness: no spurious InheritedObjectType ─────────────────────────

def _sid_bytes(sid_str: str) -> bytes:
    from impacket.ldap.ldaptypes import LDAP_SID
    s = LDAP_SID()
    s.fromCanonical(sid_str)
    return s.getData()


def test_createchild_object_ace_sid_not_shifted():
    """SID must immediately follow ObjectType (24 bytes into inner), with no 16-byte padding.

    Regression test for the bug where InheritedObjectType (16 zero bytes) was
    included even when ACE_INHERITED_OBJECT_TYPE_PRESENT was not set in Flags.
    """
    from dmsa_reaper.ldap.dacl_editor import build_allow_createchild_ace

    sid_str = "S-1-5-21-111-222-333-500"
    guid = b"\xAA" * 16
    ace = build_allow_createchild_ace(sid_str, object_type_guid_bytes=guid)

    assert ace[0] == 0x05  # ACCESS_ALLOWED_OBJECT_ACE_TYPE
    inner = ace[4:]         # skip 4-byte ACE header
    # inner: Mask(4) + Flags(4) + ObjectType(16) + Sid — total prefix = 24 bytes
    assert inner[8:24] == guid, "ObjectType GUID not at expected offset"
    assert inner[24:] == _sid_bytes(sid_str), (
        "SID is at wrong position — likely shifted by spurious InheritedObjectType padding"
    )


def test_createchild_object_ace_parses_back_correctly():
    """Object-specific CreateChild ACE round-trip: type, ObjectType GUID, and SID all correct."""
    from dmsa_reaper.ldap.dacl_editor import build_allow_createchild_ace

    sid_str = "S-1-5-21-111-222-333-500"
    guid = b"\x01\x02\x03\x04" * 4  # 16-byte GUID
    ace = build_allow_createchild_ace(sid_str, object_type_guid_bytes=guid)

    ace_type = ace[0]
    ace_size = struct.unpack_from("<H", ace, 2)[0]
    inner = ace[4:]
    mask = struct.unpack_from("<I", inner, 0)[0]
    flags = struct.unpack_from("<I", inner, 4)[0]
    object_type = inner[8:24]
    sid_data = inner[24:]

    assert ace_type == 0x05
    assert ace_size == len(ace)
    assert mask == 0x00000001           # CREATE_CHILD
    assert flags == 0x01                # ACE_OBJECT_TYPE_PRESENT only (no InheritedObjectType flag)
    assert object_type == guid
    assert sid_data == _sid_bytes(sid_str)


def test_writeproperty_object_ace_parses_back_correctly():
    """Object-specific WriteProperty ACE round-trip: type, ObjectType GUID, and SID all correct."""
    from dmsa_reaper.ldap.dacl_editor import build_allow_writeproperty_ace

    sid_str = "S-1-5-21-111-222-333-500"
    guid = b"\xBB" * 16
    ace = build_allow_writeproperty_ace(sid_str, attr_guid_bytes=guid)

    ace_type = ace[0]
    inner = ace[4:]
    mask = struct.unpack_from("<I", inner, 0)[0]
    flags = struct.unpack_from("<I", inner, 4)[0]
    object_type = inner[8:24]
    sid_data = inner[24:]

    assert ace_type == 0x05
    assert mask == 0x00000020           # WRITE_PROPERTY
    assert flags == 0x01                # ACE_OBJECT_TYPE_PRESENT only
    assert object_type == guid
    assert sid_data == _sid_bytes(sid_str)


def test_acl_revision_upgraded_to_ds_for_object_ace():
    """ACL revision must be ACL_REVISION_DS (4) when an object ACE is inserted.

    Builds a test SD with AclRevision=2 (standard), then inserts an object ACE
    and verifies the DACL header is upgraded to 0x04.
    """
    from dmsa_reaper.ldap.dacl_editor import ACL_REVISION_DS, add_aces_to_sd, build_allow_createchild_ace

    # Build a minimal SD with AclRevision=2 (not ACL_REVISION_DS).
    owner_sid = bytes([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    dacl_rev2 = struct.pack("<BBHHH", 2, 0, 8, 0, 0)  # AclRevision=2
    sd_header = struct.pack(
        "<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(owner_sid)
    )
    raw_sd = sd_header + owner_sid + dacl_rev2

    assert raw_sd[20 + len(owner_sid)] == 2, "pre-condition: AclRevision must start at 2"

    ace = build_allow_createchild_ace("S-1-5-21-111-222-333-500", object_type_guid_bytes=b"\x01" * 16)
    modified = add_aces_to_sd(raw_sd, [ace])

    new_offset_dacl = struct.unpack_from("<I", modified, 16)[0]
    new_rev = modified[new_offset_dacl]
    assert new_rev == ACL_REVISION_DS, f"ACL revision not upgraded: got {new_rev}, expected {ACL_REVISION_DS}"


def test_broad_ace_does_not_trigger_ds_revision():
    """Broad (non-object) ACEs must not upgrade ACL revision above the existing value."""
    from dmsa_reaper.ldap.dacl_editor import add_aces_to_sd, build_allow_createchild_ace

    # Build a broad (non-object) ACE
    ace = build_allow_createchild_ace("S-1-5-21-111-222-333-500", object_type_guid_bytes=None)
    assert ace[0] == 0x00, "broad ACE must be type 0x00"

    # Use a fresh SD with AclRevision=2 to test that broad ACE doesn't upgrade it.
    owner_sid = bytes([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    dacl_rev2 = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
    sd_header = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(owner_sid))
    raw_sd2 = sd_header + owner_sid + dacl_rev2

    modified = add_aces_to_sd(raw_sd2, [ace])
    new_offset_dacl = struct.unpack_from("<I", modified, 16)[0]
    new_rev = modified[new_offset_dacl]
    assert new_rev == 2, f"broad ACE should not upgrade ACL revision from 2, got {new_rev}"


# ── dacl-target-escalate: container_dn requirement ───────────────────────────

def test_dacl_target_escalate_preflight_missing_container_dn():
    """dacl-target-escalate preflight must fail when container_dn is absent."""
    prim = DaclTargetEscalatePrimitive()
    path = PathCandidate(
        id="P-0001", primitive="dacl-target-escalate", principal="S-1-5-21-1-2-3-500",
        target_dn="CN=svc,DC=corp,DC=local",
        requires_modify_target_dacl=True,
    )
    with pytest.raises(PrimitiveError, match="container-dn"):
        prim.preflight(path, scope=None, target_dn="CN=svc,DC=corp,DC=local", container_dn=None)


def test_dacl_target_escalate_preflight_with_container_dn_passes(tmp_path, monkeypatch):
    """dacl-target-escalate preflight must pass when both target_dn and container_dn are provided."""
    monkeypatch.chdir(tmp_path)
    prim = DaclTargetEscalatePrimitive()
    path = PathCandidate(
        id="P-0001", primitive="dacl-target-escalate", principal="S-1-5-21-1-2-3-500",
        target_dn="CN=svc,DC=corp,DC=local",
        requires_modify_target_dacl=True,
    )
    warnings = prim.preflight(
        path,
        scope=None,
        target_dn="CN=svc,DC=corp,DC=local",
        container_dn="OU=Reaper,DC=corp,DC=local",
    )
    assert isinstance(warnings, list)


def test_dacl_target_escalate_execute_fails_missing_container_dn(tmp_path, monkeypatch):
    """dacl-target-escalate execute must fail when container_dn is absent in metadata."""
    monkeypatch.chdir(tmp_path)
    prim = DaclTargetEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
        # no container_dn
    )
    with pytest.raises(PrimitiveError, match="container-dn"):
        prim.execute(op, confirm=True, conn=conn)
    assert conn.modified == []
    assert conn.added == []


# ── dacl-container-escalate: chain mode ──────────────────────────────────────

def test_dacl_container_legacy_mode_creates_only_link(tmp_path, monkeypatch):
    """Legacy chain mode must only create dMSA with ManagedAccountPrecededByLink (no postpatch attrs)."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
        chain="legacy",
    )
    result = prim.execute(op, confirm=True, conn=conn)

    assert result.status == "executed"
    assert len(result.created_dns) == 1
    # Only the container SD change — no postpatch attrs
    assert len(result.changed_attrs) == 1
    assert result.changed_attrs[0].attribute == "nTSecurityDescriptor"


def test_dacl_container_postpatch_mode_writes_target_attrs(tmp_path, monkeypatch):
    """Postpatch chain mode must write target-side superseded attrs after dMSA creation."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
        chain="postpatch",
        target_writable_attrs=[
            "msDS-SupersededManagedAccountLink",
            "msDS-SupersededServiceAccountState",
        ],
    )
    result = prim.execute(op, confirm=True, conn=conn)

    assert result.status == "executed"
    assert len(result.created_dns) == 1
    # container SD + link + state
    assert len(result.changed_attrs) == 3
    attr_names = [c.attribute for c in result.changed_attrs]
    assert "nTSecurityDescriptor" in attr_names
    assert "msDS-SupersededManagedAccountLink" in attr_names
    assert "msDS-SupersededServiceAccountState" in attr_names


def test_dacl_container_postpatch_refuses_without_target_write(tmp_path, monkeypatch):
    """Postpatch mode must fail before any LDAP write if target-side attrs are not writable."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
        chain="postpatch",
        # target_writable_attrs absent → pre-check must fail
    )
    with pytest.raises(PrimitiveError, match="container DACL alone"):
        prim.execute(op, confirm=True, conn=conn)
    # No LDAP writes should have occurred
    assert conn.modified == []
    assert conn.added == []


def test_dacl_container_postpatch_rollback_restores_all(tmp_path, monkeypatch):
    """When a postpatch write fails, rollback must reverse the container DACL, target attrs, and dMSA."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    # Fail on the 3rd modify call (msDS-SupersededServiceAccountState write)
    conn = _DaclMockConn(fail_modify=3)
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
        chain="postpatch",
        target_writable_attrs=[
            "msDS-SupersededManagedAccountLink",
            "msDS-SupersededServiceAccountState",
        ],
    )
    with pytest.raises(PrimitiveError, match="Postpatch target write failed"):
        prim.execute(op, confirm=True, conn=conn)

    # Rollback must have issued reversal writes (at minimum: restore link + restore SD)
    # and deleted the dMSA.
    assert len(conn.modified) >= 3   # write SD, write link, then rollback writes
    assert len(conn.deleted) >= 1    # dMSA deleted


# ── broad DACL warning appears in dry-run output ─────────────────────────────

def test_dacl_container_broad_dacl_warning_in_dry_run(tmp_path, monkeypatch):
    """Dry-run output must include the broad-ACE warning when --allow-broad-dacl is set."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    steps = prim.dry_run_steps(op)
    assert any("broad ACE grants all child classes/all writable properties" in s for s in steps)


def test_dacl_target_broad_dacl_warning_in_dry_run(tmp_path, monkeypatch):
    """dacl-target dry-run output must include the broad-ACE warning."""
    monkeypatch.chdir(tmp_path)
    prim = DaclTargetEscalatePrimitive()
    op = _op(
        prim.name,
        target_dn="CN=svc,DC=corp,DC=local",
        container_dn="OU=Reaper,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    steps = prim.dry_run_steps(op)
    assert any("broad ACE grants all child classes/all writable properties" in s for s in steps)


# ── Fix 1: write_dacl_sd uses DACL_SECURITY_INFORMATION SD control ────────────

class _CtrlCaptureMock:
    """Minimal mock that records the controls passed to modify()."""

    def __init__(self):
        self.calls: list[dict] = []

    def modify(self, dn, changes, controls=None) -> bool:
        self.calls.append({"dn": dn, "changes": changes, "controls": controls})
        return True

    @property
    def result(self):
        return {"description": "mock"}


def test_write_dacl_sd_passes_sd_control():
    """write_dacl_sd must call conn.modify() with the DACL_SECURITY_INFORMATION SD control."""
    from dmsa_reaper.ldap.dacl_editor import write_dacl_sd

    mock = _CtrlCaptureMock()
    write_dacl_sd(mock, "CN=target,DC=corp,DC=local", _TEST_SD)

    assert len(mock.calls) == 1, "write_dacl_sd must call modify() exactly once"
    controls = mock.calls[0]["controls"]
    assert controls is not None, "write_dacl_sd must pass SD control to modify()"


def test_write_sd_delegates_to_write_dacl_sd():
    """write_sd() must pass SD control (via write_dacl_sd) to conn.modify()."""
    from dmsa_reaper.ldap.dacl_editor import write_sd

    mock = _CtrlCaptureMock()
    write_sd(mock, "CN=target,DC=corp,DC=local", _TEST_SD)

    assert len(mock.calls) == 1
    assert mock.calls[0]["controls"] is not None


def test_rollback_ntsecuritydescriptor_uses_sd_control():
    """_reverse_change must use write_dacl_sd (with SD control) for nTSecurityDescriptor changes."""
    from dmsa_reaper.models import AttributeChange, AttributeValue
    from dmsa_reaper.ops.rollback import _reverse_change

    mock = _CtrlCaptureMock()
    change = AttributeChange(
        dn="CN=target,DC=corp,DC=local",
        attribute="nTSecurityDescriptor",
        before=[AttributeValue.security_descriptor(_TEST_SD)],
        after=[AttributeValue.security_descriptor(_TEST_SD)],
        mode="replace",
    )
    _reverse_change(mock, change)

    assert len(mock.calls) == 1, "one modify() call expected for SD rollback"
    assert mock.calls[0]["controls"] is not None, "SD control must be passed for nTSecurityDescriptor rollback"


def test_rollback_ntsecuritydescriptor_no_before_skips_write():
    """_reverse_change with before=None and nTSecurityDescriptor must not call modify()."""
    from dmsa_reaper.models import AttributeChange, AttributeValue
    from dmsa_reaper.ops.rollback import _reverse_change

    mock = _CtrlCaptureMock()
    change = AttributeChange(
        dn="CN=target,DC=corp,DC=local",
        attribute="nTSecurityDescriptor",
        before=None,
        after=[AttributeValue.security_descriptor(_TEST_SD)],
        mode="replace",
    )
    _reverse_change(mock, change)
    assert len(mock.calls) == 0, "no-before nTSecurityDescriptor rollback must not write"


def test_dacl_execute_sd_write_uses_sd_control(tmp_path, monkeypatch):
    """DaclContainerEscalatePrimitive execute() must pass SD control on the DACL-mod write."""
    monkeypatch.chdir(tmp_path)
    prim = DaclContainerEscalatePrimitive()
    conn = _DaclMockConn()
    op = _op(
        prim.name,
        container_dn="OU=Reaper,DC=corp,DC=local",
        target_dn="CN=svc,DC=corp,DC=local",
        principal_sid="S-1-5-21-1-2-3-500",
        allow_broad_dacl=True,
    )
    prim.execute(op, confirm=True, conn=conn)

    # At least one modify call must have non-None controls (the SD write).
    assert any(ctl is not None for _, ctl in conn.controls_used), (
        "dacl execute must pass SD control for nTSecurityDescriptor write"
    )


# ── Fix 3: _check_container_create_rights ────────────────────────────────────

def test_check_container_create_rights_state_none_no_skip_raises():
    """Must raise when state is unavailable and allow_container_unknown is False."""
    import typer
    from dmsa_reaper.cli import _check_container_create_rights

    with pytest.raises(typer.BadParameter, match="unavailable"):
        _check_container_create_rights(None, "OU=Test,DC=corp,DC=local", allow_unmapped_container=False)


def test_check_container_create_rights_state_none_with_skip_passes():
    """Must not raise when state is unavailable but allow_container_unknown is True."""
    from dmsa_reaper.cli import _check_container_create_rights

    _check_container_create_rights(None, "OU=Test,DC=corp,DC=local", allow_unmapped_container=True)


def test_check_container_create_rights_container_not_in_state_raises():
    """Must raise when container is not in mapped state and allow_container_unknown is False."""
    import typer
    from dmsa_reaper.cli import _check_container_create_rights
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), containers=[])
    with pytest.raises(typer.BadParameter, match="state.containers"):
        _check_container_create_rights(state, "OU=Missing,DC=corp,DC=local", allow_unmapped_container=False)


def test_check_container_create_rights_container_not_in_state_with_skip_passes():
    """Must not raise when container is absent but allow_container_unknown is True."""
    from dmsa_reaper.cli import _check_container_create_rights
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), containers=[])
    _check_container_create_rights(state, "OU=Missing,DC=corp,DC=local", allow_unmapped_container=True)


def test_check_container_create_rights_with_createchild_passes():
    """Must not raise when the container has CreateChild rights for the principal."""
    from dmsa_reaper.cli import _check_container_create_rights
    from dmsa_reaper.models import ContainerObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(
        principal_sid="S-1-5-21-1-2-3-500",
        right="CreateChild",
        object_dn="OU=Reaper,DC=corp,DC=local",
    )
    container = ContainerObject(dn="OU=Reaper,DC=corp,DC=local", rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        containers=[container],
        current_principal=Principal(sid="S-1-5-21-1-2-3-500"),
    )
    _check_container_create_rights(state, "OU=Reaper,DC=corp,DC=local", allow_unmapped_container=False)


def test_check_container_create_rights_without_createchild_raises():
    """Must raise when container is in state but current principal has no CreateChild rights."""
    import typer
    from dmsa_reaper.cli import _check_container_create_rights
    from dmsa_reaper.models import ContainerObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(
        principal_sid="S-1-5-21-1-2-3-500",
        right="WriteDACL",
        object_dn="OU=Reaper,DC=corp,DC=local",
    )
    container = ContainerObject(dn="OU=Reaper,DC=corp,DC=local", rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        containers=[container],
        current_principal=Principal(sid="S-1-5-21-1-2-3-500"),
    )
    with pytest.raises(typer.BadParameter, match="no CreateChild rights"):
        _check_container_create_rights(state, "OU=Reaper,DC=corp,DC=local", allow_unmapped_container=False)


def test_check_container_create_rights_with_generic_all_passes():
    """GenericAll on the container must satisfy the CreateChild check."""
    from dmsa_reaper.cli import _check_container_create_rights
    from dmsa_reaper.models import ContainerObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(
        principal_sid="S-1-5-21-1-2-3-500",
        right="GenericAll",
        object_dn="OU=Reaper,DC=corp,DC=local",
    )
    container = ContainerObject(dn="OU=Reaper,DC=corp,DC=local", rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        containers=[container],
        current_principal=Principal(sid="S-1-5-21-1-2-3-500"),
    )
    _check_container_create_rights(state, "OU=Reaper,DC=corp,DC=local", allow_unmapped_container=False)
