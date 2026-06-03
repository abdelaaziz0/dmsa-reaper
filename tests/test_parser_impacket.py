"""Tests for acl/parser.py using real impacket-constructed ACE objects.

These tests verify that _parse_ace() and parse_security_descriptor() correctly
read the real impacket ldaptypes field layout:
    ace["AceType"], ace["AceFlags"],
    ace["Ace"]["Mask"]["Mask"], ace["Ace"]["Sid"],
    ace["Ace"]["Flags"], ace["Ace"]["ObjectType"], ace["Ace"]["InheritedObjectType"]

All tests skip gracefully when impacket is not installed.
"""

import pytest

try:
    from impacket.ldap import ldaptypes
    import impacket.uuid as iuuid
    HAS_IMPACKET = True
except Exception:
    HAS_IMPACKET = False

pytestmark = pytest.mark.skipif(not HAS_IMPACKET, reason="impacket not installed")

from dmsa_reaper.acl.parser import parse_security_descriptor, _parse_ace  # noqa: E402

# ── well-known GUIDs used in tests ────────────────────────────────────────────
# msDS-KeyCredentialLink attribute GUID (schema default)
KEY_CRED_GUID = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
# dMSA class GUID (msDS-DelegatedManagedServiceAccount)
DMSA_CLASS_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"

SID_STR = "S-1-5-21-111-222-333-1000"


# ── helpers ───────────────────────────────────────────────────────────────────

def _sid(s: str):
    sid = ldaptypes.LDAP_SID()
    sid.fromCanonical(s)
    return sid


def _make_allow_ace(sid_str: str, mask: int, flags: int = 0) -> object:
    """Build a real impacket ACCESS_ALLOWED_ACE wrapped in an ACE header."""
    inner = ldaptypes.ACCESS_ALLOWED_ACE()
    inner["Mask"] = ldaptypes.ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    inner["Sid"] = _sid(sid_str)
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    ace["Ace"] = inner
    return ace


def _make_deny_ace(sid_str: str, mask: int, flags: int = 0) -> object:
    inner = ldaptypes.ACCESS_DENIED_ACE()
    inner["Mask"] = ldaptypes.ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    inner["Sid"] = _sid(sid_str)
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    ace["Ace"] = inner
    return ace


def _make_object_allow_ace(
    sid_str: str,
    mask: int,
    object_type_guid: str | None = None,
    inherited_object_type_guid: str | None = None,
    flags: int = 0,
) -> object:
    """Build a real impacket ACCESS_ALLOWED_OBJECT_ACE."""
    inner = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    inner["Mask"] = ldaptypes.ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    obj_flags = 0
    if object_type_guid:
        obj_flags |= ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        inner["ObjectType"] = iuuid.string_to_bin(object_type_guid)
    else:
        inner["ObjectType"] = b""
    if inherited_object_type_guid:
        obj_flags |= ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT
        inner["InheritedObjectType"] = iuuid.string_to_bin(inherited_object_type_guid)
    else:
        inner["InheritedObjectType"] = b""
    inner["Flags"] = obj_flags
    inner["Sid"] = _sid(sid_str)
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    ace["Ace"] = inner
    return ace


def _make_object_deny_ace(
    sid_str: str,
    mask: int,
    object_type_guid: str | None = None,
    flags: int = 0,
) -> object:
    inner = ldaptypes.ACCESS_DENIED_OBJECT_ACE()
    inner["Mask"] = ldaptypes.ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    obj_flags = 0
    if object_type_guid:
        obj_flags |= ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        inner["ObjectType"] = iuuid.string_to_bin(object_type_guid)
    else:
        inner["ObjectType"] = b""
    inner["InheritedObjectType"] = b""
    inner["Flags"] = obj_flags
    inner["Sid"] = _sid(sid_str)
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    ace["Ace"] = inner
    return ace


# ── _parse_ace unit tests ─────────────────────────────────────────────────────

class TestParseAce:
    def test_simple_allow_ace(self):
        # 0x000f01ff = CreateChild|DeleteChild|ListContents|SelfWrite|ReadProperty|
        #              WriteProperty|DeleteTree|ListObject|ControlAccess|Delete|ReadControl
        raw = _make_allow_ace(SID_STR, 0x000f01ff)
        parsed, warning = _parse_ace(raw)
        assert warning is None
        assert parsed is not None
        assert parsed.ace_type == "allow"
        assert parsed.sid == SID_STR
        assert "WriteProperty" in parsed.rights
        assert "CreateChild" in parsed.rights

    def test_simple_deny_ace(self):
        raw = _make_deny_ace(SID_STR, 0x00040000)  # WriteDACL
        parsed, warning = _parse_ace(raw)
        assert warning is None
        assert parsed is not None
        assert parsed.ace_type == "deny"
        assert "WriteDACL" in parsed.rights

    def test_inherited_flag_set(self):
        _INHERITED_ACE = 0x10
        raw = _make_allow_ace(SID_STR, 0x00020000, flags=_INHERITED_ACE)
        parsed, _ = _parse_ace(raw)
        assert parsed is not None
        assert parsed.inherited is True

    def test_inherit_only_flag_set(self):
        _INHERIT_ONLY_ACE = 0x08
        raw = _make_allow_ace(SID_STR, 0x00020000, flags=_INHERIT_ONLY_ACE)
        parsed, _ = _parse_ace(raw)
        assert parsed is not None
        assert parsed.inherit_only is True

    def test_container_inherit_flag(self):
        _CONTAINER_INHERIT_ACE = 0x02
        raw = _make_allow_ace(SID_STR, 0x00020000, flags=_CONTAINER_INHERIT_ACE)
        parsed, _ = _parse_ace(raw)
        assert parsed is not None
        assert parsed.container_inherit is True

    def test_object_allow_ace_with_guid(self):
        # WriteProperty (0x20) restricted to msDS-KeyCredentialLink attribute.
        raw = _make_object_allow_ace(SID_STR, 0x00000020, object_type_guid=KEY_CRED_GUID)
        parsed, warning = _parse_ace(raw)
        assert warning is None
        assert parsed is not None
        assert parsed.ace_type == "allow"
        assert "WriteProperty" in parsed.rights
        assert parsed.object_type_guid is not None
        assert parsed.object_type_guid.lower() == KEY_CRED_GUID.lower()

    def test_object_deny_ace_with_guid(self):
        raw = _make_object_deny_ace(SID_STR, 0x00000001, object_type_guid=DMSA_CLASS_GUID)
        parsed, warning = _parse_ace(raw)
        assert warning is None
        assert parsed is not None
        assert parsed.ace_type == "deny"
        assert "CreateChild" in parsed.rights
        assert parsed.object_type_guid.lower() == DMSA_CLASS_GUID.lower()

    def test_object_ace_without_guid_flag_has_no_guid(self):
        # Object ACE with Flags=0 means ObjectType is not present.
        raw = _make_object_allow_ace(SID_STR, 0x00000020)  # no object_type_guid
        parsed, _ = _parse_ace(raw)
        assert parsed is not None
        assert parsed.object_type_guid is None

    def test_inherited_object_type_parsed(self):
        raw = _make_object_allow_ace(
            SID_STR, 0x00000001,
            object_type_guid=DMSA_CLASS_GUID,
            inherited_object_type_guid=KEY_CRED_GUID,
        )
        parsed, _ = _parse_ace(raw)
        assert parsed is not None
        assert parsed.inherited_object_type_guid is not None
        assert parsed.inherited_object_type_guid.lower() == KEY_CRED_GUID.lower()

    def test_audit_ace_skipped_cleanly(self):
        """An AUDIT ACE (type 0x02) must return (None, None) — no warning."""
        # Build a minimal audit ACE wrapper manually.
        ace = ldaptypes.ACE()
        ace["AceType"] = 0x02   # SYSTEM_AUDIT_ACE
        ace["AceFlags"] = 0
        # The inner Ace bytes can be empty — parser must not access them for audit types.
        ace["Ace"] = b""
        parsed, warning = _parse_ace(ace)
        assert parsed is None
        assert warning is None


# ── full round-trip via parse_security_descriptor ────────────────────────────

def _build_sd_with_aces(aces: list, owner_sid: str = SID_STR) -> bytes:
    """Build a minimal binary SD containing the given ACE list.

    impacket ACL quirk: the aces list must be set on the ``aces`` attribute
    of the ACL object (not via ``acl["Data"]``) so that ``ACL.getData()``
    can iterate it when serialising.
    """
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x0004  # SE_DACL_PRESENT
    owner = ldaptypes.LDAP_SID()
    owner.fromCanonical(owner_sid)
    sd["OwnerSid"] = owner
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 2
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = aces
    sd["Dacl"] = dacl
    return sd.getData()


class TestFullRoundTrip:
    def test_allow_ace_round_trip(self):
        raw_sd = _build_sd_with_aces([
            _make_allow_ace(SID_STR, 0x00000020),  # WriteProperty (0x20)
        ])
        psd = parse_security_descriptor(raw_sd)
        assert not psd.parse_failed
        assert psd.owner_sid is not None
        assert len(psd.aces) == 1
        assert psd.aces[0].ace_type == "allow"
        assert psd.aces[0].sid == SID_STR
        assert "WriteProperty" in psd.aces[0].rights

    def test_deny_ace_round_trip(self):
        raw_sd = _build_sd_with_aces([
            _make_deny_ace(SID_STR, 0x00040000),  # WriteDACL
        ])
        psd = parse_security_descriptor(raw_sd)
        assert not psd.parse_failed
        assert len(psd.aces) == 1
        assert psd.aces[0].ace_type == "deny"
        assert "WriteDACL" in psd.aces[0].rights

    def test_object_specific_write_property_ace(self):
        """WriteProperty restricted to msDS-KeyCredentialLink via GUID."""
        raw_sd = _build_sd_with_aces([
            _make_object_allow_ace(SID_STR, 0x00000020, object_type_guid=KEY_CRED_GUID),
        ])
        psd = parse_security_descriptor(raw_sd)
        assert not psd.parse_failed
        assert len(psd.aces) == 1
        ace = psd.aces[0]
        assert "WriteProperty" in ace.rights
        assert ace.object_type_guid is not None
        assert ace.object_type_guid.lower() == KEY_CRED_GUID.lower()

    def test_object_specific_create_child_dmsa(self):
        """CreateChild restricted to the dMSA class GUID."""
        raw_sd = _build_sd_with_aces([
            _make_object_allow_ace(SID_STR, 0x00000001, object_type_guid=DMSA_CLASS_GUID),
        ])
        psd = parse_security_descriptor(raw_sd)
        assert not psd.parse_failed
        ace = psd.aces[0]
        assert "CreateChild" in ace.rights
        assert ace.object_type_guid.lower() == DMSA_CLASS_GUID.lower()

    def test_inherit_only_ace_excluded_from_results(self):
        """An INHERIT_ONLY_ACE must not appear in the parsed aces for the current object."""
        _INHERIT_ONLY_ACE = 0x08
        raw_sd = _build_sd_with_aces([
            _make_allow_ace(SID_STR, 0x000f01ff, flags=_INHERIT_ONLY_ACE),
        ])
        psd = parse_security_descriptor(raw_sd)
        assert not psd.parse_failed
        assert psd.aces == []

    def test_mixed_aces_inherit_only_filtered(self):
        """Inherit-only ACE filtered; the non-inherit-only ACE is kept."""
        _INHERIT_ONLY_ACE = 0x08
        raw_sd = _build_sd_with_aces([
            _make_allow_ace(SID_STR, 0x000f01ff, flags=_INHERIT_ONLY_ACE),  # excluded
            _make_allow_ace(SID_STR, 0x00000020),                            # included (WriteProperty)
        ])
        psd = parse_security_descriptor(raw_sd)
        assert not psd.parse_failed
        assert len(psd.aces) == 1
        assert "WriteProperty" in psd.aces[0].rights
