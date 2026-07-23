"""Tests for acl/enrichment.py — compute_effective_rights."""

from dmsa_reaper.acl.ace_matcher import Ace
from dmsa_reaper.acl.enrichment import compute_effective_rights

DMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"
ATTR_GUID = "a0945b2b-57a2-43bd-b327-4d112a4e8bd1"
USER_SID = "S-1-5-21-X-1000"
DN = "OU=Apps,DC=corp,DC=local"


def _rights(*right_names, guid=None) -> list[Ace]:
    return [Ace(sid=USER_SID, ace_type="allow", rights={r}, object_type_guid=guid) for r in right_names]


class TestComputeEffectiveRights:
    def test_no_aces_no_rights(self):
        rights, writable = compute_effective_rights([], USER_SID, {USER_SID}, DN, None)
        assert rights == []
        assert writable == []

    def test_create_child_dmsa_detected(self):
        aces = [Ace(sid=USER_SID, ace_type="allow", rights={"CreateChild"}, object_type_guid=DMSA_GUID)]
        rights, _ = compute_effective_rights(
            aces, USER_SID, {USER_SID}, DN, None, dmsa_class_guid=DMSA_GUID
        )
        right_names = {r.right for r in rights}
        assert "CreateChild:dMSA" in right_names

    def test_generic_all_aces_produces_create_child_dmsa(self):
        aces = [Ace(sid=USER_SID, ace_type="allow", rights={"GenericAll"})]
        rights, _ = compute_effective_rights(
            aces, USER_SID, {USER_SID}, DN, None, dmsa_class_guid=DMSA_GUID
        )
        right_names = {r.right for r in rights}
        assert "GenericAll" in right_names
        assert "CreateChild:dMSA" in right_names

    def test_write_property_attr_detected(self):
        aces = [Ace(sid=USER_SID, ace_type="allow", rights={"WriteProperty"}, object_type_guid=ATTR_GUID)]
        rights, writable = compute_effective_rights(
            aces, USER_SID, {USER_SID}, DN, None,
            attr_guids={"msDS-ManagedAccountPrecededByLink": ATTR_GUID},
        )
        assert "msDS-ManagedAccountPrecededByLink" in writable

    def test_deny_blocks_right(self):
        aces = [
            Ace(sid=USER_SID, ace_type="deny", rights={"WriteProperty"}),
            Ace(sid=USER_SID, ace_type="allow", rights={"GenericAll"}),
        ]
        rights, writable = compute_effective_rights(
            aces, USER_SID, {USER_SID}, DN, None,
            attr_guids={"msDS-ManagedAccountPrecededByLink": ATTR_GUID},
        )
        assert "msDS-ManagedAccountPrecededByLink" not in writable

    def test_owner_implied_write_dacl(self):
        rights, _ = compute_effective_rights(
            [], USER_SID, {USER_SID}, DN, owner_sid=USER_SID
        )
        right_names = {r.right for r in rights}
        assert "WriteDACL" in right_names

    def test_side_filter_skips_wrong_side(self):
        """Attribute that lives on 'dmsa' should not appear in target-side enrichment."""
        from dmsa_reaper.constants import ATTR_LIVES_ON
        # Find a dmsa-side attribute
        dmsa_attrs = {k: "fake-guid" for k, v in ATTR_LIVES_ON.items() if v == "dmsa"}
        if not dmsa_attrs:
            return
        aces = [Ace(sid=USER_SID, ace_type="allow", rights={"WriteProperty"})]
        _, writable = compute_effective_rights(
            aces, USER_SID, {USER_SID}, DN, None,
            attr_guids=dmsa_attrs, side="target"
        )
        assert writable == []

    def test_empty_principal_sid_returns_empty(self):
        aces = [Ace(sid=USER_SID, ace_type="allow", rights={"GenericAll"})]
        rights, writable = compute_effective_rights(aces, "", set(), DN, None)
        assert rights == []
        assert writable == []
