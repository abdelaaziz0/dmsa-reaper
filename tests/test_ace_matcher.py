"""Tests for acl/ace_matcher.py — ACE applicability and right matching."""


from dmsa_reaper.acl.ace_matcher import Ace, ace_applies_to_sid, ace_matches_right

DMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"
OTHER_GUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
USER_SID = "S-1-5-21-X-1000"


# ── ace_applies_to_sid ────────────────────────────────────────────────────────

class TestAceApplies:
    def test_direct_sid(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights=set())
        assert ace_applies_to_sid(ace, {USER_SID})

    def test_sid_not_present(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights=set())
        assert not ace_applies_to_sid(ace, {"S-1-5-21-X-9999"})

    def test_everyone_always_applies(self):
        ace = Ace(sid="S-1-1-0", ace_type="allow", rights=set())
        assert ace_applies_to_sid(ace, set())

    def test_authenticated_users_always_applies(self):
        ace = Ace(sid="S-1-5-11", ace_type="allow", rights=set())
        assert ace_applies_to_sid(ace, set())

    def test_self_not_applies_without_flag(self):
        ace = Ace(sid="S-1-5-10", ace_type="allow", rights=set())
        assert not ace_applies_to_sid(ace, {USER_SID}, is_self=False)

    def test_self_applies_with_flag(self):
        ace = Ace(sid="S-1-5-10", ace_type="allow", rights=set())
        assert ace_applies_to_sid(ace, {USER_SID}, is_self=True)

    def test_group_sid_in_set(self):
        group_sid = "S-1-5-21-X-500"
        ace = Ace(sid=group_sid, ace_type="allow", rights=set())
        assert ace_applies_to_sid(ace, {USER_SID, group_sid})


# ── ace_matches_right ─────────────────────────────────────────────────────────

class TestAceMatchesRight:
    def test_generic_all_matches_everything(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"GenericAll"})
        assert ace_matches_right(ace, "WriteProperty")
        assert ace_matches_right(ace, "CreateChild")
        assert ace_matches_right(ace, "WriteDACL")
        assert ace_matches_right(ace, "WriteProperty", object_type_guid=DMSA_GUID)

    def test_object_specific_generic_all_respects_object_type(self):
        ace = Ace(
            sid=USER_SID,
            ace_type="allow",
            rights={"GenericAll"},
            object_type_guid=DMSA_GUID,
        )
        assert ace_matches_right(ace, "WriteProperty", object_type_guid=DMSA_GUID)
        assert ace_matches_right(ace, "CreateChild", object_type_guid=DMSA_GUID)
        assert not ace_matches_right(ace, "WriteProperty", object_type_guid=OTHER_GUID)
        assert not ace_matches_right(ace, "WriteProperty")

    def test_generic_write_implies_write_property_selfwrite_readcontrol(self):
        """AD DS generic-rights mapping: GENERIC_WRITE → WriteProperty | SelfWrite | ReadControl."""
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"GenericWrite"})
        assert ace_matches_right(ace, "WriteProperty")
        assert ace_matches_right(ace, "WriteProperty", object_type_guid=DMSA_GUID)
        assert ace_matches_right(ace, "SelfWrite")
        assert ace_matches_right(ace, "ReadControl")

    def test_object_specific_generic_write_respects_object_type(self):
        ace = Ace(
            sid=USER_SID,
            ace_type="allow",
            rights={"GenericWrite"},
            object_type_guid=DMSA_GUID,
        )
        assert ace_matches_right(ace, "WriteProperty", object_type_guid=DMSA_GUID)
        assert not ace_matches_right(ace, "WriteProperty", object_type_guid=OTHER_GUID)
        assert not ace_matches_right(ace, "WriteProperty")
        assert not ace_matches_right(ace, "CreateChild", object_type_guid=DMSA_GUID)

    def test_object_specific_generic_read_respects_object_type(self):
        ace = Ace(
            sid=USER_SID,
            ace_type="allow",
            rights={"GenericRead"},
            object_type_guid=DMSA_GUID,
        )
        assert ace_matches_right(ace, "ReadProperty", object_type_guid=DMSA_GUID)
        assert not ace_matches_right(ace, "ReadProperty", object_type_guid=OTHER_GUID)
        assert not ace_matches_right(ace, "ReadProperty")

    def test_generic_write_does_not_imply_write_dacl_or_write_owner(self):
        """GenericWrite must not grant WriteDACL or WriteOwner — those require explicit ACEs."""
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"GenericWrite"})
        assert not ace_matches_right(ace, "WriteDACL")
        assert not ace_matches_right(ace, "WriteOwner")

    def test_generic_write_does_not_imply_create_child(self):
        """GenericWrite must not grant CreateChild — creating objects requires GenericAll or explicit ACE."""
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"GenericWrite"})
        assert not ace_matches_right(ace, "CreateChild")

    def test_specific_right_no_restriction(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"CreateChild"}, object_type_guid=None)
        assert ace_matches_right(ace, "CreateChild")

    def test_specific_right_with_restriction_match(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"CreateChild"}, object_type_guid=DMSA_GUID)
        assert ace_matches_right(ace, "CreateChild", object_type_guid=DMSA_GUID)

    def test_specific_right_with_restriction_no_match(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"CreateChild"}, object_type_guid=DMSA_GUID)
        assert not ace_matches_right(ace, "CreateChild", object_type_guid=OTHER_GUID)

    def test_object_restricted_ace_does_not_satisfy_unrestricted_check(self):
        # ACE grants CreateChild only for dMSA class; should NOT satisfy unrestricted CreateChild.
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"CreateChild"}, object_type_guid=DMSA_GUID)
        assert not ace_matches_right(ace, "CreateChild", object_type_guid=None)

    def test_unrestricted_ace_satisfies_specific_check(self):
        # ACE with no object_type_guid should satisfy a specific-type check.
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"WriteProperty"}, object_type_guid=None)
        assert ace_matches_right(ace, "WriteProperty", object_type_guid=DMSA_GUID)

    def test_wrong_right_not_matched(self):
        ace = Ace(sid=USER_SID, ace_type="allow", rights={"ReadProperty"})
        assert not ace_matches_right(ace, "WriteProperty")
