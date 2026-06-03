"""Tests for owner-implied rights and OWNER RIGHTS SID restriction."""

from dmsa_reaper.acl.ace_matcher import Ace
from dmsa_reaper.acl.effective_rights import has_effective_right
from dmsa_reaper.acl.owner_rights import owner_rights_restricted

OWNER = "S-1-5-21-X-500"
OTHER = "S-1-5-21-X-999"
OWNER_RIGHTS_SID = "S-1-3-4"


def test_owner_gets_writedacl_implicitly():
    assert has_effective_right([], {OWNER}, "WriteDACL", owner_sid=OWNER)


def test_non_owner_does_not_get_writedacl_implicitly():
    assert not has_effective_right([], {OTHER}, "WriteDACL", owner_sid=OWNER)


def test_owner_implied_read_control():
    assert has_effective_right([], {OWNER}, "ReadControl", owner_sid=OWNER)


def test_owner_rights_ace_suppresses_implicit_writedacl():
    aces = [Ace(sid=OWNER_RIGHTS_SID, ace_type="allow", rights={"ReadControl"})]
    restricted = owner_rights_restricted(aces)
    assert restricted
    assert not has_effective_right(aces, {OWNER}, "WriteDACL", owner_sid=OWNER, owner_rights_restricted=True)


def test_owner_rights_restricted_returns_false_without_ace():
    aces = [Ace(sid=OWNER, ace_type="allow", rights={"ReadControl"})]
    assert not owner_rights_restricted(aces)


def test_owner_rights_explicitly_allows_writedacl():
    """S-1-3-4 ALLOW WriteDACL: owner gets WriteDACL via the explicit ACE, not implicitly."""
    aces = [Ace(sid=OWNER_RIGHTS_SID, ace_type="allow", rights={"WriteDACL", "ReadControl"})]
    assert owner_rights_restricted(aces)
    # Implicit grant is suppressed (owner_rights_restricted=True), but the explicit
    # S-1-3-4 ACE applies to the owner (is_owner computed inside has_effective_right).
    assert has_effective_right(aces, {OWNER}, "WriteDACL", owner_sid=OWNER, owner_rights_restricted=True)


def test_owner_rights_explicitly_denies_writedacl():
    """S-1-3-4 DENY WriteDACL: owner is explicitly denied WriteDACL."""
    aces = [Ace(sid=OWNER_RIGHTS_SID, ace_type="deny", rights={"WriteDACL"})]
    assert owner_rights_restricted(aces)
    assert not has_effective_right(aces, {OWNER}, "WriteDACL", owner_sid=OWNER, owner_rights_restricted=True)


def test_owner_rights_non_owner_unaffected_by_s134_ace():
    """S-1-3-4 ACEs must not apply to non-owners."""
    aces = [Ace(sid=OWNER_RIGHTS_SID, ace_type="allow", rights={"WriteDACL"})]
    # OTHER is not the owner — S-1-3-4 ACE should not apply.
    assert not has_effective_right(aces, {OTHER}, "WriteDACL", owner_sid=OWNER, owner_rights_restricted=True)
