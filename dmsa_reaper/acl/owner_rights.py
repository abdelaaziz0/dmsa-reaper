from __future__ import annotations

from dmsa_reaper.acl.ace_matcher import Ace, OWNER_RIGHTS_SID


def owner_rights_restricted(aces: list[Ace]) -> bool:
    """Return True if an OWNER RIGHTS ACE (S-1-3-4) is present in the DACL.

    When True:
    - The implicit owner grants (ReadControl + WriteDACL) are suppressed.
    - The explicit S-1-3-4 ACEs govern what the object owner is allowed to do.
      Those ACEs are evaluated by has_effective_right() with is_owner=True, which
      makes ace_applies_to_sid() match against ACEs whose SID is OWNER_RIGHTS_SID.
    """
    return any(ace.sid == OWNER_RIGHTS_SID for ace in aces)
