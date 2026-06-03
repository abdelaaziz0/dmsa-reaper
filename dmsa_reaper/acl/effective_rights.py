from __future__ import annotations

from dmsa_reaper.acl.ace_matcher import Ace, ace_applies_to_sid, ace_matches_right


def has_effective_right(
    aces: list[Ace],
    principal_sids: set[str],
    right: str,
    *,
    object_type_guid: str | None = None,
    owner_sid: str | None = None,
    owner_rights_restricted: bool = False,
    is_self: bool = False,
) -> bool:
    """Evaluate whether the principal holds the requested right on an AD object.

    Evaluation order (mirrors Windows AuthZ for DS objects):
    1. Owner-implied ReadControl / WriteDACL — suppressed when OWNER RIGHTS SID is present.
    2. DENY ACEs (including OWNER RIGHTS SID ACEs when principal is the owner) — first match denies.
    3. ALLOW ACEs (including OWNER RIGHTS SID ACEs when principal is the owner) — first match grants.

    The OWNER RIGHTS SID (S-1-3-4) requires special treatment:
    - If *any* ACE with sid=S-1-3-4 is present in the DACL, the implicit owner grants
      (ReadControl + WriteDACL) are suppressed (owner_rights_restricted=True from the caller).
    - The explicit S-1-3-4 ACEs then apply to the principal *only* when that principal owns
      the object (is_owner=True, computed below from owner_sid).

    Args:
        aces: Parsed DACL ACEs for the object.
        principal_sids: All SIDs held by the principal (direct + nested groups).
        right: Right token to test.
        object_type_guid: Optional attribute/class GUID for object-specific rights.
        owner_sid: The object's owner SID.
        owner_rights_restricted: True when an OWNER RIGHTS ACE is present in the DACL,
            suppressing implicit owner grants.
        is_self: True when the principal IS the target object (enables SELF SID matching).
    """
    is_owner = bool(owner_sid and owner_sid in principal_sids)

    # Implicit owner rights: ReadControl and WriteDACL are granted to the object owner
    # unless the OWNER RIGHTS SID is present in the DACL.
    if not owner_rights_restricted and is_owner:
        if right in ("WriteDACL", "ReadControl"):
            return True

    applicable = [
        a for a in aces
        if ace_applies_to_sid(a, principal_sids, is_self=is_self, is_owner=is_owner)
    ]

    # DENY wins before any ALLOW — includes S-1-3-4 DENY ACEs for the owner.
    for ace in applicable:
        if ace.ace_type == "deny" and ace_matches_right(ace, right, object_type_guid):
            return False

    # First matching ALLOW grants the right.
    for ace in applicable:
        if ace.ace_type == "allow" and ace_matches_right(ace, right, object_type_guid):
            return True

    return False
