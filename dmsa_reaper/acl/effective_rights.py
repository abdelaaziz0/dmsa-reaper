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
) -> bool:
    """Evaluate whether the principal holds the requested right on an AD object.

    Evaluation order (mirrors Windows AuthZ for one requested DS access bit):
    1. Owner-implied ReadControl / WriteDACL — suppressed when OWNER RIGHTS SID is present.
    2. Walk applicable ACEs in their stored DACL order.  The first matching deny
       rejects the still-ungranted bit; the first matching allow grants it.  A
       later inherited deny cannot revoke a bit granted by an earlier explicit
       allow.

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
    """
    is_owner = bool(owner_sid and owner_sid in principal_sids)

    # Implicit owner rights: ReadControl and WriteDACL are granted to the object owner
    # unless the OWNER RIGHTS SID is present in the DACL.
    if not owner_rights_restricted and is_owner:
        if right in ("WriteDACL", "ReadControl"):
            return True

    for ace in aces:
        if not ace_applies_to_sid(ace, principal_sids, is_owner=is_owner):
            continue
        if not ace_matches_right(ace, right, object_type_guid):
            continue
        if ace.ace_type == "deny":
            return False
        if ace.ace_type == "allow":
            return True

    return False
