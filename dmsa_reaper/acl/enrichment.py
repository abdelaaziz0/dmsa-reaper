from __future__ import annotations

from dmsa_reaper.acl.ace_matcher import Ace
from dmsa_reaper.acl.effective_rights import has_effective_right
from dmsa_reaper.acl.owner_rights import owner_rights_restricted as _owner_rights_restricted
from dmsa_reaper.constants import ATTR_LIVES_ON
from dmsa_reaper.models import Right


def compute_effective_rights(
    aces: list[Ace],
    principal_sid: str,
    principal_sids: set[str],
    object_dn: str,
    owner_sid: str | None,
    *,
    dmsa_class_guid: str | None = None,
    attr_guids: dict[str, str] | None = None,
    side: str = "any",
    is_self: bool = False,
    null_dacl: bool = False,
) -> tuple[list[Right], list[str]]:
    """Compute Rights held by the principal on one AD object.

    Args:
        aces: Parsed DACL ACEs.
        principal_sid: The primary SID of the principal.
        principal_sids: Full SID set (direct + nested groups).
        object_dn: DN of the object being evaluated.
        owner_sid: Owner SID of the object (for implicit owner rights).
        dmsa_class_guid: Schema GUID for the dMSA class (enables CreateChild:dMSA detection).
        attr_guids: Mapping of attribute ldap-display-name → schema GUID.
        side: Filter attribute checks to "dmsa", "target", or "any" (default).
        is_self: True when the principal IS the object (e.g. dMSA evaluating itself).

    Returns:
        (rights, writable_attrs)
        - rights: list[Right] — each detected right held by the principal.
        - writable_attrs: list of attribute ldap-display-names writable by the principal.
    """
    if not principal_sid:
        return [], []

    or_restricted = _owner_rights_restricted(aces)

    rights: list[Right] = []
    writable_attrs: list[str] = []

    def _check(right_name: str, *, guid: str | None = None) -> bool:
        # A null DACL grants all requested access.  This is intentionally
        # distinct from an empty DACL, which grants none.
        if null_dacl:
            return True
        return has_effective_right(
            aces,
            principal_sids,
            right_name,
            object_type_guid=guid,
            owner_sid=owner_sid,
            owner_rights_restricted=or_restricted,
            is_self=is_self,
        )

    def _add(right_name: str, attr: str | None = None, guid: str | None = None) -> None:
        rights.append(Right(
            principal_sid=principal_sid,
            right=right_name,
            object_dn=object_dn,
            attribute=attr,
            object_type_guid=guid,
        ))

    # --- Generic / structural rights ---
    for rname in ("GenericAll", "GenericWrite", "WriteDACL", "WriteOwner", "ReadControl", "Delete"):
        if _check(rname):
            _add(rname)

    # --- CreateChild (unrestricted — any object type) ---
    if _check("CreateChild"):
        _add("CreateChild")

    # --- CreateChild:dMSA specifically (requires GenericAll or explicit CreateChild ACE) ---
    # GenericWrite does NOT imply CreateChild in the AD DS generic-rights mapping.
    if dmsa_class_guid and _check("CreateChild", guid=dmsa_class_guid):
        _add("CreateChild:dMSA", guid=dmsa_class_guid)

    # --- WriteProperty for dMSA-relevant attributes ---
    if attr_guids:
        for attr_name, attr_guid in attr_guids.items():
            lives_on = ATTR_LIVES_ON.get(attr_name, "any")
            if side != "any" and lives_on not in (side, "any"):
                continue
            if _check("WriteProperty", guid=attr_guid):
                _add(f"WriteProperty:{attr_name}", attr=attr_name, guid=attr_guid)
                writable_attrs.append(attr_name)

    return rights, writable_attrs
