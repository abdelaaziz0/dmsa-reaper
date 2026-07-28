from __future__ import annotations

from dataclasses import dataclass

# Well-known SIDs that always apply to any authenticated principal.
_ALWAYS_APPLY = frozenset({
    "S-1-1-0",               # Everyone
    "S-1-5-11",              # Authenticated Users
    "EVERYONE",              # alias seen in some parsers
    "AUTHENTICATED_USERS",   # alias
})

# OWNER RIGHTS SID — when present in the DACL, suppresses implicit owner grants
# and instead the explicit ACEs for this SID govern what the object owner may do.
OWNER_RIGHTS_SID = "S-1-3-4"

# AD DS generic-rights mapping per MS-DTYP / MS-ADTS.
#
# GENERIC_WRITE maps to: READ_CONTROL | DS_WRITE_PROP | DS_SELF
# It does NOT map to WRITE_DAC or WRITE_OWNER.  Those require explicit ACEs
# or GenericAll.  Mapping GenericWrite to WriteDACL/WriteOwner is incorrect
# and would produce false-positive dangerous-rights findings.
_GENERIC_WRITE_IMPLIES = frozenset({"WriteProperty", "SelfWrite", "ReadControl"})

# GENERIC_READ maps to: READ_CONTROL | DS_LIST_CONTENTS | DS_LIST_OBJECT | DS_READ_PROP
_GENERIC_READ_IMPLIES = frozenset({"ReadProperty", "ReadControl", "ListContents", "ListObject"})


@dataclass(frozen=True)
class Ace:
    sid: str
    ace_type: str                              # "allow" or "deny"
    rights: set[str]                           # right-name tokens from _mask_to_rights
    object_type_guid: str | None = None        # None = applies to all object/attribute types
    inherited: bool = False                    # INHERITED_ACE (0x10): propagated from parent
    attribute: str | None = None

    # Propagation flags — these govern child objects, not the current object.
    # Inherit-only ACEs must not be used to evaluate access on the object they are attached to.
    inherit_only: bool = False                 # INHERIT_ONLY_ACE (0x08)
    container_inherit: bool = False            # CONTAINER_INHERIT_ACE (0x02)
    object_inherit: bool = False               # OBJECT_INHERIT_ACE (0x01)

    # InheritedObjectType GUID from object ACEs — restricts which child class inherits this ACE.
    inherited_object_type_guid: str | None = None


def _object_type_matches(ace: Ace, requested_guid: str | None) -> bool:
    """Return True when the ACE's object-type scope covers the requested scope."""
    if requested_guid is not None:
        return ace.object_type_guid is None or ace.object_type_guid.lower() == requested_guid.lower()
    return ace.object_type_guid is None


def ace_applies_to_sid(
    ace: Ace,
    principal_sids: set[str],
    *,
    is_owner: bool = False,
) -> bool:
    """Return True if this ACE's SID applies to the given principal SID set.

    Args:
        ace: The ACE to evaluate.
        principal_sids: All SIDs held by the principal (direct + nested groups).
        is_owner: True when the principal is the object owner (enables OWNER RIGHTS SID matching).
    """
    if ace.sid in _ALWAYS_APPLY:
        return True
    # When the principal owns the object, OWNER RIGHTS SID ACEs govern their rights.
    if ace.sid == OWNER_RIGHTS_SID and is_owner:
        return True
    return ace.sid in principal_sids


def ace_matches_right(ace: Ace, right: str, object_type_guid: str | None = None) -> bool:
    """Return True if this ACE grants (or denies) the requested right.

    Args:
        ace: The ACE to test.
        right: The right token to check (e.g. "WriteProperty", "CreateChild", "WriteDACL").
        object_type_guid: When not None, the check is for a specific attribute/class GUID.
            The ACE matches if it has no object-type restriction OR its restriction matches.
            When None, the check is for the right with no object-type restriction; the ACE
            must have no object_type_guid restriction to satisfy an unrestricted check.
    """
    ace_rights = ace.rights

    # GenericAll covers every right within the ACE's object-type scope.
    if "GenericAll" in ace_rights:
        return _object_type_matches(ace, object_type_guid)

    # GenericWrite implies WriteProperty (all attrs), SelfWrite, ReadControl.
    # It does NOT imply CreateChild, WriteDACL, or WriteOwner.
    if "GenericWrite" in ace_rights and right in _GENERIC_WRITE_IMPLIES:
        return _object_type_matches(ace, object_type_guid)

    # GenericRead implies ReadProperty, ReadControl, ListContents, ListObject.
    if "GenericRead" in ace_rights and right in _GENERIC_READ_IMPLIES:
        return _object_type_matches(ace, object_type_guid)

    if right not in ace_rights:
        return False

    return _object_type_matches(ace, object_type_guid)
