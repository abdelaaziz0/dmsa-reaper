from __future__ import annotations

from dataclasses import dataclass, field

from dmsa_reaper.acl.ace_matcher import Ace
from dmsa_reaper.utils import bytes_to_guid_le

try:
    from impacket.ldap import ldaptypes
except Exception:  # pragma: no cover
    ldaptypes = None

# ACE type codes from MS-DTYP.
_ACE_ALLOW = frozenset({0x00, 0x05})   # ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE
_ACE_DENY  = frozenset({0x01, 0x06})   # ACCESS_DENIED_ACE,  ACCESS_DENIED_OBJECT_ACE
_ACE_OBJECT = frozenset({0x05, 0x06})  # Object ACE types carry optional ObjectType GUID

# Callback/conditional ACEs can affect AccessCheck but require claims and a
# conditional-expression evaluator that this project does not implement.  A
# DACL containing one must be classified as unknown, never as exploitable.
_ACE_CALLBACK = frozenset({0x09, 0x0A, 0x0B, 0x0C})

# AceFlags bits (from the AceFlags byte of the ACE header).
_INHERITED_ACE         = 0x10  # ACE was inherited from a parent container
_INHERIT_ONLY_ACE      = 0x08  # ACE applies to child objects only — NOT the current object
_CONTAINER_INHERIT_ACE = 0x02  # ACE propagates to container (non-leaf) children
_OBJECT_INHERIT_ACE    = 0x01  # ACE propagates to non-container children

# Object ACE Flags bits (Flags field inside the inner ACCESS_*_OBJECT_ACE).
_OBJ_TYPE_PRESENT           = 0x01  # ObjectType GUID is present
_INHERITED_OBJ_TYPE_PRESENT = 0x02  # InheritedObjectType GUID is present

# Access mask bit → right name.
_MASK_BITS: list[tuple[int, str]] = [
    (0x00000001, "CreateChild"),
    (0x00000002, "DeleteChild"),
    (0x00000004, "ListContents"),
    (0x00000008, "SelfWrite"),
    (0x00000010, "ReadProperty"),
    (0x00000020, "WriteProperty"),
    (0x00000040, "DeleteTree"),
    (0x00000080, "ListObject"),
    (0x00000100, "ControlAccess"),
    (0x00010000, "Delete"),
    (0x00020000, "ReadControl"),
    (0x00040000, "WriteDACL"),
    (0x00080000, "WriteOwner"),
    (0x10000000, "GenericAll"),
    (0x20000000, "GenericExecute"),
    (0x40000000, "GenericWrite"),
    (0x80000000, "GenericRead"),
]


def _mask_to_rights(mask: int) -> set[str]:
    return {name for bit, name in _MASK_BITS if mask & bit}


def _parse_ace(ace) -> tuple[Ace | None, str | None]:
    """Convert one impacket ACE object into an Ace dataclass.

    Real impacket ldaptypes.ACE field layout:
        ace["AceType"]    — ACE type byte (0=allow, 1=deny, 5=allow-obj, 6=deny-obj, …)
        ace["AceFlags"]   — inheritance / propagation flags byte
        ace["Ace"]        — inner structure (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, …)
            inner["Mask"]["Mask"]   — DWORD access mask
            inner["Sid"]            — LDAP_SID with .formatCanonical()
        For object ACEs additionally:
            inner["Flags"]          — ObjectType/InheritedObjectType presence bits
            inner["ObjectType"]     — 16-byte GUID (little-endian)
            inner["InheritedObjectType"] — 16-byte GUID (little-endian)

    Returns:
        (Ace, None):       successfully parsed DACL ACE.
        (None, None):      unsupported audit/system/alarm ACE — skipped cleanly.
        (None, warning):   malformed DACL ACE — error message to surface as parse_warning.
    """
    try:
        ace_type_val = int(ace["AceType"])

        if ace_type_val in _ACE_CALLBACK:
            return None, (
                f"unsupported callback/conditional DACL ACE type 0x{ace_type_val:02x}; "
                "effective access is unknown"
            )
        if ace_type_val in _ACE_ALLOW:
            type_str = "allow"
        elif ace_type_val in _ACE_DENY:
            type_str = "deny"
        else:
            return None, None  # audit / system / alarm — skip cleanly, no warning

        ace_flags_val = int(ace["AceFlags"])
        inherited         = bool(ace_flags_val & _INHERITED_ACE)
        inherit_only      = bool(ace_flags_val & _INHERIT_ONLY_ACE)
        container_inherit = bool(ace_flags_val & _CONTAINER_INHERIT_ACE)
        object_inherit    = bool(ace_flags_val & _OBJECT_INHERIT_ACE)

        inner    = ace["Ace"]
        mask_val = int(inner["Mask"]["Mask"])
        sid_obj  = inner["Sid"]
        sid: str = sid_obj.formatCanonical() if hasattr(sid_obj, "formatCanonical") else str(sid_obj)

        object_type_guid: str | None = None
        inherited_object_type_guid: str | None = None

        if ace_type_val in _ACE_OBJECT:
            try:
                flags = int(inner["Flags"])
                if flags & _OBJ_TYPE_PRESENT:
                    raw_ot = bytes(inner["ObjectType"])
                    if len(raw_ot) != 16:
                        raise ValueError(f"ObjectType GUID must be 16 bytes, got {len(raw_ot)}")
                    object_type_guid = bytes_to_guid_le(raw_ot)
                if flags & _INHERITED_OBJ_TYPE_PRESENT:
                    raw_iot = bytes(inner["InheritedObjectType"])
                    if len(raw_iot) == 16:
                        inherited_object_type_guid = bytes_to_guid_le(raw_iot)
            except Exception as exc:
                return None, f"DACL ACE parse error: malformed object type GUID: {exc}"

        rights = _mask_to_rights(mask_val)
        return Ace(
            sid=sid,
            ace_type=type_str,
            rights=rights,
            object_type_guid=object_type_guid,
            inherited=inherited,
            inherit_only=inherit_only,
            container_inherit=container_inherit,
            object_inherit=object_inherit,
            inherited_object_type_guid=inherited_object_type_guid,
        ), None

    except Exception as exc:
        return None, f"DACL ACE parse error: {exc}"


def _try_parse_dacl(raw_sd: bytes) -> tuple[list[Ace], list[str]]:
    """Internal: parse DACL ACEs and return (aces, warnings).

    Inherit-only ACEs are intentionally excluded from the returned list because
    they govern child objects only and must not affect access evaluation on the
    current object.  Parse errors for individual ACEs are surfaced as warnings
    rather than silently producing an empty DACL.
    """
    if ldaptypes is None:
        return [], ["impacket not available; DACL parsing disabled"]

    warnings: list[str] = []
    aces: list[Ace] = []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        dacl = sd["Dacl"]
        if dacl is None or (isinstance(dacl, (bytes, bytearray)) and not dacl):
            return [], []
        for raw_ace in dacl["Data"]:
            parsed, warning = _parse_ace(raw_ace)
            if warning:
                warnings.append(warning)
            elif parsed is not None and not parsed.inherit_only:
                aces.append(parsed)
    except Exception as exc:
        warnings.append(f"DACL parse error: {exc}")
    return aces, warnings


@dataclass
class ParsedSecurityDescriptor:
    owner_sid: str | None
    aces: list[Ace]
    raw: bytes | None = None
    parse_failed: bool = False
    parse_warnings: list[str] = field(default_factory=list)
    null_dacl: bool = False


def parse_security_descriptor(raw_sd: bytes | None) -> ParsedSecurityDescriptor:
    """Parse owner SID and DACL ACEs from a raw nTSecurityDescriptor blob.

    Parse failures are recorded in parse_warnings and parse_failed rather than
    silently producing an empty DACL.  An empty DACL (no ACEs) and a failed parse
    are therefore distinguishable by the caller.
    """
    if not raw_sd:
        return ParsedSecurityDescriptor(owner_sid=None, aces=[], raw=raw_sd)

    if ldaptypes is None:
        return ParsedSecurityDescriptor(
            owner_sid=None,
            aces=[],
            raw=raw_sd,
            parse_failed=True,
            parse_warnings=["impacket not available; SD parsing disabled"],
        )

    owner_sid: str | None = None
    null_dacl = False
    parse_failed = False
    parse_warnings: list[str] = []

    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        owner = sd["OwnerSid"]
        # After parsing, OwnerSid is either a LDAP_SID object or empty bytes b''.
        owner_sid = owner.formatCanonical() if hasattr(owner, "formatCanonical") else None
        dacl = sd["Dacl"]
        null_dacl = dacl is None or (
            isinstance(dacl, (bytes, bytearray)) and not dacl
        )
    except Exception as exc:
        parse_failed = True
        parse_warnings.append(f"SD owner parse error: {exc}")

    aces, dacl_warnings = _try_parse_dacl(raw_sd)
    if dacl_warnings:
        parse_failed = True
        parse_warnings.extend(dacl_warnings)

    return ParsedSecurityDescriptor(
        owner_sid=owner_sid,
        aces=aces,
        raw=raw_sd,
        parse_failed=parse_failed,
        parse_warnings=parse_warnings,
        null_dacl=null_dacl,
    )


def parse_dacl_aces(raw_sd: bytes | None) -> list[Ace]:
    """Public convenience wrapper: returns parsed ACEs; parse failures yield an empty list."""
    if not raw_sd:
        return []
    aces, _ = _try_parse_dacl(raw_sd)
    return aces


def parse_owner_from_sd(raw_sd: bytes | None) -> ParsedSecurityDescriptor:
    """Backward-compatible alias for parse_security_descriptor."""
    return parse_security_descriptor(raw_sd)
