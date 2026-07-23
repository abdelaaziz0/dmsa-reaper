"""Low-level helpers for reading and modifying LDAP nTSecurityDescriptors.

Uses raw struct manipulation for the SD binary format (MS-DTYP self-relative SD).
impacket is used for SID serialization only; its ACCESS_ALLOWED_OBJECT_ACE type
always emits both ObjectType and InheritedObjectType fields regardless of Flags,
which is incorrect for the conditional-field layout in MS-DTYP §2.4.4.3.
Raw struct is therefore used for ACE construction to get the layout right.
"""

from __future__ import annotations

import struct
import hashlib
from typing import TYPE_CHECKING

from dmsa_reaper.constants import DACL_SECURITY_INFORMATION
from dmsa_reaper.ldap.sd_control import sd_control

if TYPE_CHECKING:
    from ldap3 import Connection

# Access mask bits
CREATE_CHILD = 0x00000001
WRITE_PROPERTY = 0x00000020

# ACE type codes
ACE_TYPE_ALLOW = 0x00          # ACCESS_ALLOWED_ACE_TYPE
ACE_TYPE_ALLOW_OBJECT = 0x05   # ACCESS_ALLOWED_OBJECT_ACE_TYPE

# Object ACE Flags (MS-DTYP §2.4.4.3)
ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02

# ACL revision values (MS-DTYP §2.4.4.1)
ACL_REVISION = 0x02      # standard ACE types only
ACL_REVISION_DS = 0x04   # required when object-specific ACEs are present

_INHERITED_ACE = 0x10
_EXPLICIT_ALLOW_TYPES = frozenset({0x00, 0x05})
_EXPLICIT_DENY_TYPES = frozenset({0x01, 0x06})


def _build_sid_bytes(sid_str: str) -> bytes:
    """Serialize a SID string to binary using impacket."""
    try:
        from impacket.ldap.ldaptypes import LDAP_SID
    except ImportError as exc:
        raise RuntimeError(
            "impacket is required for DACL editing. Install it with: pip install impacket"
        ) from exc
    sid = LDAP_SID()
    sid.fromCanonical(sid_str)
    return sid.getData()


def _build_ace_bytes(ace_type: int, ace_flags: int, inner_bytes: bytes) -> bytes:
    """Wrap inner ACE data in an ACE header (type + flags + size + inner)."""
    ace_size = 4 + len(inner_bytes)
    header = struct.pack("<BBH", ace_type, ace_flags, ace_size)
    return header + inner_bytes


def build_allow_createchild_ace(
    principal_sid: str,
    object_type_guid_bytes: bytes | None = None,
) -> bytes:
    """Build an ACE granting CreateChild.

    If object_type_guid_bytes (16-byte GUID, little-endian) is provided, the ACE is
    object-specific (ACCESS_ALLOWED_OBJECT_ACE_TYPE, type 0x05) with only
    ACE_OBJECT_TYPE_PRESENT set.  Per MS-DTYP §2.4.4.3 the InheritedObjectType field
    is absent when ACE_INHERITED_OBJECT_TYPE_PRESENT (0x02) is not set in Flags.
    The inner layout is therefore: Mask(4) + Flags(4) + ObjectType(16) + Sid.

    Without a GUID a broad ACCESS_ALLOWED_ACE (type 0x00) is built instead.
    """
    sid_data = _build_sid_bytes(principal_sid)
    if object_type_guid_bytes is not None:
        if len(object_type_guid_bytes) != 16:
            raise ValueError(f"Object type GUID must be 16 bytes, got {len(object_type_guid_bytes)}")
        # MS-DTYP §2.4.4.3: inner = Mask(4) + Flags(4) + ObjectType(16) + Sid
        # ACE_INHERITED_OBJECT_TYPE_PRESENT is NOT set, so InheritedObjectType is absent.
        inner = (
            struct.pack("<II", CREATE_CHILD, ACE_OBJECT_TYPE_PRESENT)
            + object_type_guid_bytes
            + sid_data
        )
        return _build_ace_bytes(ACE_TYPE_ALLOW_OBJECT, 0, inner)
    else:
        # ACCESS_ALLOWED_ACE inner: Mask(4) + Sid
        inner = struct.pack("<I", CREATE_CHILD) + sid_data
        return _build_ace_bytes(ACE_TYPE_ALLOW, 0, inner)


def build_allow_writeproperty_ace(
    principal_sid: str,
    attr_guid_bytes: bytes | None = None,
) -> bytes:
    """Build an ACE granting WriteProperty.

    If attr_guid_bytes (16-byte GUID, little-endian) is provided, grants WriteProperty
    only for that attribute (object-specific ACE, InheritedObjectType absent).
    Otherwise a broad WriteProperty ACE is built (ACCESS_ALLOWED_ACE).
    """
    sid_data = _build_sid_bytes(principal_sid)
    if attr_guid_bytes is not None:
        if len(attr_guid_bytes) != 16:
            raise ValueError(f"Attribute GUID must be 16 bytes, got {len(attr_guid_bytes)}")
        # MS-DTYP §2.4.4.3: inner = Mask(4) + Flags(4) + ObjectType(16) + Sid
        # No InheritedObjectType — ACE_INHERITED_OBJECT_TYPE_PRESENT not set.
        inner = (
            struct.pack("<II", WRITE_PROPERTY, ACE_OBJECT_TYPE_PRESENT)
            + attr_guid_bytes
            + sid_data
        )
        return _build_ace_bytes(ACE_TYPE_ALLOW_OBJECT, 0, inner)
    else:
        inner = struct.pack("<I", WRITE_PROPERTY) + sid_data
        return _build_ace_bytes(ACE_TYPE_ALLOW, 0, inner)


def _split_aces(ace_data: bytes, ace_count: int) -> list[bytes]:
    """Split and validate an ACL's packed ACE sequence."""
    result: list[bytes] = []
    offset = 0
    for index in range(ace_count):
        if offset + 4 > len(ace_data):
            raise ValueError(f"ACE {index} header exceeds DACL data")
        ace_size = struct.unpack_from("<H", ace_data, offset + 2)[0]
        if ace_size < 4 or offset + ace_size > len(ace_data):
            raise ValueError(f"ACE {index} has invalid size {ace_size}")
        result.append(ace_data[offset : offset + ace_size])
        offset += ace_size
    if offset != len(ace_data):
        raise ValueError(
            f"DACL contains {len(ace_data) - offset} trailing bytes after {ace_count} ACEs"
        )
    return result


def ace_fingerprint(ace: bytes) -> str:
    """Return the exact journal fingerprint used for conflict-safe cleanup."""
    return hashlib.sha256(ace).hexdigest()


def _canonical_rank(ace: bytes) -> int:
    if len(ace) < 4:
        raise ValueError("ACE is too short")
    if ace[1] & _INHERITED_ACE:
        return 2
    if ace[0] in _EXPLICIT_DENY_TYPES:
        return 0
    if ace[0] in _EXPLICIT_ALLOW_TYPES:
        return 1
    raise ValueError(
        f"unsupported explicit DACL ACE type 0x{ace[0]:02x}; refusing to recanonicalize it"
    )


def _dacl_parts(raw_sd: bytes) -> tuple[int, int, int, int, int, list[bytes]]:
    if len(raw_sd) < 20:
        raise ValueError(f"SD too short: {len(raw_sd)} bytes")
    offset_dacl = struct.unpack_from("<I", raw_sd, 16)[0]
    if offset_dacl == 0:
        raise ValueError("SD has no DACL (OffsetDacl = 0)")
    if offset_dacl + 8 > len(raw_sd):
        raise ValueError(f"OffsetDacl {offset_dacl} leaves no room for DACL header")
    acl_rev, acl_sbz1, acl_size, ace_count, acl_sbz2 = struct.unpack_from(
        "<BBHHH", raw_sd, offset_dacl
    )
    if acl_size < 8 or offset_dacl + acl_size > len(raw_sd):
        raise ValueError(
            f"DACL AclSize {acl_size} at offset {offset_dacl} exceeds SD length {len(raw_sd)}"
        )
    ace_data = raw_sd[offset_dacl + 8 : offset_dacl + acl_size]
    return offset_dacl, acl_rev, acl_sbz1, acl_sbz2, acl_size, _split_aces(ace_data, ace_count)


def _replace_dacl_aces(
    raw_sd: bytes,
    *,
    offset_dacl: int,
    acl_rev: int,
    acl_sbz1: int,
    acl_sbz2: int,
    old_acl_size: int,
    aces: list[bytes],
) -> bytes:
    ace_data = b"".join(aces)
    new_acl_size = 8 + len(ace_data)
    size_delta = new_acl_size - old_acl_size
    has_object_ace = any(ace and ace[0] in {0x05, 0x06} for ace in aces)
    new_acl_rev = max(acl_rev, ACL_REVISION_DS) if has_object_ace else acl_rev
    new_dacl = (
        struct.pack("<BBHHH", new_acl_rev, acl_sbz1, new_acl_size, len(aces), acl_sbz2)
        + ace_data
    )
    sd_header = bytearray(raw_sd[:20])
    for off_field in (4, 8, 12):
        ptr = struct.unpack_from("<I", bytes(sd_header), off_field)[0]
        if ptr > offset_dacl:
            struct.pack_into("<I", sd_header, off_field, ptr + size_delta)
    before_dacl = raw_sd[20:offset_dacl]
    after_dacl = raw_sd[offset_dacl + old_acl_size :]
    return bytes(sd_header) + before_dacl + new_dacl + after_dacl


def add_aces_to_sd(raw_sd: bytes, new_aces: list[bytes]) -> bytes:
    """Insert explicit allow ACEs canonically and return the modified SD.

    Existing ACE order is preserved.  The input DACL must already be canonical;
    new explicit allows are placed after existing explicit allows and before all
    inherited ACEs.  Refusing noncanonical or duplicate input avoids silently
    changing Windows AccessCheck behavior and makes exact cleanup unambiguous.
    """
    parts = _dacl_parts(raw_sd)
    offset_dacl, acl_rev, acl_sbz1, acl_sbz2, old_acl_size, existing = parts
    ranks = [_canonical_rank(ace) for ace in existing]
    if ranks != sorted(ranks):
        raise ValueError("existing DACL is noncanonical; refusing to add an ACE")
    unique_new = list(dict.fromkeys(new_aces))
    if any(_canonical_rank(ace) != 1 for ace in unique_new):
        raise ValueError("only explicit allow ACE insertion is supported")
    existing_fingerprints = {ace_fingerprint(ace) for ace in existing}
    duplicates = [ace_fingerprint(ace) for ace in unique_new if ace_fingerprint(ace) in existing_fingerprints]
    if duplicates:
        raise ValueError("requested ACE already exists; exact cleanup would be ambiguous")
    inherited_at = next((i for i, rank in enumerate(ranks) if rank == 2), len(existing))
    combined = existing[:inherited_at] + unique_new + existing[inherited_at:]
    return _replace_dacl_aces(
        raw_sd,
        offset_dacl=offset_dacl,
        acl_rev=acl_rev,
        acl_sbz1=acl_sbz1,
        acl_sbz2=acl_sbz2,
        old_acl_size=old_acl_size,
        aces=combined,
    )


def remove_aces_by_fingerprint(raw_sd: bytes, fingerprints: list[str]) -> tuple[bytes, list[str]]:
    """Remove exactly one ACE for each recorded SHA-256 fingerprint.

    Returns ``(new_sd, missing)``.  Missing or duplicate journal targets are
    conflicts: no potentially third-party ACE is guessed or removed.
    """
    parts = _dacl_parts(raw_sd)
    offset_dacl, acl_rev, acl_sbz1, acl_sbz2, old_acl_size, existing = parts
    remaining = list(existing)
    missing: list[str] = []
    for fingerprint in fingerprints:
        matches = [i for i, ace in enumerate(remaining) if ace_fingerprint(ace) == fingerprint]
        if len(matches) != 1:
            missing.append(fingerprint)
            continue
        remaining.pop(matches[0])
    if missing:
        return raw_sd, missing
    return _replace_dacl_aces(
        raw_sd,
        offset_dacl=offset_dacl,
        acl_rev=acl_rev,
        acl_sbz1=acl_sbz1,
        acl_sbz2=acl_sbz2,
        old_acl_size=old_acl_size,
        aces=remaining,
    ), []


def read_sd(conn: "Connection", dn: str) -> bytes:
    """Read the raw nTSecurityDescriptor bytes for a DN using the DACL SD control."""
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope="BASE",
        attributes=["nTSecurityDescriptor"],
        controls=sd_control(DACL_SECURITY_INFORMATION),
    )
    from dmsa_reaper.ldap.query import ensure_search_succeeded
    ensure_search_succeeded(conn, ok, f"read nTSecurityDescriptor for {dn!r}")
    if not conn.entries:
        raise RuntimeError(f"Object not found: {dn}")
    entry = conn.entries[0]
    if "nTSecurityDescriptor" not in entry:
        raise RuntimeError(f"nTSecurityDescriptor not readable on: {dn}")
    raw = entry["nTSecurityDescriptor"].raw_values
    if not raw:
        raise RuntimeError(f"nTSecurityDescriptor is empty on: {dn}")
    return bytes(raw[0])


def write_dacl_sd(conn: "Connection", dn: str, raw_sd: bytes) -> None:
    """Write a raw nTSecurityDescriptor with DACL_SECURITY_INFORMATION SD flags control.

    The SD flags control (OID 1.2.840.113556.1.4.801) tells the DC which security
    descriptor section is being replaced.  Without it the DC may reject the write or
    silently ignore the DACL.  This must be used for all nTSecurityDescriptor writes.
    """
    from ldap3 import MODIFY_REPLACE
    if not conn.modify(
        dn,
        {"nTSecurityDescriptor": [(MODIFY_REPLACE, [raw_sd])]},
        controls=sd_control(DACL_SECURITY_INFORMATION),
    ):
        raise RuntimeError(
            f"LDAP nTSecurityDescriptor write failed for {dn}: {conn.result}"
        )


def write_sd(conn: "Connection", dn: str, raw_sd: bytes) -> None:
    """Write a raw nTSecurityDescriptor back to LDAP with SD flags control."""
    write_dacl_sd(conn, dn, raw_sd)
