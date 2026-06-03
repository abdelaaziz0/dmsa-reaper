"""Low-level helpers for reading and modifying LDAP nTSecurityDescriptors.

Uses raw struct manipulation for the SD binary format (MS-DTYP self-relative SD).
impacket is used for SID serialization only; its ACCESS_ALLOWED_OBJECT_ACE type
always emits both ObjectType and InheritedObjectType fields regardless of Flags,
which is incorrect for the conditional-field layout in MS-DTYP §2.4.4.3.
Raw struct is therefore used for ACE construction to get the layout right.
"""

from __future__ import annotations

import struct
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


def add_aces_to_sd(raw_sd: bytes, new_aces: list[bytes]) -> bytes:
    """Prepend new_aces to the DACL in raw_sd and return the modified SD bytes.

    Operates on the raw self-relative SD binary (MS-DTYP §2.4.6).
    The DACL header offsets are updated accordingly.  If any of the new ACEs is an
    object ACE (type 0x05), the ACL revision is upgraded to ACL_REVISION_DS (4).
    """
    if len(raw_sd) < 20:
        raise ValueError(f"SD too short: {len(raw_sd)} bytes")

    # SD header (self-relative, 20 bytes):
    #   Revision(1) Sbz1(1) Control(2) OffsetOwner(4) OffsetGroup(4) OffsetSacl(4) OffsetDacl(4)
    offset_dacl = struct.unpack_from("<I", raw_sd, 16)[0]

    if offset_dacl == 0:
        raise ValueError("SD has no DACL (OffsetDacl = 0)")
    if offset_dacl + 8 > len(raw_sd):
        raise ValueError(f"OffsetDacl {offset_dacl} leaves no room for DACL header")

    # DACL (ACL) header: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2) = 8 bytes
    acl_rev, acl_sbz1, old_acl_size, old_ace_count, acl_sbz2 = struct.unpack_from(
        "<BBHHH", raw_sd, offset_dacl
    )

    if offset_dacl + old_acl_size > len(raw_sd):
        raise ValueError(
            f"DACL AclSize {old_acl_size} at offset {offset_dacl} "
            f"exceeds SD length {len(raw_sd)}"
        )

    # Extract existing ACE bytes (everything between DACL header and end of DACL)
    existing_aces = raw_sd[offset_dacl + 8 : offset_dacl + old_acl_size]
    # Extract any bytes that come AFTER the DACL (rare but possible)
    after_dacl = raw_sd[offset_dacl + old_acl_size :]

    # Build new DACL
    combined_new_aces = b"".join(new_aces)
    new_ace_data = combined_new_aces + existing_aces
    new_ace_count = old_ace_count + len(new_aces)
    new_acl_size = 8 + len(new_ace_data)
    size_delta = new_acl_size - old_acl_size

    # Upgrade ACL revision to DS if any new ACE is an object ACE (MS-DTYP §2.4.4.1).
    has_object_ace = any(len(ace) > 0 and ace[0] == ACE_TYPE_ALLOW_OBJECT for ace in new_aces)
    new_acl_rev = max(acl_rev, ACL_REVISION_DS) if has_object_ace else acl_rev

    new_dacl = (
        struct.pack("<BBHHH", new_acl_rev, acl_sbz1, new_acl_size, new_ace_count, acl_sbz2)
        + new_ace_data
    )

    # Rebuild SD header, adjusting offsets of any sections that come AFTER the DACL
    sd_header = bytearray(raw_sd[:20])
    for off_field in (4, 8, 12):  # OffsetOwner, OffsetGroup, OffsetSacl
        ptr = struct.unpack_from("<I", bytes(sd_header), off_field)[0]
        if ptr > offset_dacl:
            struct.pack_into("<I", sd_header, off_field, ptr + size_delta)
    # OffsetDacl does not change (DACL starts at the same position)

    # Preserve everything between the 20-byte header and the DACL start
    before_dacl_content = raw_sd[20:offset_dacl]

    return bytes(sd_header) + before_dacl_content + new_dacl + after_dacl


def read_sd(conn: "Connection", dn: str) -> bytes:
    """Read the raw nTSecurityDescriptor bytes for a DN using the DACL SD control."""
    conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope="BASE",
        attributes=["nTSecurityDescriptor"],
        controls=sd_control(DACL_SECURITY_INFORMATION),
    )
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
