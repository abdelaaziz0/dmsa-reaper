from __future__ import annotations

from ldap3 import SUBTREE, Connection

from dmsa_reaper.constants import KDS_ROOT_KEYS_RDN
from dmsa_reaper.models import CheckStatus

# LDAP result codes used for error classification.
_LDAP_NO_SUCH_OBJECT = 32       # base DN does not exist
_LDAP_INSUFFICIENT_ACCESS = 50  # access denied to search base or results


def kds_root_key_status(conn: Connection, config_nc: str) -> CheckStatus:
    """Return whether the KDS root-key container has a child key."""
    base = f"{KDS_ROOT_KEYS_RDN},{config_nc}"
    try:
        ok = conn.search(
            search_base=base,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["cn"],
            size_limit=5,
        )
    except Exception:
        return CheckStatus.unknown

    result = (getattr(conn, "result", None) or {})
    code = result.get("result", -1)

    if not ok:
        if code == _LDAP_NO_SUCH_OBJECT:
            return CheckStatus.absent
        if code == _LDAP_INSUFFICIENT_ACCESS:
            return CheckStatus.unknown
        return CheckStatus.unknown

    children = [
        entry
        for entry in conn.entries
        if getattr(entry, "entry_dn", None)
        and entry.entry_dn.lower() != base.lower()
    ]
    return CheckStatus.present if children else CheckStatus.absent
