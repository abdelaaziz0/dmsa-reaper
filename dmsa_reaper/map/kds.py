from __future__ import annotations

from ldap3 import SUBTREE, Connection

from dmsa_reaper.constants import KDS_ROOT_KEYS_RDN
from dmsa_reaper.models import CheckStatus

# LDAP result codes used for error classification.
_LDAP_NO_SUCH_OBJECT = 32       # base DN does not exist
_LDAP_INSUFFICIENT_ACCESS = 50  # access denied to search base or results


def detect_kds_root_key(conn: Connection, config_nc: str) -> tuple[CheckStatus, list[str]]:
    """Search for KDS root key objects and return (status, diagnostics).

    Returns:
        (present, diag): at least one root key child object found.
        (absent, diag):  container exists but contains no child objects, or
                         container itself is confirmed absent (noSuchObject).
        (unknown, diag): access denied, communication error, or other LDAP
                         failure — cannot confirm presence or absence.

    The search uses ``(objectClass=*)`` rather than ``(objectClass=msKds-ProvRootKey)``
    to avoid client-side class-name validation and maximize result coverage
    when the KDS class is accessible but the filter string is rejected.
    """
    base = f"{KDS_ROOT_KEYS_RDN},{config_nc}"
    diag: list[str] = [f"KDS search base: {base}"]

    try:
        ok = conn.search(
            search_base=base,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["cn"],
            size_limit=5,
        )
    except Exception as exc:
        diag.append(f"KDS search exception: {exc}")
        return CheckStatus.unknown, diag

    result = (getattr(conn, "result", None) or {})
    code = result.get("result", -1)
    desc = result.get("description", "")
    diag.append(f"KDS LDAP result: code={code} ({desc})")

    if not ok:
        if code == _LDAP_NO_SUCH_OBJECT:
            diag.append("KDS root key container does not exist")
            return CheckStatus.absent, diag
        if code == _LDAP_INSUFFICIENT_ACCESS:
            diag.append("KDS search: insufficient access rights — cannot confirm presence")
            return CheckStatus.unknown, diag
        diag.append("KDS search failed (non-zero result code)")
        return CheckStatus.unknown, diag

    # ok=True means the search completed. Filter out the container itself
    # (SUBTREE scope includes the base object); count only child entries.
    # Use entry.entry_dn (from the LDAP response header) rather than
    # entry.distinguishedName.value (which requires the attribute to be
    # explicitly requested and may be None when only 'cn' is requested).
    all_entries = list(conn.entries)
    children = [
        e for e in all_entries
        if getattr(e, "entry_dn", None) and e.entry_dn.lower() != base.lower()
    ]
    diag.append(f"KDS entries: total={len(all_entries)} children={len(children)}")
    for e in children[:3]:
        diag.append(f"  {e.entry_dn}")

    if children:
        return CheckStatus.present, diag
    return CheckStatus.absent, diag


def kds_root_key_status(conn: Connection, config_nc: str) -> CheckStatus:
    """Return KDS root key status. Wrapper around detect_kds_root_key()."""
    status, _ = detect_kds_root_key(conn, config_nc)
    return status


def has_kds_root_key(conn: Connection, config_nc: str) -> bool:
    return kds_root_key_status(conn, config_nc) == CheckStatus.present
