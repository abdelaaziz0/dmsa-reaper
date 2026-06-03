from __future__ import annotations

from typing import Iterable

from ldap3 import LEVEL, SUBTREE, Connection

from dmsa_reaper.ldap.sd_control import sd_control


def search_entries(
    conn: Connection,
    base: str,
    ldap_filter: str,
    attributes: Iterable[str],
    *,
    controls=None,
    paged_size: int = 500,
):
    attrs = list(attributes)
    entries = []
    cookie = None
    while True:
        conn.search(
            search_base=base,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            controls=controls,
            paged_size=paged_size,
            paged_cookie=cookie,
        )
        entries.extend(list(conn.entries))
        controls_result = (getattr(conn, "result", {}) or {}).get("controls", {})
        paged = controls_result.get("1.2.840.113556.1.4.319", {})
        cookie = (paged.get("value") or {}).get("cookie")
        if not cookie:
            break
    return entries


def search_one_level(
    conn: Connection,
    base: str,
    ldap_filter: str,
    attributes: Iterable[str],
    *,
    controls=None,
):
    conn.search(
        search_base=base,
        search_filter=ldap_filter,
        search_scope=LEVEL,
        attributes=list(attributes),
        controls=controls,
    )
    return list(conn.entries)


def search_with_sd(conn: Connection, base: str, ldap_filter: str, attributes: Iterable[str], sdflags: int):
    attrs = list(attributes)
    if "nTSecurityDescriptor" not in attrs:
        attrs.append("nTSecurityDescriptor")
    return search_entries(conn, base, ldap_filter, attrs, controls=sd_control(sdflags))
