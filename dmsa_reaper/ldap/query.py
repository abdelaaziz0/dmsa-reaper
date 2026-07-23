from __future__ import annotations

from typing import Any, Iterable

from ldap3 import LEVEL, SUBTREE, Connection

from dmsa_reaper.ldap.sd_control import sd_control


class LdapSearchError(RuntimeError):
    """Raised when LDAP returned an error instead of an authoritative result set."""


def ensure_search_succeeded(conn: Connection, ok: object, context: str) -> None:
    result = getattr(conn, "result", {}) or {}
    code = result.get("result") if isinstance(result, dict) else None
    description = result.get("description") if isinstance(result, dict) else None
    if ok is False or (isinstance(code, int) and code != 0):
        raise LdapSearchError(
            f"LDAP search failed ({context}): code={code!r} "
            f"description={description!r} result={result!r}"
        )


def search_entries(
    conn: Connection,
    base: str,
    ldap_filter: str,
    attributes: Iterable[str],
    *,
    controls=None,
    paged_size: int = 500,
    max_entries: int | None = None,
):
    attrs = list(attributes)
    entries: list[Any] = []
    cookie = None
    while True:
        request_size = paged_size
        if max_entries is not None:
            request_size = min(request_size, max(1, max_entries - len(entries)))
        ok = conn.search(
            search_base=base,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            controls=controls,
            paged_size=request_size,
            paged_cookie=cookie,
        )
        ensure_search_succeeded(conn, ok, f"base={base!r} filter={ldap_filter!r}")
        entries.extend(list(conn.entries))
        if max_entries is not None and len(entries) >= max_entries:
            return entries[:max_entries]
        controls_result = (getattr(conn, "result", {}) or {}).get("controls", {})
        paged = controls_result.get("1.2.840.113556.1.4.319", {})
        next_cookie = (paged.get("value") or {}).get("cookie")
        if next_cookie and next_cookie == cookie:
            raise LdapSearchError("LDAP paging returned the same non-empty cookie twice")
        cookie = next_cookie
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
    ok = conn.search(
        search_base=base,
        search_filter=ldap_filter,
        search_scope=LEVEL,
        attributes=list(attributes),
        controls=controls,
    )
    ensure_search_succeeded(conn, ok, f"one-level base={base!r} filter={ldap_filter!r}")
    return list(conn.entries)


def search_with_sd(
    conn: Connection,
    base: str,
    ldap_filter: str,
    attributes: Iterable[str],
    sdflags: int,
    *,
    max_entries: int | None = None,
):
    attrs = list(attributes)
    if "nTSecurityDescriptor" not in attrs:
        attrs.append("nTSecurityDescriptor")
    return search_entries(
        conn,
        base,
        ldap_filter,
        attrs,
        controls=sd_control(sdflags),
        max_entries=max_entries,
    )
