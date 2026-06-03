from __future__ import annotations

from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars

from dmsa_reaper.ldap.sid import entry_sid


def expand_nested_groups(
    conn: Connection,
    principal_dn: str,
    default_nc: str = "",
) -> list[str]:
    """Return SIDs of all groups the principal belongs to (including nested).

    Uses the LDAP_MATCHING_RULE_IN_CHAIN OID (1.2.840.113556.1.4.1941) which
    traverses the full transitive member chain in a single server-side query.

    Args:
        conn: Bound LDAP connection.
        principal_dn: Distinguished name of the user/computer account.
        default_nc: Domain defaultNamingContext — used as the search base so that
            groups anywhere in the domain tree are found, not just under the
            principal's immediate parent container.

    Limitations:
        - primaryGroupID — the user's primary group (usually Domain Users) is NOT
          returned by LDAP_MATCHING_RULE_IN_CHAIN.  The caller (get_current_principal)
          reads primaryGroupID separately and appends the derived SID.
    """
    escaped_dn = escape_filter_chars(principal_dn)
    conn.search(
        search_base=default_nc,
        search_filter=f"(member:1.2.840.113556.1.4.1941:={escaped_dn})",
        attributes=["objectSid"],
    )
    sids: list[str] = []
    for entry in conn.entries:
        if "objectSid" in entry:
            sid = entry_sid(entry.objectSid)
            if sid:
                sids.append(sid)
    return sids
