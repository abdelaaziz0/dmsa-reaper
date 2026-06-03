from __future__ import annotations

from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars

from dmsa_reaper.acl.group_expansion import expand_nested_groups
from dmsa_reaper.models import Principal
from dmsa_reaper.ldap.sid import entry_sid

_PRINCIPAL_OBJECT_FILTER = (
    "(|"
    "(objectClass=user)"
    "(objectClass=computer)"
    "(objectClass=msDS-GroupManagedServiceAccount)"
    "(objectClass=msDS-DelegatedManagedServiceAccount)"
    ")"
)


def _derive_primary_group_sid(object_sid: str, primary_group_id: int) -> str:
    """Derive primary group SID by replacing the RID in objectSid with primaryGroupID."""
    prefix, _ = object_sid.rsplit("-", 1)
    return f"{prefix}-{primary_group_id}"


def get_current_principal(
    conn: Connection,
    default_nc: str,
    username: str | None = None,
) -> Principal | None:
    """Resolve the current principal's SID and nested group memberships.

    Looks up the principal by sAMAccountName derived from the supplied username string
    (strips domain prefix / UPN suffix).  Returns None when username is absent
    or the lookup finds no matching account (anonymous bind, ccache, etc.).

    Also derives the primary group SID from primaryGroupID — this group is not
    returned by LDAP_MATCHING_RULE_IN_CHAIN because membership is stored as an
    integer attribute, not in the group's member list.
    """
    if not username:
        return None

    # Accept DOMAIN\user, user@domain, or bare user.
    sam = username.split("\\")[-1].split("@")[0]
    escaped_sam = escape_filter_chars(sam)

    conn.search(
        search_base=default_nc,
        search_filter=f"(&{_PRINCIPAL_OBJECT_FILTER}(sAMAccountName={escaped_sam}))",
        attributes=["distinguishedName", "objectSid", "sAMAccountName", "primaryGroupID"],
    )
    if not conn.entries:
        return None

    entry = conn.entries[0]
    dn: str = str(entry.distinguishedName.value)
    sid = ""
    if "objectSid" in entry:
        sid = entry_sid(entry.objectSid) or ""
    name: str = (
        str(entry.sAMAccountName.value)
        if "sAMAccountName" in entry and entry.sAMAccountName.value
        else sam
    )

    group_sids = expand_nested_groups(conn, dn, default_nc)

    # primaryGroupID is not returned by LDAP_MATCHING_RULE_IN_CHAIN — add it explicitly.
    if sid and "primaryGroupID" in entry and entry.primaryGroupID.value is not None:
        try:
            pg_sid = _derive_primary_group_sid(sid, int(entry.primaryGroupID.value))
            if pg_sid not in group_sids:
                group_sids.append(pg_sid)
        except (ValueError, TypeError):
            pass

    return Principal(name=name, sid=sid, groups=group_sids)


def principal_sid_set(principal: Principal | None) -> set[str]:
    """Return the full SID set for a principal (direct + all groups)."""
    if principal is None:
        return set()
    return {principal.sid} | set(principal.groups)
