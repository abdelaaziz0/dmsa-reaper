"""Tests for acl/group_expansion.py — search base correctness and filter escaping."""

from unittest.mock import MagicMock

from dmsa_reaper.acl.group_expansion import expand_nested_groups


PRINCIPAL_DN = "CN=operator,CN=Users,DC=corp,DC=local"
DEFAULT_NC = "DC=corp,DC=local"
GROUP_SID = "S-1-5-21-X-1234"


def _mock_conn(sids: list[str]) -> MagicMock:
    """Build a fake ldap3 Connection that returns entries with the given SIDs."""
    conn = MagicMock()
    entries = []
    for sid in sids:
        entry = MagicMock()
        entry.__contains__ = lambda self, key: key == "objectSid"
        entry.objectSid.value = sid
        entries.append(entry)
    conn.entries = entries
    return conn


def test_search_uses_default_nc_not_parent_container():
    """Search base must be defaultNamingContext, not the user's immediate parent DN."""
    conn = _mock_conn([])
    expand_nested_groups(conn, PRINCIPAL_DN, default_nc=DEFAULT_NC)
    _, kwargs = conn.search.call_args
    assert kwargs["search_base"] == DEFAULT_NC


def test_search_base_empty_string_when_no_default_nc():
    conn = _mock_conn([])
    expand_nested_groups(conn, PRINCIPAL_DN)
    _, kwargs = conn.search.call_args
    assert kwargs["search_base"] == ""


def test_filter_contains_dn():
    conn = _mock_conn([])
    expand_nested_groups(conn, PRINCIPAL_DN, default_nc=DEFAULT_NC)
    _, kwargs = conn.search.call_args
    assert PRINCIPAL_DN in kwargs["search_filter"]


def test_filter_escapes_special_chars():
    """DN with special LDAP filter chars must be escaped in the query."""
    from ldap3.utils.conv import escape_filter_chars
    special_dn = "CN=op(er)ator*,CN=Users,DC=corp,DC=local"
    conn = _mock_conn([])
    expand_nested_groups(conn, special_dn, default_nc=DEFAULT_NC)
    _, kwargs = conn.search.call_args
    assert escape_filter_chars(special_dn) in kwargs["search_filter"]
    assert "(" not in kwargs["search_filter"].split("=", 2)[-1].split(")")[0]


def test_uses_matching_rule_in_chain():
    """Filter must include the OID for transitive group membership."""
    conn = _mock_conn([])
    expand_nested_groups(conn, PRINCIPAL_DN, default_nc=DEFAULT_NC)
    _, kwargs = conn.search.call_args
    assert "1.2.840.113556.1.4.1941" in kwargs["search_filter"]


def test_returns_sids_from_entries():
    conn = _mock_conn([GROUP_SID, "S-1-5-21-X-5678"])
    sids = expand_nested_groups(conn, PRINCIPAL_DN, default_nc=DEFAULT_NC)
    assert GROUP_SID in sids
    assert "S-1-5-21-X-5678" in sids


def test_empty_result_when_no_groups():
    conn = _mock_conn([])
    sids = expand_nested_groups(conn, PRINCIPAL_DN, default_nc=DEFAULT_NC)
    assert sids == []


# ── primaryGroupID derivation ─────────────────────────────────────────────────

def test_derive_primary_group_sid():
    from dmsa_reaper.map.principal import _derive_primary_group_sid
    sid = "S-1-5-21-111-222-333-1000"
    assert _derive_primary_group_sid(sid, 513) == "S-1-5-21-111-222-333-513"


def test_derive_primary_group_sid_domain_computers():
    from dmsa_reaper.map.principal import _derive_primary_group_sid
    sid = "S-1-5-21-111-222-333-1001"
    assert _derive_primary_group_sid(sid, 515) == "S-1-5-21-111-222-333-515"


def test_get_current_principal_includes_primary_group(monkeypatch):
    """primaryGroupID-derived SID must appear in principal.groups."""
    from unittest.mock import MagicMock
    from dmsa_reaper.map.principal import get_current_principal

    conn = MagicMock()

    # Set up the principal lookup entry.
    principal_entry = MagicMock()
    principal_entry.distinguishedName.value = "CN=op,CN=Users,DC=corp,DC=local"
    principal_entry.objectSid.value = "S-1-5-21-111-222-333-1000"
    principal_entry.sAMAccountName.value = "op"
    principal_entry.primaryGroupID.value = 513
    principal_entry.__contains__ = lambda self, k: k in (
        "objectSid", "sAMAccountName", "primaryGroupID"
    )
    conn.entries = [principal_entry]

    # expand_nested_groups returns no transitive groups (empty) so we can
    # verify that the primary group SID is added by get_current_principal alone.
    monkeypatch.setattr(
        "dmsa_reaper.map.principal.expand_nested_groups",
        lambda *a, **kw: [],
    )

    principal = get_current_principal(conn, "DC=corp,DC=local", username="op")
    assert principal is not None
    assert "S-1-5-21-111-222-333-513" in principal.groups


def test_principal_sid_set_includes_primary_group(monkeypatch):
    """principal_sid_set must include the primaryGroupID-derived SID."""
    from unittest.mock import MagicMock
    from dmsa_reaper.map.principal import get_current_principal, principal_sid_set

    conn = MagicMock()
    entry = MagicMock()
    entry.distinguishedName.value = "CN=op,CN=Users,DC=corp,DC=local"
    entry.objectSid.value = "S-1-5-21-111-222-333-1000"
    entry.sAMAccountName.value = "op"
    entry.primaryGroupID.value = 513
    entry.__contains__ = lambda self, k: k in ("objectSid", "sAMAccountName", "primaryGroupID")
    conn.entries = [entry]

    monkeypatch.setattr(
        "dmsa_reaper.map.principal.expand_nested_groups",
        lambda *a, **kw: [],
    )

    p = get_current_principal(conn, "DC=corp,DC=local", username="op")
    sid_set = principal_sid_set(p)
    assert "S-1-5-21-111-222-333-513" in sid_set


def test_primary_group_not_duplicated_if_already_in_groups(monkeypatch):
    """If expand_nested_groups already returned the primary-group SID, don't add it twice."""
    from unittest.mock import MagicMock
    from dmsa_reaper.map.principal import get_current_principal

    conn = MagicMock()
    entry = MagicMock()
    entry.distinguishedName.value = "CN=op,CN=Users,DC=corp,DC=local"
    entry.objectSid.value = "S-1-5-21-111-222-333-1000"
    entry.sAMAccountName.value = "op"
    entry.primaryGroupID.value = 513
    entry.__contains__ = lambda self, k: k in ("objectSid", "sAMAccountName", "primaryGroupID")
    conn.entries = [entry]

    monkeypatch.setattr(
        "dmsa_reaper.map.principal.expand_nested_groups",
        lambda *a, **kw: ["S-1-5-21-111-222-333-513"],
    )

    p = get_current_principal(conn, "DC=corp,DC=local", username="op")
    assert p.groups.count("S-1-5-21-111-222-333-513") == 1
