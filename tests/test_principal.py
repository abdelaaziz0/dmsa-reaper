from __future__ import annotations

from ldap3.utils.conv import escape_filter_chars

from dmsa_reaper.map import principal as principal_mod


DEFAULT_NC = "DC=corp,DC=local"
USER_SID = "S-1-5-21-X-1000"
GROUP_SID = "S-1-5-21-X-513"


class _Attr:
    def __init__(self, value):
        self.value = value


class _Entry:
    distinguishedName = _Attr("CN=svc,CN=Users,DC=corp,DC=local")
    objectSid = _Attr(USER_SID)
    sAMAccountName = _Attr("svc")

    def __contains__(self, key):
        return key in {"distinguishedName", "objectSid", "sAMAccountName"}


class _Conn:
    def __init__(self, entries=None):
        self.entries = entries or []
        self.search_kwargs = None

    def search(self, **kwargs):
        self.search_kwargs = kwargs
        return True


def test_current_principal_filter_escapes_sam_and_includes_account_classes():
    conn = _Conn()
    username = r"CORP\svc*)(admin"

    principal_mod.get_current_principal(conn, DEFAULT_NC, username=username)

    ldap_filter = conn.search_kwargs["search_filter"]
    assert escape_filter_chars("svc*)(admin") in ldap_filter
    assert "(objectClass=user)" in ldap_filter
    assert "(objectClass=computer)" in ldap_filter
    assert "(objectClass=msDS-GroupManagedServiceAccount)" in ldap_filter
    assert "(objectClass=msDS-DelegatedManagedServiceAccount)" in ldap_filter


def test_current_principal_normal_user_path_still_returns_principal(monkeypatch):
    conn = _Conn(entries=[_Entry()])
    monkeypatch.setattr(
        principal_mod,
        "expand_nested_groups",
        lambda conn, dn, default_nc: [GROUP_SID],
    )

    principal = principal_mod.get_current_principal(conn, DEFAULT_NC, username=r"CORP\svc")

    assert principal is not None
    assert principal.name == "svc"
    assert principal.sid == USER_SID
    assert principal.groups == [GROUP_SID]
