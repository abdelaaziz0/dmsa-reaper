from dmsa_reaper.ldap.query import search_entries


class _PagedConn:
    def __init__(self):
        self.calls = []
        self.entries = []
        self.result = {}
        self._pages = [
            (["one", "two"], b"next"),
            (["three"], b""),
        ]

    def search(self, **kwargs):
        self.calls.append(kwargs)
        entries, cookie = self._pages.pop(0)
        self.entries = entries
        self.result = {
            "controls": {
                "1.2.840.113556.1.4.319": {
                    "value": {"cookie": cookie},
                }
            }
        }
        return True


def test_search_entries_consumes_multiple_ldap_pages():
    conn = _PagedConn()

    entries = search_entries(conn, "DC=corp,DC=local", "(objectClass=*)", ["cn"], paged_size=2)

    assert entries == ["one", "two", "three"]
    assert len(conn.calls) == 2
    assert conn.calls[0]["paged_cookie"] is None
    assert conn.calls[1]["paged_cookie"] == b"next"
