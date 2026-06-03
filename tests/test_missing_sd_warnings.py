from dmsa_reaper.map.containers import enumerate_containers
from dmsa_reaper.map.dmsa_objects import enumerate_dmsas
from dmsa_reaper.map.targets import enumerate_targets
from dmsa_reaper.models import SchemaCache

_WARNING = "nTSecurityDescriptor missing or unreadable; effective-rights result is incomplete"


class _Attr:
    def __init__(self, value=None, values=None, raw_values=None):
        self.value = value
        self.values = values if values is not None else ([] if value is None else [value])
        self.raw_values = raw_values or []


class _Entry:
    def __init__(self, attrs):
        self._attrs = attrs

    def __contains__(self, key):
        return key in self._attrs

    def __getitem__(self, key):
        return self._attrs[key]

    def __getattr__(self, key):
        try:
            return self._attrs[key]
        except KeyError as exc:
            raise AttributeError(key) from exc


class _Conn:
    def __init__(self, entry):
        self.entries = []
        self.entry = entry
        self.result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b""}}}}

    def search(self, **kwargs):
        self.entries = [self.entry]
        return True


def test_enumerate_containers_warns_on_missing_sd():
    entry = _Entry({
        "distinguishedName": _Attr("OU=Apps,DC=corp,DC=local"),
        "objectClass": _Attr(values=["top", "organizationalUnit"]),
    })

    result = enumerate_containers(_Conn(entry), "DC=corp,DC=local", 0x5, schema_cache=SchemaCache())

    assert _WARNING in result[0].parse_warnings


def test_enumerate_targets_warns_on_missing_sd():
    entry = _Entry({
        "distinguishedName": _Attr("CN=svc,DC=corp,DC=local"),
        "sAMAccountName": _Attr("svc"),
        "objectSid": _Attr("S-1-5-21-X-1000"),
        "objectClass": _Attr(values=["top", "user"]),
    })

    result = enumerate_targets(_Conn(entry), "DC=corp,DC=local", 0x5, schema_cache=SchemaCache())

    assert _WARNING in result[0].parse_warnings


def test_enumerate_dmsas_warns_on_missing_sd():
    entry = _Entry({
        "distinguishedName": _Attr("CN=dmsa,DC=corp,DC=local"),
        "sAMAccountName": _Attr("dmsa$"),
        "objectSid": _Attr("S-1-5-21-X-2000"),
        "objectClass": _Attr(values=["top", "msDS-DelegatedManagedServiceAccount"]),
    })

    result = enumerate_dmsas(_Conn(entry), "DC=corp,DC=local", 0x5, schema_cache=SchemaCache())

    assert _WARNING in result[0].parse_warnings
