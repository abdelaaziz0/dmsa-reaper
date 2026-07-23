from __future__ import annotations

import struct

import pytest
import typer

from dmsa_reaper.acl.enrichment import compute_effective_rights
from dmsa_reaper.acl.parser import _parse_ace, parse_security_descriptor
from dmsa_reaper.ldap.dacl_editor import add_aces_to_sd
from dmsa_reaper.ldap.query import LdapSearchError, search_entries
from dmsa_reaper.models import ContainerObject, Environment, MapState, Right, SchemaCache
from dmsa_reaper.models import Principal
from dmsa_reaper.paths.classifier import classify_paths


def _ace(ace_type: int, *, inherited: bool = False, marker: int = 0) -> bytes:
    flags = 0x10 if inherited else 0
    return struct.pack("<BBHI", ace_type, flags, 8, marker)


def _sd(aces: list[bytes]) -> bytes:
    owner = bytes([1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])
    ace_data = b"".join(aces)
    dacl = struct.pack("<BBHHH", 4, 0, 8 + len(ace_data), len(aces), 0) + ace_data
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(owner))
    return header + owner + dacl


def _ace_types_and_markers(raw_sd: bytes) -> list[tuple[int, int, int]]:
    offset = struct.unpack_from("<I", raw_sd, 16)[0]
    count = struct.unpack_from("<H", raw_sd, offset + 4)[0]
    cursor = offset + 8
    result = []
    for _ in range(count):
        ace_type, flags, size = struct.unpack_from("<BBH", raw_sd, cursor)
        marker = struct.unpack_from("<I", raw_sd, cursor + 4)[0]
        result.append((ace_type, flags, marker))
        cursor += size
    return result


def test_new_allow_is_inserted_after_explicit_allows_before_inherited_aces():
    existing = [
        _ace(0x01, marker=1),
        _ace(0x00, marker=2),
        _ace(0x01, inherited=True, marker=3),
    ]

    modified = add_aces_to_sd(_sd(existing), [_ace(0x00, marker=4)])

    assert _ace_types_and_markers(modified) == [
        (0x01, 0, 1),
        (0x00, 0, 2),
        (0x00, 0, 4),
        (0x01, 0x10, 3),
    ]


def test_noncanonical_existing_dacl_is_refused():
    raw = _sd([_ace(0x00, marker=1), _ace(0x01, marker=2)])

    with pytest.raises(ValueError, match="noncanonical"):
        add_aces_to_sd(raw, [_ace(0x00, marker=3)])


class _CallbackAce:
    def __getitem__(self, key):
        if key == "AceType":
            return 0x09
        raise KeyError(key)


def test_callback_ace_marks_access_unknown():
    parsed, warning = _parse_ace(_CallbackAce())

    assert parsed is None
    assert "effective access is unknown" in warning


def test_null_and_empty_dacl_are_distinct_for_enrichment():
    empty_rights, _ = compute_effective_rights(
        [], "S-1-5-21-1", {"S-1-5-21-1"}, "CN=x", None
    )
    null_rights, _ = compute_effective_rights(
        [], "S-1-5-21-1", {"S-1-5-21-1"}, "CN=x", None, null_dacl=True
    )

    assert empty_rights == []
    assert "GenericAll" in {right.right for right in null_rights}


def test_null_dacl_parses_without_becoming_a_parse_failure():
    raw_sd = struct.pack("<BBHIIII", 1, 0, 0x8000, 0, 0, 0, 0)

    parsed = parse_security_descriptor(raw_sd)

    assert parsed.null_dacl is True
    assert parsed.parse_failed is False


class _FailedSearch:
    entries = []
    result = {"result": 50, "description": "insufficientAccessRights"}

    def search(self, **_kwargs):
        return False


def test_ldap_access_error_never_becomes_empty_results():
    with pytest.raises(LdapSearchError, match="insufficientAccessRights"):
        search_entries(_FailedSearch(), "DC=corp,DC=local", "(objectClass=*)", ["dn"])


class _PagedSearch:
    def __init__(self):
        self.entries = [object(), object()]
        self.result = {"result": 0, "description": "success", "controls": {}}
        self.requested_sizes = []

    def search(self, **kwargs):
        self.requested_sizes.append(kwargs["paged_size"])
        return True


def test_server_page_is_bounded_by_max_entries():
    conn = _PagedSearch()

    results = search_entries(
        conn,
        "DC=corp,DC=local",
        "(objectClass=*)",
        ["dn"],
        max_entries=2,
    )

    assert len(results) == 2
    assert conn.requested_sizes == [2]


def test_write_owner_alone_never_enables_direct_dacl_primitive():
    dn = "OU=Apps,DC=corp,DC=local"
    state = MapState(
        environment=Environment(dmsa_capable=True),
        schema_cache=SchemaCache(),
        containers=[
            ContainerObject(
                dn=dn,
                rights=[Right(principal_sid="S-1-5-21-1", right="WriteOwner", object_dn=dn)],
            )
        ],
    )

    assert not any(path.primitive == "dacl-container-escalate" for path in classify_paths(state))


def test_path_id_is_stable_across_enumeration_order():
    sid = "S-1-5-21-1"
    first = ContainerObject(
        dn="OU=A,DC=corp,DC=local",
        object_guid="00000000-0000-0000-0000-000000000001",
        rights=[Right(principal_sid=sid, right="CreateChild", object_dn="OU=A,DC=corp,DC=local")],
    )
    second = ContainerObject(
        dn="OU=B,DC=corp,DC=local",
        object_guid="00000000-0000-0000-0000-000000000002",
        rights=[Right(principal_sid=sid, right="CreateChild", object_dn="OU=B,DC=corp,DC=local")],
    )
    common = {"environment": Environment(dmsa_capable=True), "schema_cache": SchemaCache()}

    forward = classify_paths(MapState(**common, containers=[first, second]))
    reverse = classify_paths(MapState(**common, containers=[second, first]))

    assert {path.id for path in forward} == {path.id for path in reverse}
    assert all(path.id.startswith("BS-") for path in forward)


def test_wrong_execution_sid_is_rejected_before_operation(monkeypatch):
    from dmsa_reaper import cli

    state = MapState(
        environment=Environment(domain="corp.local", default_nc="DC=corp,DC=local"),
        schema_cache=SchemaCache(),
        current_principal=Principal(name="mapped", sid="S-1-5-21-1000"),
    )
    monkeypatch.setattr(
        cli,
        "get_current_principal",
        lambda *_args, **_kwargs: Principal(name="other", sid="S-1-5-21-2000"),
    )

    with pytest.raises(typer.BadParameter, match="does not match mapped SID"):
        cli._validate_execution_binding(
            conn=object(),
            state=state,
            username="other",
            kerberos=False,
            dc_host=None,
            dc_ip=None,
        )
