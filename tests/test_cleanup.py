from __future__ import annotations

import struct

from ldap3 import MODIFY_DELETE, MODIFY_REPLACE

from dmsa_reaper.ldap.dacl_editor import (
    ace_fingerprint,
    add_aces_to_sd,
    build_allow_createchild_ace,
)
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation
from dmsa_reaper.ops.cleanup import cleanup_operation
from dmsa_reaper.utils import bytes_to_guid_le


TARGET = "CN=target,DC=corp,DC=local"
DMSA = "CN=dmsarpr-123,OU=Reaper,DC=corp,DC=local"
GUID_RAW = bytes(range(16))
GUID = bytes_to_guid_le(GUID_RAW)


class _Attr:
    def __init__(self, values, raw_values=None):
        self.values = values
        self.raw_values = raw_values if raw_values is not None else values
        self.value = values[0] if values else None


class _Entry:
    def __init__(self, attrs):
        self.attrs = attrs

    def __contains__(self, key):
        return key in self.attrs

    def __getitem__(self, key):
        return self.attrs[key]


class _Conn:
    def __init__(self, objects):
        self.objects = objects
        self.entries = []
        self.result = {"result": 0, "description": "success"}

    def search(self, search_base, attributes, **_kwargs):
        attrs = self.objects.get(search_base)
        if attrs is None:
            self.entries = []
            self.result = {"result": 32, "description": "noSuchObject"}
            return False
        requested = attributes[0]
        if requested == "objectGUID":
            value = attrs.get("objectGUID")
            entry_attrs = {requested: _Attr([], [value])} if value is not None else {}
        elif requested == "nTSecurityDescriptor":
            value = attrs.get(requested)
            entry_attrs = {requested: _Attr([value], [value])} if value is not None else {}
        else:
            values = attrs.get(requested)
            entry_attrs = {requested: _Attr(list(values))} if values is not None else {}
        self.entries = [_Entry(entry_attrs)]
        self.result = {"result": 0, "description": "success"}
        return True

    def modify(self, dn, changes, controls=None):
        del controls
        attrs = self.objects[dn]
        for attribute, operations in changes.items():
            for operation, values in operations:
                if operation == MODIFY_DELETE:
                    attrs.pop(attribute, None)
                elif operation == MODIFY_REPLACE:
                    if attribute == "nTSecurityDescriptor":
                        attrs[attribute] = values[0]
                    else:
                        attrs[attribute] = list(values)
        self.result = {"result": 0, "description": "success"}
        return True

    def delete(self, dn):
        self.objects.pop(dn, None)
        self.result = {"result": 0, "description": "success"}
        return True


def _operation() -> Operation:
    return Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        status="executed",
        created_dns=[DMSA],
        changed_attrs=[
            AttributeChange(
                dn=TARGET,
                attribute="msDS-SupersededManagedAccountLink",
                before=["CN=old,DC=corp,DC=local"],
                after=[DMSA],
                mode="replace",
                step_status="written",
            )
        ],
        metadata={"created_objects": {DMSA: {"object_guid": GUID}}},
    )


def test_cleanup_restores_only_matching_write_and_guid_bound_object():
    operation = _operation()
    conn = _Conn({
        TARGET: {"msDS-SupersededManagedAccountLink": [DMSA]},
        DMSA: {"objectGUID": GUID_RAW},
    })

    result = cleanup_operation(operation, conn)

    assert result.status == "cleaned-up"
    assert result.cleanup_verified is True
    assert conn.objects[TARGET]["msDS-SupersededManagedAccountLink"] == [
        "CN=old,DC=corp,DC=local"
    ]
    assert DMSA not in conn.objects


def test_cleanup_reports_conflict_instead_of_overwriting_third_party_value():
    operation = _operation()
    conn = _Conn({
        TARGET: {"msDS-SupersededManagedAccountLink": ["CN=third-party,DC=corp,DC=local"]},
    })

    result = cleanup_operation(operation, conn)

    assert result.status == "cleanup-conflict"
    assert conn.objects[TARGET]["msDS-SupersededManagedAccountLink"] == [
        "CN=third-party,DC=corp,DC=local"
    ]
    assert result.metadata["cleanup"]["conflicts"]


def test_cleanup_refuses_to_delete_replaced_dn_with_wrong_guid():
    operation = _operation()
    wrong_guid = bytes(reversed(range(16)))
    conn = _Conn({
        TARGET: {"msDS-SupersededManagedAccountLink": [DMSA]},
        DMSA: {"objectGUID": wrong_guid},
    })

    result = cleanup_operation(operation, conn)

    assert result.status == "cleanup-conflict"
    assert DMSA in conn.objects
    assert any("objectGUID mismatch" in item["reason"] for item in result.metadata["cleanup"]["conflicts"])


def _empty_sd() -> bytes:
    owner = bytes([1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])
    dacl = struct.pack("<BBHHH", 4, 0, 8, 0, 0)
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(owner))
    return header + owner + dacl


def test_cleanup_removes_only_fingerprinted_ace_and_preserves_later_change():
    original = _empty_sd()
    ours = build_allow_createchild_ace("S-1-5-21-1-2-3-1000")
    third_party = build_allow_createchild_ace("S-1-5-21-1-2-3-1001")
    after_ours = add_aces_to_sd(original, [ours])
    current = add_aces_to_sd(after_ours, [third_party])
    operation = Operation(
        id="OP-0001",
        primitive="dacl-container-escalate",
        status="executed",
        changed_attrs=[
            AttributeChange(
                dn=TARGET,
                attribute="nTSecurityDescriptor",
                before=[AttributeValue.security_descriptor(original)],
                after=[AttributeValue.security_descriptor(after_ours)],
                mode="replace",
                step_name="dacl-mod",
                step_status="written",
            )
        ],
        metadata={
            "added_aces": [
                {"dn": TARGET, "sha256": ace_fingerprint(ours), "step_name": "dacl-mod"}
            ]
        },
    )
    conn = _Conn({TARGET: {"nTSecurityDescriptor": current}})

    result = cleanup_operation(operation, conn)

    assert result.cleanup_verified is True
    assert conn.objects[TARGET]["nTSecurityDescriptor"] == add_aces_to_sd(original, [third_party])


def test_cleanup_is_idempotent_after_verified_completion():
    operation = _operation()
    conn = _Conn({
        TARGET: {"msDS-SupersededManagedAccountLink": [DMSA]},
        DMSA: {"objectGUID": GUID_RAW},
    })

    first = cleanup_operation(operation, conn)
    second = cleanup_operation(first, conn)

    assert second.status == "cleaned-up"
    assert second.cleanup_verified is True
