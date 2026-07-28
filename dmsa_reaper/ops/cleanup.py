from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ldap3 import BASE, Connection

from dmsa_reaper.ldap.dacl_editor import (
    _dacl_parts,
    ace_fingerprint,
    read_sd,
    remove_aces_by_fingerprint,
    write_dacl_sd,
)
from dmsa_reaper.ldap.modify import delete_object, modify_attribute
from dmsa_reaper.ldap.query import ensure_search_succeeded
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation
from dmsa_reaper.utils import bytes_to_guid_le


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _value_keys(values: list[Any] | None) -> list[tuple[str, str]]:
    return sorted(AttributeValue.from_python(value).comparison_key() for value in (values or []))


def _read_attribute(conn: Connection, dn: str, attribute: str) -> tuple[bool, list[Any]]:
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=[attribute],
    )
    ensure_search_succeeded(conn, ok, f"cleanup read {attribute!r} on {dn!r}")
    if not conn.entries:
        return False, []
    entry = conn.entries[0]
    if attribute not in entry:
        return True, []
    attr = entry[attribute]
    values = getattr(attr, "values", None) or []
    return True, list(values)


def _read_object_guid(conn: Connection, dn: str) -> tuple[bool, str | None]:
    ok = conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["objectGUID"],
    )
    result = getattr(conn, "result", {}) or {}
    code = result.get("result") if isinstance(result, dict) else None
    if ok is False and code == 32:
        return False, None
    ensure_search_succeeded(conn, ok, f"cleanup read objectGUID on {dn!r}")
    if not conn.entries:
        return False, None
    entry = conn.entries[0]
    if "objectGUID" not in entry:
        return True, None
    attr = entry["objectGUID"]
    raw_values = getattr(attr, "raw_values", None) or []
    if raw_values and isinstance(raw_values[0], (bytes, bytearray)):
        raw = bytes(raw_values[0])
        if len(raw) == 16:
            return True, bytes_to_guid_le(raw)
    value = getattr(attr, "value", None)
    if value:
        return True, str(value).lower()
    values = getattr(attr, "values", None) or []
    return True, str(values[0]).lower() if values else None


def _ace_fingerprint_counts(raw_sd: bytes, fingerprints: list[str]) -> dict[str, int]:
    wanted = set(fingerprints)
    counts = dict.fromkeys(wanted, 0)
    for ace in _dacl_parts(raw_sd)[-1]:
        fingerprint = ace_fingerprint(ace)
        if fingerprint in wanted:
            counts[fingerprint] += 1
    return counts


def _restore_attribute(conn: Connection, change: AttributeChange) -> dict[str, Any]:
    detail: dict[str, Any] = {"dn": change.dn, "attribute": change.attribute}
    exists, actual = _read_attribute(conn, change.dn, change.attribute)
    if not exists:
        return {**detail, "status": "conflict", "reason": "object is absent"}
    before = change.before_python() or []
    after = change.after_python() or []
    if _value_keys(actual) == _value_keys(before):
        change.step_status = "cleaned"
        return {**detail, "status": "already-clean", "reason": "recorded before-value is present"}
    if _value_keys(actual) != _value_keys(after):
        return {
            **detail,
            "status": "conflict",
            "reason": "current value differs from both the operation write and recorded before-value",
        }
    if change.before is None:
        modify_attribute(conn, change.dn, change.attribute, [], mode="delete")
    else:
        modify_attribute(conn, change.dn, change.attribute, before, mode="replace")
    _, verified = _read_attribute(conn, change.dn, change.attribute)
    if _value_keys(verified) != _value_keys(before):
        return {**detail, "status": "error", "reason": "restoration verification failed"}
    change.step_status = "cleaned"
    return {**detail, "status": "cleaned", "reason": "restored recorded before-value"}


def _cleanup_created_object(conn: Connection, operation: Operation, dn: str) -> dict[str, Any]:
    detail: dict[str, Any] = {"dn": dn}
    exists, actual_guid = _read_object_guid(conn, dn)
    if not exists:
        return {**detail, "status": "already-clean", "reason": "object is absent"}
    created = operation.metadata.get("created_objects")
    journal = created.get(dn) if isinstance(created, dict) else None
    expected_guid = journal.get("object_guid") if isinstance(journal, dict) else None
    if not expected_guid:
        return {
            **detail,
            "status": "conflict",
            "reason": "operation did not journal the created object's objectGUID",
        }
    if not actual_guid or actual_guid.lower() != str(expected_guid).lower():
        return {
            **detail,
            "status": "conflict",
            "reason": f"objectGUID mismatch (expected {expected_guid}, found {actual_guid})",
        }
    delete_object(conn, dn)
    still_exists, _ = _read_object_guid(conn, dn)
    if still_exists:
        return {**detail, "status": "error", "reason": "object still exists after delete"}
    return {**detail, "status": "cleaned", "reason": "deleted GUID-matched created object"}


def _cleanup_dacl(conn: Connection, operation: Operation, change: AttributeChange) -> dict[str, Any]:
    detail: dict[str, Any] = {"dn": change.dn, "attribute": change.attribute}
    records = operation.metadata.get("added_aces")
    matching = [
        item
        for item in records if isinstance(item, dict) and item.get("dn", "").lower() == change.dn.lower()
    ] if isinstance(records, list) else []
    fingerprints = [str(item["sha256"]) for item in matching if item.get("sha256")]
    current = read_sd(conn, change.dn)
    if not fingerprints:
        before = change.before_python() or []
        if len(before) == 1 and current == before[0]:
            change.step_status = "cleaned"
            return {
                **detail,
                "status": "already-clean",
                "reason": "recorded DACL is unchanged",
            }
        return {
            **detail,
            "status": "conflict",
            "reason": "no exact added-ACE fingerprints were journaled; whole-DACL restore refused",
        }
    counts = _ace_fingerprint_counts(current, fingerprints)
    ambiguous = sorted(fingerprint for fingerprint, count in counts.items() if count > 1)
    if ambiguous:
        return {
            **detail,
            "status": "conflict",
            "reason": "a journaled ACE fingerprint occurs more than once; DACL left unchanged",
            "ambiguous_fingerprints": ambiguous,
        }
    absent = sorted(fingerprint for fingerprint, count in counts.items() if count == 0)
    if len(absent) == len(counts):
        change.step_status = "cleaned"
        return {**detail, "status": "already-clean", "reason": "journaled ACEs are absent"}
    if absent:
        return {
            **detail,
            "status": "conflict",
            "reason": "only some journaled ACE fingerprints are present; DACL left unchanged",
            "missing_fingerprints": absent,
        }
    modified, missing = remove_aces_by_fingerprint(current, fingerprints)
    if missing:
        return {
            **detail,
            "status": "conflict",
            "reason": "journaled ACE fingerprints could not be removed exactly; DACL left unchanged",
            "missing_fingerprints": missing,
        }
    write_dacl_sd(conn, change.dn, modified)
    verified = read_sd(conn, change.dn)
    still_present = sorted(
        fingerprint
        for fingerprint, count in _ace_fingerprint_counts(verified, fingerprints).items()
        if count
    )
    if still_present:
        return {**detail, "status": "error", "reason": "ACE removal verification failed"}
    change.step_status = "cleaned"
    return {**detail, "status": "cleaned", "reason": "removed only journaled ACE fingerprints"}


def cleanup_operation(operation: Operation, conn: Connection | None = None) -> Operation:
    """Conflict-aware, idempotent cleanup suitable for retry/recovery."""
    if operation.cleaned_up and operation.cleanup_verified:
        return operation
    has_work = bool(operation.changed_attrs or operation.created_dns or operation.maybe_created_dns)
    if not has_work:
        now = _utc_now_iso()
        operation.status = "cleaned-up"
        operation.cleaned_up = True
        operation.cleanup_verified = True
        operation.cleanup_available = False
        operation.cleaned_up_at = now
        operation.cleanup_verified_at = now
        operation.metadata["cleanup"] = {
            "status": "verified",
            "ok": True,
            "attributes": [],
            "created_objects": [],
            "conflicts": [],
            "errors": [],
        }
        return operation
    if conn is None:
        operation.status = "cleanup-requires-ldap"
        return operation

    attribute_details: list[dict[str, Any]] = []
    object_details: list[dict[str, Any]] = []

    normal_changes = [c for c in operation.changed_attrs if c.attribute != "nTSecurityDescriptor"]
    dacl_changes = [c for c in operation.changed_attrs if c.attribute == "nTSecurityDescriptor"]
    for change in reversed(normal_changes):
        try:
            attribute_details.append(_restore_attribute(conn, change))
        except Exception as exc:
            attribute_details.append({
                "dn": change.dn,
                "attribute": change.attribute,
                "status": "error",
                "reason": str(exc),
            })

    for dn in reversed(list(dict.fromkeys(operation.created_dns + operation.maybe_created_dns))):
        try:
            object_details.append(_cleanup_created_object(conn, operation, dn))
        except Exception as exc:
            object_details.append({"dn": dn, "status": "error", "reason": str(exc)})

    for change in reversed(dacl_changes):
        try:
            attribute_details.append(_cleanup_dacl(conn, operation, change))
        except Exception as exc:
            attribute_details.append({
                "dn": change.dn,
                "attribute": change.attribute,
                "status": "error",
                "reason": str(exc),
            })

    all_details = attribute_details + object_details
    conflicts = [d for d in all_details if d["status"] == "conflict"]
    errors = [d for d in all_details if d["status"] == "error"]
    ok = not conflicts and not errors
    operation.metadata["cleanup"] = {
        "status": "verified" if ok else "conflict" if conflicts and not errors else "partial",
        "ok": ok,
        "attributes": attribute_details,
        "created_objects": object_details,
        "conflicts": conflicts,
        "errors": errors,
    }
    if ok:
        now = _utc_now_iso()
        operation.status = "cleaned-up"
        operation.cleaned_up = True
        operation.cleanup_verified = True
        operation.cleanup_available = False
        operation.cleaned_up_at = now
        operation.cleanup_verified_at = now
    else:
        operation.status = "cleanup-conflict" if conflicts and not errors else "cleanup-partial"
        operation.cleanup_verified = False
        operation.cleanup_available = True
    return operation
