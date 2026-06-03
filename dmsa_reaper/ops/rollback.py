from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ldap3 import BASE, Connection
from ldap3.core.exceptions import LDAPException

from dmsa_reaper.ldap.modify import delete_object, modify_attribute
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _value_keys(values) -> list[tuple[str, str]]:
    return sorted(AttributeValue.from_python(value).comparison_key() for value in (values or []))


def _reverse_change(conn: Connection, change: AttributeChange) -> None:
    """Reverse a single attribute change."""
    if change.step_status == "planned":
        return
    if change.attribute == "nTSecurityDescriptor":
        if change.before is not None:
            from dmsa_reaper.ldap.dacl_editor import write_dacl_sd
            before_vals = change.before_python()
            if before_vals:
                write_dacl_sd(conn, change.dn, before_vals[0])
        return
    if change.before is None and change.after is not None:
        try:
            modify_attribute(conn, change.dn, change.attribute, [], mode="delete")
        except Exception as exc:
            if _is_no_such_attribute(exc):
                return
            raise
    elif change.before is not None:
        modify_attribute(conn, change.dn, change.attribute, change.before_python(), mode="replace")


def _is_no_such_attribute(exc: Exception) -> bool:
    text = str(exc).lower()
    return "nosuchattribute" in text or "no such attribute" in text


def _dn_exists(conn: Connection, dn: str) -> bool:
    try:
        conn.search(search_base=dn, search_filter="(objectClass=*)", search_scope=BASE, attributes=["dn"])
        return bool(conn.entries)
    except LDAPException:
        return False


def _attr_matches_value(conn: Connection, dn: str, attribute: str, expected: list | None) -> bool:
    """Return True if the attribute in LDAP currently matches expected (None means absent/empty)."""
    conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=[attribute],
    )
    if not conn.entries:
        return False
    entry = conn.entries[0]
    if attribute not in entry:
        return not expected
    actual = list(entry[attribute].values)
    return _value_keys(actual) == _value_keys(expected)


def _rollback_attr_detail(conn: Connection, change: AttributeChange) -> dict[str, Any]:
    if change.step_status == "planned":
        return {
            "dn": change.dn,
            "attribute": change.attribute,
            "status": "skipped",
            "reason": "planned change was never written",
        }
    expected = change.before
    try:
        matched = _attr_matches_value(conn, change.dn, change.attribute, expected)
    except Exception as exc:
        return {
            "dn": change.dn,
            "attribute": change.attribute,
            "status": "error",
            "reason": str(exc),
        }
    return {
        "dn": change.dn,
        "attribute": change.attribute,
        "status": "restored" if matched else "mismatch",
        "reason": (
            "attribute matches recorded before-values"
            if matched
            else "attribute does not match recorded before-values"
        ),
    }


def _rollback_object_detail(conn: Connection, dn: str) -> dict[str, str]:
    try:
        exists = _dn_exists(conn, dn)
    except Exception as exc:
        return {"dn": dn, "status": "error", "reason": str(exc)}
    return {
        "dn": dn,
        "status": "absent" if not exists else "present",
        "reason": "object is absent" if not exists else "object still exists",
    }


def _rollback_verification_details(conn: Connection, operation: Operation) -> dict[str, Any]:
    created_objects = [
        _rollback_object_detail(conn, dn)
        for dn in operation.created_dns + operation.maybe_created_dns
    ]
    attributes = [_rollback_attr_detail(conn, change) for change in operation.changed_attrs]
    failures: list[str] = []
    for detail in created_objects:
        if detail["status"] != "absent":
            failures.append(f"object {detail['status']}: {detail['dn']} ({detail['reason']})")
    for detail in attributes:
        if detail["status"] in {"skipped", "restored"}:
            continue
        failures.append(
            f"attribute {detail['status']}: {detail['dn']} {detail['attribute']} "
            f"({detail['reason']})"
        )
    return {
        "status": "failed" if failures else "verified",
        "ok": not failures,
        "created_objects": created_objects,
        "attributes": attributes,
        "failures": failures,
    }


def _verify_rollback_state(conn: Connection, operation: Operation) -> bool:
    """Confirm that LDAP reflects a successful rollback.

    - Objects listed in created_dns must no longer exist.
    - Attributes in changed_attrs must match their before values.
    """
    for dn in operation.created_dns + operation.maybe_created_dns:
        if _dn_exists(conn, dn):
            return False
    for change in operation.changed_attrs:
        if change.step_status == "planned":
            continue
        if not _attr_matches_value(conn, change.dn, change.attribute, change.before):
            return False
    return True


def _maybe_created_dn_can_be_deleted(operation: Operation, dn: str) -> bool:
    """Return True when a maybe-created DN is tied to this operation's generated object."""
    if dn == operation.metadata.get("created_dmsa_dn"):
        return True
    cn = dn.split(",", 1)[0].strip().lower()
    sam = str(operation.metadata.get("created_dmsa_sam") or "").rstrip("$").lower()
    return bool(cn.startswith("cn=dmsarpr-") or (sam and cn == f"cn={sam}"))


def rollback_operation(
    operation: Operation,
    conn: Connection | None = None,
) -> Operation:
    """Reverse an operation's LDAP changes in reverse order, then verify.

    When conn is None:
    - If there is nothing to undo (no created_dns, no changed_attrs), marks as
      'rolled-back' without requiring a connection.
    - Otherwise marks as 'rollback-requires-ldap' and returns without touching LDAP.
    """
    if not operation.rollback_available:
        if operation.rolled_back or operation.status == "rolled-back":
            return operation
        operation.status = "rollback-not-available"
        return operation

    if not operation.created_dns and not operation.maybe_created_dns and not operation.changed_attrs:
        operation.status = "rolled-back"
        operation.rollback_available = False
        operation.rolled_back = True
        operation.rollback_verified = True
        now = _utc_now_iso()
        operation.rolled_back_at = now
        operation.rollback_verified_at = now
        operation.verified = False
        operation.metadata["rollback_verification"] = {
            "status": "verified",
            "ok": True,
            "created_objects": [],
            "attributes": [],
            "failures": [],
        }
        return operation

    if conn is None:
        operation.status = "rollback-requires-ldap"
        operation.rollback_verified = False
        return operation

    errors: list[str] = []

    # Reverse attribute changes in reverse order.
    for change in reversed(operation.changed_attrs):
        try:
            _reverse_change(conn, change)
        except Exception as exc:
            errors.append(f"attr-reverse {change.dn} {change.attribute}: {exc}")

    # Delete objects created by this operation in reverse order.
    for dn in reversed(operation.created_dns):
        try:
            delete_object(conn, dn)
        except Exception as exc:
            errors.append(f"delete {dn}: {exc}")
            sam = operation.metadata.get("created_dmsa_sam")
            if sam:
                operation.recovery_notes.append(
                    f"Created object deletion failed for {dn}; look up and clean up sAMAccountName {sam}."
                )

    # maybe_created_dns records create attempts where the client saw an
    # exception. Check before deleting so an absent object is treated as clean.
    for dn in reversed(operation.maybe_created_dns):
        if not _maybe_created_dn_can_be_deleted(operation, dn):
            note = f"maybe-created DN not auto-deleted because it is not tied to this operation: {dn}"
            operation.recovery_notes.append(note)
            continue
        try:
            if _dn_exists(conn, dn):
                delete_object(conn, dn)
            else:
                operation.recovery_notes.append(f"maybe-created DN was absent during rollback: {dn}")
        except Exception as exc:
            errors.append(f"maybe-delete {dn}: {exc}")

    if errors:
        operation.status = "rollback-partial"
        operation.rollback_verified = False
        operation.errors.extend(errors)
        operation.metadata.setdefault("rollback_errors", []).extend(errors)
        return operation

    # Verify the directory state reflects the rollback before declaring success.
    rollback_verification = _rollback_verification_details(conn, operation)
    operation.metadata["rollback_verification"] = rollback_verification
    if rollback_verification["ok"]:
        operation.status = "rolled-back"
        operation.rollback_available = False
        operation.rolled_back = True
        operation.rollback_verified = True
        now = _utc_now_iso()
        operation.rolled_back_at = now
        operation.rollback_verified_at = now
        # The LDAP state no longer matches what was originally verified, so clear
        # the verified flag to prevent stale positive results from verify_operation_ldap.
        operation.verified = False
    else:
        operation.status = "rollback-verify-failed"
        operation.rollback_verified = False
        operation.recovery_notes.append(
            "Rollback verification failed; inspect metadata.rollback_verification and "
            "manually confirm created objects and restored attributes."
        )

    return operation
