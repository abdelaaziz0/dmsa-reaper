from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Any

from ldap3 import BASE, Connection
from ldap3.core.exceptions import LDAPException

from dmsa_reaper.models import AttributeChange, AttributeValue, Operation

_TARGET_SIDE_ATTRS = frozenset({
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
})
_DMSA_SIDE_ATTRS = frozenset({
    "msDS-ManagedAccountPrecededByLink",
    "msDS-DelegatedMSAState",
})
_INT_RE = re.compile(r"^[+-]?\d+$")


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def record_ldap_verification(operation: Operation, details: dict[str, Any]) -> None:
    """Persist LDAP verification details with explicit historical/current semantics."""
    operation.metadata["ldap_verification"] = details
    operation.ldap_verified_at = _utc_now_iso()
    if details.get("status") == "verified":
        operation.verified = True
        operation.verified_ldap = True
    else:
        operation.verified = False


def _resolve_meta(operation: Operation, key: str) -> str | None:
    value = operation.metadata.get(key)
    if value is not None:
        return str(value)
    path = operation.metadata.get("path")
    if isinstance(path, dict):
        value = path.get(key)
        if value is not None:
            return str(value)
    return None


def _strip_wrappers(value: str) -> str:
    stripped = value.strip()
    while len(stripped) >= 2 and (
        (stripped[0], stripped[-1]) in {("<", ">"), ('"', '"'), ("'", "'")}
    ):
        stripped = stripped[1:-1].strip()
    return stripped


def _looks_like_dn(value: str) -> bool:
    lower = value.lower()
    return "=" in value and "," in value and any(
        token in lower for token in ("cn=", "ou=", "dc=", "o=", "uid=")
    )


def _normalize_dn(value: str) -> str:
    stripped = _strip_wrappers(value)
    stripped = re.sub(r"\s*=\s*", "=", stripped)
    stripped = re.sub(r"\s*,\s*", ",", stripped)
    return stripped.lower()


def _canonical_value(value: Any) -> tuple[str, str]:
    if isinstance(value, AttributeValue):
        value = value.to_python()
    if value is None:
        return ("none", "")
    if isinstance(value, bool):
        return ("bool", "true" if value else "false")
    if isinstance(value, int):
        return ("int", str(value))
    if isinstance(value, float):
        return ("float", repr(value))
    if isinstance(value, bytes | bytearray):
        raw = bytes(value)
        try:
            decoded = raw.decode("utf-8").strip("\x00")
        except UnicodeDecodeError:
            return ("bytes", base64.b64encode(raw).decode("ascii"))
        if decoded and all(ch.isprintable() for ch in decoded):
            return _canonical_value(decoded)
        return ("bytes", base64.b64encode(raw).decode("ascii"))

    text = _strip_wrappers(str(value))
    if _INT_RE.fullmatch(text):
        return ("int", str(int(text)))
    if _looks_like_dn(text):
        return ("dn", _normalize_dn(text))
    return ("str", text)


def _value_keys(values: list[Any] | None) -> list[tuple[str, str]]:
    return sorted(_canonical_value(value) for value in (values or []))


def _result_description(conn: Connection) -> str:
    result = getattr(conn, "result", None) or {}
    if isinstance(result, dict):
        return str(result.get("description") or result.get("message") or "")
    return ""


def _is_unreadable_result(description: str) -> bool:
    lowered = description.lower()
    return any(
        token in lowered
        for token in (
            "insufficientaccessrights",
            "insufficient access",
            "unwillingtoperform",
            "confidential",
        )
    )


def _read_attr(conn: Connection, dn: str, attribute: str) -> tuple[str, list[Any] | None, str]:
    try:
        ok = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[attribute],
        )
    except LDAPException as exc:
        return "unreadable", None, str(exc)
    description = _result_description(conn)
    if ok is False and _is_unreadable_result(description):
        return "unreadable", None, description
    if not getattr(conn, "entries", []):
        if _is_unreadable_result(description):
            return "unreadable", None, description
        return "object-missing", None, description or "object was not returned"
    entry = conn.entries[0]
    if attribute not in entry:
        return "absent", [], "attribute absent"
    return "present", list(entry[attribute].values), "attribute present"


def _verify_attr(conn: Connection, change: AttributeChange) -> dict[str, Any]:
    status, actual, reason = _read_attr(conn, change.dn, change.attribute)
    expected = change.after_python() or []
    detail: dict[str, Any] = {
        "dn": change.dn,
        "attribute": change.attribute,
        "expected": [_canonical_value(value) for value in expected],
        "actual": [_canonical_value(value) for value in (actual or [])],
        "status": status,
        "read_status": status,
        "reason": reason,
    }
    if status == "present" or status == "absent":
        if _value_keys(actual) == _value_keys(expected):
            detail["status"] = "matched"
            detail["reason"] = "actual values match expected after-values"
        else:
            detail["status"] = "mismatch"
            detail["reason"] = "actual values do not match expected after-values"
    return detail


def _dn_exists(conn: Connection, dn: str) -> bool:
    try:
        conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["objectClass"],
        )
        return bool(conn.entries)
    except LDAPException:
        return False


def _created_object_detail(conn: Connection, dn: str) -> dict[str, str]:
    try:
        ok = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["objectClass"],
        )
    except LDAPException as exc:
        return {"dn": dn, "status": "unreadable", "reason": str(exc)}
    description = _result_description(conn)
    if bool(getattr(conn, "entries", [])):
        return {"dn": dn, "status": "present", "reason": "object exists"}
    if ok is False and _is_unreadable_result(description):
        return {"dn": dn, "status": "unreadable", "reason": description}
    return {"dn": dn, "status": "absent", "reason": description or "object was not returned"}


def _written_changes(operation: Operation) -> list[AttributeChange]:
    return [
        change for change in operation.changed_attrs
        if change.step_status != "planned"
    ]


def _is_target_side(change: AttributeChange) -> bool:
    return change.attribute in _TARGET_SIDE_ATTRS


def _is_dmsa_side(change: AttributeChange, operation: Operation) -> bool:
    dmsa_dn = _resolve_meta(operation, "dmsa_dn") or operation.metadata.get("created_dmsa_dn")
    return (
        change.attribute in _DMSA_SIDE_ATTRS
        or change.dn in operation.created_dns
        or (dmsa_dn is not None and change.dn.lower() == str(dmsa_dn).lower())
    )


def _created_dmsa_attr_checks(operation: Operation) -> list[AttributeChange]:
    dmsa_dn = operation.metadata.get("created_dmsa_dn")
    target_dn = _resolve_meta(operation, "target_dn")
    if not dmsa_dn or dmsa_dn not in operation.created_dns:
        return []
    checks: list[AttributeChange] = []
    if target_dn:
        checks.append(
            AttributeChange(
                dn=str(dmsa_dn),
                attribute="msDS-ManagedAccountPrecededByLink",
                after=[AttributeValue.from_python(target_dn)],
                mode="replace",
                step_name="created-dmsa-preceded-by",
                step_status="written",
            )
        )
    checks.append(
        AttributeChange(
            dn=str(dmsa_dn),
            attribute="msDS-DelegatedMSAState",
            after=[AttributeValue.from_python(2)],
            mode="replace",
            step_name="created-dmsa-state",
            step_status="written",
        )
    )
    return checks


def verify_operation_ldap_details(
    operation: Operation,
    conn: Connection | None = None,
) -> dict[str, Any]:
    if conn is None:
        return {
            "status": "verified" if operation.verified else "unknown",
            "ok": operation.verified,
            "reason": "no live LDAP connection supplied",
            "created_objects": [],
            "attributes": [],
            "failures": [],
            "partial_reasons": [],
            "target_side_verified": False,
            "created_objects_verified": False,
        }

    created_details = [_created_object_detail(conn, dn) for dn in operation.created_dns]
    attr_details = [_verify_attr(conn, change) for change in _written_changes(operation)]
    attr_details.extend(_verify_attr(conn, change) for change in _created_dmsa_attr_checks(operation))

    failures: list[str] = []
    partial_reasons: list[str] = []

    for detail in created_details:
        if detail["status"] == "absent":
            failures.append(f"created object missing: {detail['dn']} ({detail['reason']})")
        elif detail["status"] == "unreadable":
            partial_reasons.append(f"created object unreadable: {detail['dn']} ({detail['reason']})")

    target_details = [detail for detail in attr_details if detail["attribute"] in _TARGET_SIDE_ATTRS]
    for detail in attr_details:
        change = AttributeChange(
            dn=detail["dn"],
            attribute=detail["attribute"],
            mode="replace",
        )
        if detail["status"] == "matched":
            continue
        if (
            _is_dmsa_side(change, operation)
            and detail["read_status"] in {"absent", "unreadable", "object-missing"}
        ):
            partial_reasons.append(
                f"{detail['dn']} {detail['attribute']}: "
                f"{detail['read_status']} ({detail['reason']})"
            )
            continue
        failures.append(
            f"{detail['dn']} {detail['attribute']}: {detail['status']} ({detail['reason']})"
        )

    target_side_verified = bool(target_details) and all(
        detail["status"] == "matched" for detail in target_details
    )
    created_objects_verified = all(
        detail["status"] == "present" for detail in created_details
    ) if created_details else True

    status = "verified"
    if failures:
        status = "failed"
    elif partial_reasons:
        status = "partial"

    return {
        "status": status,
        "ok": status in {"verified", "partial"},
        "created_objects": created_details,
        "attributes": attr_details,
        "failures": failures,
        "partial_reasons": partial_reasons,
        "target_side_verified": target_side_verified,
        "created_objects_verified": created_objects_verified,
    }


def verify_operation_ldap(
    operation: Operation,
    conn: Connection | None = None,
) -> bool:
    """Verify that all LDAP writes recorded in the operation are still in effect.

    When conn is None, returns the stored operation.verified flag (no live check).
    When conn is provided, always performs a live LDAP check regardless of the
    stored flag — the environment may have changed since the last verification.
    """
    if conn is None:
        return operation.verified

    details = verify_operation_ldap_details(operation, conn=conn)
    record_ldap_verification(operation, details)
    return bool(details["ok"])
