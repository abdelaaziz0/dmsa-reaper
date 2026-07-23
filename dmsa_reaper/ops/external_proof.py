from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dmsa_reaper.models import Operation

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|hash|ntlm|aes|secret|session_?key|private_?key|"
    r"raw_?ticket|ticket_?blob|ticket_?base64|kirbi)",
    re.IGNORECASE,
)
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/]{80,}={0,2}$")
_HEXISH_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_ALLOWED_DIGEST_KEYS = frozenset({
    "proof_sha256",
    "evidence_sha256",
    "stdout_sha256",
    "stderr_sha256",
    "command_sha256",
})
DMSA_PROOF_TYPE = "kerberos-dmsa-proof"
BASE_PROOF_TYPE = "kerberos-base-proof"
DMSA_REQUIRED_TOP_FIELDS = frozenset({
    "type",
    "operation_id",
    "created_dmsa_sam",
    "domain",
    "realm",
    "result",
    "evidence",
})
DMSA_OPTIONAL_TOP_FIELDS = frozenset({
    "target_sam",
    "target_dn",
    "tool",
    "tool_version",
    "verifier",
    "verifier_version",
    "failure_class",  # present in failure proofs (result != "success")
})
DMSA_EVIDENCE_REQUIRED_FIELDS = frozenset({"principal", "service", "timestamp"})
DMSA_EVIDENCE_OPTIONAL_FIELDS = frozenset({"proof_method"})


class ExternalProofError(ValueError):
    pass


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _dn_cn(dn: str | None) -> str | None:
    if not dn:
        return None
    first = dn.split(",", 1)[0].strip()
    if first.lower().startswith("cn="):
        return first[3:]
    return None


def _strip_wrappers(value: str) -> str:
    stripped = value.strip()
    while len(stripped) >= 2 and (
        (stripped[0], stripped[-1]) in {("<", ">"), ('"', '"'), ("'", "'")}
    ):
        stripped = stripped[1:-1].strip()
    return stripped


def _normalize_dn(value: str) -> str:
    stripped = _strip_wrappers(value)
    stripped = re.sub(r"\s*=\s*", "=", stripped)
    stripped = re.sub(r"\s*,\s*", ",", stripped)
    return stripped.lower()


def _domain_from_dn(dn: str | None) -> str | None:
    if not dn:
        return None
    parts = re.findall(r"(?:^|,)\s*DC\s*=\s*([^,]+)", _strip_wrappers(dn), flags=re.IGNORECASE)
    if not parts:
        return None
    return ".".join(part.strip() for part in parts if part.strip())


def _target_dn_from_operation(operation: Operation) -> str | None:
    direct = operation.metadata.get("target_dn")
    if direct:
        return str(direct)
    path = operation.metadata.get("path")
    if isinstance(path, dict) and path.get("target_dn"):
        return str(path["target_dn"])
    return None


def _target_sam_from_operation(operation: Operation) -> str | None:
    direct = operation.metadata.get("target_sam")
    if direct:
        return str(direct).rstrip("$")
    target_dn = operation.metadata.get("target_dn")
    if target_dn:
        return _dn_cn(str(target_dn))
    path = operation.metadata.get("path")
    if isinstance(path, dict):
        target_sam = path.get("target_sam")
        if target_sam:
            return str(target_sam).rstrip("$")
        return _dn_cn(path.get("target_dn"))
    return None


def _created_sam_from_operation(operation: Operation) -> str | None:
    sam = operation.metadata.get("created_dmsa_sam")
    if sam:
        return str(sam)
    path = operation.metadata.get("path")
    if isinstance(path, dict) and path.get("created_dmsa_sam"):
        return str(path["created_dmsa_sam"])
    created_dn = operation.metadata.get("created_dmsa_dn")
    if created_dn:
        cn = _dn_cn(str(created_dn))
        return f"{cn}$" if cn else None
    if operation.created_dns:
        cn = _dn_cn(operation.created_dns[0])
        return f"{cn}$" if cn else None
    return None


def _domain_from_operation(operation: Operation) -> str | None:
    direct = operation.metadata.get("domain")
    if direct:
        return str(direct).lower()
    for key in ("target_dn", "created_dmsa_dn", "dmsa_dn", "container_dn"):
        domain = _domain_from_dn(str(operation.metadata.get(key) or ""))
        if domain:
            return domain.lower()
    path = operation.metadata.get("path")
    if isinstance(path, dict):
        for key in ("target_dn", "dmsa_dn", "container_dn"):
            domain = _domain_from_dn(str(path.get(key) or ""))
            if domain:
                return domain.lower()
    for dn in operation.created_dns:
        domain = _domain_from_dn(dn)
        if domain:
            return domain.lower()
    return None


def _realm_from_operation(operation: Operation, domain: str | None) -> str | None:
    direct = operation.metadata.get("realm")
    if direct:
        return str(direct).upper()
    if domain:
        return domain.upper()
    return None


def _realm_from_principal(value: Any) -> str | None:
    if not isinstance(value, str) or "@" not in value:
        return None
    return value.rsplit("@", 1)[1].strip().upper() or None


def _require_string(data: dict[str, Any], key: str, *, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ExternalProofError(f"{label}.{key} must be a non-empty string")
    return value.strip()


def _reject_unknown_keys(data: dict[str, Any], allowed: set[str] | frozenset[str], *, label: str) -> None:
    unknown = sorted(str(key) for key in data if str(key) not in allowed)
    if unknown:
        raise ExternalProofError(f"{label} contains unsupported field(s): {', '.join(unknown)}")


def _contains_secret(value: Any, *, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key) in _ALLOWED_DIGEST_KEYS:
                continue
            if _SECRET_KEY_RE.search(str(key)):
                findings.append(f"secret-looking evidence key: {child_path}")
            findings.extend(_contains_secret(child, path=child_path))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            findings.extend(_contains_secret(child, path=f"{path}[{idx}]"))
    elif isinstance(value, str):
        stripped = value.strip()
        if _BASE64ISH_RE.fullmatch(stripped):
            findings.append(f"secret-looking base64/blob value at {path}")
        elif _HEXISH_RE.fullmatch(stripped):
            findings.append(f"secret-looking hex/hash value at {path}")
    return findings


def find_secret_material(value: Any) -> list[str]:
    return _contains_secret(value)


def _sanitized_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitized_copy(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_sanitized_copy(child) for child in value]
    return value


def load_evidence_file(path: str | Path) -> tuple[dict[str, Any], str]:
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        evidence = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ExternalProofError(f"evidence file is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(evidence, dict):
        raise ExternalProofError("evidence file must contain a JSON object")
    return evidence, digest


def validate_kerberos_evidence(
    operation: Operation,
    evidence: dict[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    proof_type = evidence.get("type")
    if proof_type == BASE_PROOF_TYPE:
        return validate_kerberos_base_evidence(operation, evidence, evidence_sha256)
    return validate_kerberos_dmsa_evidence(operation, evidence, evidence_sha256)


def validate_kerberos_base_evidence_for_operation(
    operation: Operation | None,
    evidence: dict[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    if evidence.get("type") != BASE_PROOF_TYPE:
        raise ExternalProofError("evidence type must be 'kerberos-base-proof'")
    supplied_op = evidence.get("operation_id")
    allowed_ops: tuple[Any, ...] = (None, "")
    if operation is not None:
        allowed_ops = (None, "", operation.id)
    if supplied_op not in allowed_ops:
        expected = operation.id if operation is not None else "no operation_id"
        raise ExternalProofError(
            f"base proof operation_id {supplied_op!r} does not match {expected!r}"
        )
    if evidence.get("result") != "success":
        raise ExternalProofError("kerberos-base-proof result must be 'success'")
    secret_findings = _contains_secret(evidence)
    if secret_findings:
        raise ExternalProofError("; ".join(secret_findings))
    principal = _require_string(evidence, "principal", label="kerberos-base-proof")
    service = evidence.get("service")
    if service is not None and (not isinstance(service, str) or not service.strip()):
        raise ExternalProofError("kerberos-base-proof.service must be a non-empty string when present")
    realm = evidence.get("realm") or _realm_from_principal(principal)
    tickets = evidence.get("tickets")
    if isinstance(tickets, dict):
        if tickets.get("tgt_present") is not True:
            raise ExternalProofError("kerberos-base-proof requires tickets.tgt_present=true")
        if service and tickets.get("service_ticket_present") is not True:
            raise ExternalProofError(
                "kerberos-base-proof with a service requires tickets.service_ticket_present=true"
            )
    return {
        "mode": "evidence-file",
        "status": "verified",
        "ok": True,
        "type": BASE_PROOF_TYPE,
        "operation_id": supplied_op,
        "principal": principal,
        "service": service,
        "realm": realm,
        "tool": evidence.get("tool", "external"),
        "result": evidence.get("result"),
        "timestamp": evidence.get("timestamp"),
        "tickets": tickets if isinstance(tickets, dict) else None,
        "environment": evidence.get("environment") if isinstance(evidence.get("environment"), dict) else None,
        "notes": evidence.get("notes"),
        "proof_sha256": evidence.get("proof_sha256"),
        "evidence_sha256": evidence_sha256,
        "recorded_at": _utc_now_iso(),
        "scope": "base-kerberos-only",
    }


def validate_kerberos_base_evidence(
    operation: Operation,
    evidence: dict[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    return validate_kerberos_base_evidence_for_operation(operation, evidence, evidence_sha256)


def validate_kerberos_dmsa_evidence(
    operation: Operation,
    evidence: dict[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    if operation.status != "executed":
        raise ExternalProofError(
            "external Kerberos proof can only be recorded for an executed operation"
        )
    if evidence.get("type") != DMSA_PROOF_TYPE:
        raise ExternalProofError("evidence type must be 'kerberos-dmsa-proof'")
    secret_findings = _contains_secret(evidence)
    if secret_findings:
        raise ExternalProofError("; ".join(secret_findings))

    allowed_top_fields = DMSA_REQUIRED_TOP_FIELDS | DMSA_OPTIONAL_TOP_FIELDS
    _reject_unknown_keys(evidence, allowed_top_fields, label="kerberos-dmsa-proof")
    missing_top = sorted(field for field in DMSA_REQUIRED_TOP_FIELDS if field not in evidence)
    if missing_top:
        raise ExternalProofError(
            "kerberos-dmsa-proof missing required field(s): " + ", ".join(missing_top)
        )
    if "target_sam" not in evidence and "target_dn" not in evidence:
        raise ExternalProofError("kerberos-dmsa-proof requires target_sam or target_dn")

    if evidence.get("operation_id") != operation.id:
        raise ExternalProofError(
            f"evidence operation_id {evidence.get('operation_id')!r} does not match {operation.id!r}"
        )

    expected_domain = _domain_from_operation(operation)
    expected_realm = _realm_from_operation(operation, expected_domain)
    evidence_domain = _require_string(evidence, "domain", label="kerberos-dmsa-proof").lower()
    evidence_realm = _require_string(evidence, "realm", label="kerberos-dmsa-proof").upper()
    if not expected_domain:
        raise ExternalProofError("operation domain could not be determined for kerberos-dmsa-proof")
    if not expected_realm:
        raise ExternalProofError("operation realm could not be determined for kerberos-dmsa-proof")
    if evidence_domain != expected_domain:
        raise ExternalProofError(
            f"evidence domain {evidence_domain!r} does not match operation domain {expected_domain!r}"
        )
    if evidence_realm != expected_realm:
        raise ExternalProofError(
            f"evidence realm {evidence_realm!r} does not match operation realm {expected_realm!r}"
        )

    expected_target = _target_sam_from_operation(operation)
    expected_target_dn = _target_dn_from_operation(operation)
    if not expected_target and not expected_target_dn:
        raise ExternalProofError("operation target could not be determined for kerberos-dmsa-proof")
    if "target_sam" in evidence:
        evidence_target = _require_string(evidence, "target_sam", label="kerberos-dmsa-proof").rstrip("$")
        if expected_target and evidence_target.lower() != expected_target.lower():
            raise ExternalProofError(
                f"evidence target_sam {evidence_target!r} does not match operation target {expected_target!r}"
            )
    if "target_dn" in evidence:
        evidence_target_dn = _require_string(evidence, "target_dn", label="kerberos-dmsa-proof")
        if expected_target_dn and _normalize_dn(evidence_target_dn) != _normalize_dn(expected_target_dn):
            raise ExternalProofError("evidence target_dn does not match operation target_dn")

    expected_created = _created_sam_from_operation(operation)
    if not expected_created:
        raise ExternalProofError("operation created_dmsa_sam could not be determined for kerberos-dmsa-proof")
    evidence_created = _require_string(evidence, "created_dmsa_sam", label="kerberos-dmsa-proof")
    if expected_created and evidence_created.lower() != expected_created.lower():
        raise ExternalProofError(
            "evidence created_dmsa_sam does not match operation created_dmsa_sam"
        )

    proof_evidence = evidence.get("evidence")
    if not isinstance(proof_evidence, dict):
        raise ExternalProofError("evidence.evidence must be a JSON object")
    _reject_unknown_keys(
        proof_evidence,
        DMSA_EVIDENCE_REQUIRED_FIELDS | DMSA_EVIDENCE_OPTIONAL_FIELDS,
        label="kerberos-dmsa-proof.evidence",
    )
    missing_evidence = sorted(
        field for field in DMSA_EVIDENCE_REQUIRED_FIELDS if field not in proof_evidence
    )
    if missing_evidence:
        raise ExternalProofError(
            "kerberos-dmsa-proof.evidence missing required field(s): "
            + ", ".join(missing_evidence)
        )

    if evidence.get("result") != "success":
        raise ExternalProofError("kerberos-dmsa-proof result must be 'success'")

    principal = _require_string(proof_evidence, "principal", label="kerberos-dmsa-proof.evidence")
    service = _require_string(proof_evidence, "service", label="kerberos-dmsa-proof.evidence")
    timestamp = _require_string(proof_evidence, "timestamp", label="kerberos-dmsa-proof.evidence")
    for label, value in (("principal", principal), ("service", service)):
        value_realm = _realm_from_principal(value)
        if value_realm and value_realm != expected_realm:
            raise ExternalProofError(
                f"evidence {label} realm {value_realm!r} does not match operation realm {expected_realm!r}"
            )

    sanitized_evidence = {
        "principal": principal,
        "service": service,
        "timestamp": timestamp,
    }
    if "proof_method" in proof_evidence:
        sanitized_evidence["proof_method"] = _require_string(
            proof_evidence,
            "proof_method",
            label="kerberos-dmsa-proof.evidence",
        )

    return {
        "mode": "evidence-file",
        "status": "verified",
        "ok": True,
        "type": DMSA_PROOF_TYPE,
        "input_type": evidence["type"],
        "operation_id": evidence["operation_id"],
        "domain": evidence_domain,
        "realm": evidence_realm,
        "target_sam": evidence.get("target_sam"),
        "target_dn": evidence.get("target_dn"),
        "created_dmsa_sam": evidence.get("created_dmsa_sam"),
        "tool": evidence.get("tool", "external"),
        "tool_version": evidence.get("tool_version"),
        "verifier": evidence.get("verifier"),
        "verifier_version": evidence.get("verifier_version"),
        "result": evidence.get("result", "success"),
        "evidence_sha256": evidence_sha256,
        "principal": principal,
        "service": service,
        "timestamp": timestamp,
        "evidence": sanitized_evidence,
        "recorded_at": _utc_now_iso(),
    }


def record_kerberos_base_check(operation: Operation, metadata: dict[str, Any]) -> None:
    operation.metadata["kerberos_base_check"] = metadata


def record_external_verification(operation: Operation, metadata: dict[str, Any]) -> None:
    operation.metadata["external_verification"] = metadata
    operation.verified = True
    operation.verified_external = True
    operation.external_verified_at = metadata.get("recorded_at") or _utc_now_iso()
