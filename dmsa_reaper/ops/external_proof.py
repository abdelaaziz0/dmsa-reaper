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
DMSA_PROOF_TYPES = frozenset({"kerberos-dmsa-proof", "kerberos-proof"})
BASE_PROOF_TYPE = "kerberos-base-proof"


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
    return None


def _contains_secret(value: Any, *, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
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


def validate_kerberos_base_evidence(
    operation: Operation,
    evidence: dict[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    if evidence.get("type") != BASE_PROOF_TYPE:
        raise ExternalProofError("evidence type must be 'kerberos-base-proof'")
    supplied_op = evidence.get("operation_id")
    if supplied_op not in (None, "", operation.id):
        raise ExternalProofError(
            f"base proof operation_id {supplied_op!r} does not match {operation.id!r}"
        )
    if evidence.get("result") != "success":
        raise ExternalProofError("kerberos-base-proof result must be 'success'")
    secret_findings = _contains_secret(evidence)
    if secret_findings:
        raise ExternalProofError("; ".join(secret_findings))
    return {
        "mode": "evidence-file",
        "status": "verified",
        "ok": True,
        "type": BASE_PROOF_TYPE,
        "operation_id": supplied_op,
        "principal": evidence.get("principal"),
        "service": evidence.get("service"),
        "tool": evidence.get("tool", "external"),
        "result": evidence.get("result"),
        "notes": evidence.get("notes"),
        "evidence_sha256": evidence_sha256,
        "recorded_at": _utc_now_iso(),
        "scope": "base-kerberos-only",
    }


def validate_kerberos_dmsa_evidence(
    operation: Operation,
    evidence: dict[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    if operation.status != "executed" or operation.rolled_back:
        raise ExternalProofError(
            "external Kerberos proof can only be recorded for an executed, not rolled-back operation"
        )
    if evidence.get("type") not in DMSA_PROOF_TYPES:
        raise ExternalProofError("evidence type must be 'kerberos-dmsa-proof'")
    if evidence.get("operation_id") != operation.id:
        raise ExternalProofError(
            f"evidence operation_id {evidence.get('operation_id')!r} does not match {operation.id!r}"
        )

    expected_target = _target_sam_from_operation(operation)
    evidence_target = str(evidence.get("target_sam") or "").rstrip("$")
    if expected_target and evidence_target.lower() != expected_target.lower():
        raise ExternalProofError(
            f"evidence target_sam {evidence_target!r} does not match operation target {expected_target!r}"
        )

    expected_created = _created_sam_from_operation(operation)
    evidence_created = str(evidence.get("created_dmsa_sam") or "")
    if expected_created and evidence_created.lower() != expected_created.lower():
        raise ExternalProofError(
            "evidence created_dmsa_sam does not match operation created_dmsa_sam"
        )

    if not isinstance(evidence.get("evidence"), dict):
        raise ExternalProofError("evidence.evidence must be a JSON object")

    if evidence.get("result", "success") != "success":
        raise ExternalProofError("kerberos-dmsa-proof result must be 'success'")

    secret_findings = _contains_secret(evidence)
    if secret_findings:
        raise ExternalProofError("; ".join(secret_findings))

    return {
        "mode": "evidence-file",
        "status": "verified",
        "ok": True,
        "type": "kerberos-dmsa-proof",
        "input_type": evidence["type"],
        "operation_id": evidence["operation_id"],
        "target_sam": evidence.get("target_sam"),
        "created_dmsa_sam": evidence.get("created_dmsa_sam"),
        "tool": evidence.get("tool", "external"),
        "result": evidence.get("result", "success"),
        "evidence_sha256": evidence_sha256,
        "evidence": _sanitized_copy(evidence["evidence"]),
        "recorded_at": _utc_now_iso(),
    }


def record_kerberos_base_check(operation: Operation, metadata: dict[str, Any]) -> None:
    operation.metadata["kerberos_base_check"] = metadata


def record_external_verification(operation: Operation, metadata: dict[str, Any]) -> None:
    operation.metadata["external_verification"] = metadata
    operation.verified = True
    operation.verified_external = True
    operation.external_verified_at = metadata.get("recorded_at") or _utc_now_iso()
