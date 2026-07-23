from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from dmsa_reaper.models import Operation
from dmsa_reaper.ops.external_proof import (
    ExternalProofError,
    _domain_from_operation,
    _realm_from_operation,
    _target_dn_from_operation,
    _target_sam_from_operation,
    find_secret_material,
    load_evidence_file,
    record_external_verification,
    validate_kerberos_dmsa_evidence,
)
from dmsa_reaper.ops.operation_log import save_operation

# Variables that may appear as {var} placeholders in verifier command templates.
ALLOWED_VERIFIER_VARS = frozenset({
    "operation_id",
    "domain",
    "realm",
    "target_dn",
    "target_sam",
    "created_dmsa_dn",
    "created_dmsa_sam",
    "output_proof",
})

_VAR_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class DmsaVerifierError(ValueError):
    pass


def validate_verifier_file(data: Any) -> tuple[str, list[str]]:
    """Validate a verifier command-file dict and return (name, argv_template).

    The command file must be a JSON object with:
      ``name``    — non-empty string identifying the verifier.
      ``command`` — non-empty list of strings, each optionally containing
                    ``{var}`` placeholders drawn from ALLOWED_VERIFIER_VARS.

    Raises DmsaVerifierError on structural or template problems.
    """
    if not isinstance(data, dict):
        raise DmsaVerifierError("verifier command file must be a JSON object")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise DmsaVerifierError("verifier command file must contain a non-empty string 'name'")
    command = data.get("command")
    if not isinstance(command, list) or not command:
        raise DmsaVerifierError("verifier command file must contain a non-empty list 'command'")
    if not all(isinstance(arg, str) for arg in command):
        raise DmsaVerifierError("verifier 'command' list must contain only strings")
    for arg in command:
        for match in _VAR_RE.finditer(arg):
            var = match.group(1)
            if var not in ALLOWED_VERIFIER_VARS:
                raise DmsaVerifierError(
                    f"unsupported template variable {{{var}}}; "
                    f"allowed: {sorted(ALLOWED_VERIFIER_VARS)}"
                )
    return name.strip(), list(command)


def _build_template_vars(op: Operation, output_proof: str) -> dict[str, str]:
    domain = _domain_from_operation(op) or ""
    realm = _realm_from_operation(op, domain) or ""
    return {
        "operation_id": op.id,
        "domain": domain,
        "realm": realm,
        "target_dn": _target_dn_from_operation(op) or "",
        "target_sam": _target_sam_from_operation(op) or "",
        "created_dmsa_dn": str(op.metadata.get("created_dmsa_dn") or ""),
        "created_dmsa_sam": str(op.metadata.get("created_dmsa_sam") or ""),
        "output_proof": output_proof,
    }


def render_verifier_argv(
    command_template: list[str],
    op: Operation,
    output_proof: str,
) -> list[str]:
    """Render all ``{var}`` placeholders in a command template list.

    Only variables from ALLOWED_VERIFIER_VARS are accepted. Unknown variables
    raise DmsaVerifierError before any subprocess is launched.
    """
    vars = _build_template_vars(op, output_proof)
    rendered: list[str] = []
    for arg in command_template:
        for match in _VAR_RE.finditer(arg):
            var = match.group(1)
            if var not in ALLOWED_VERIFIER_VARS:
                raise DmsaVerifierError(
                    f"unsupported template variable {{{var}}}; "
                    f"allowed: {sorted(ALLOWED_VERIFIER_VARS)}"
                )
        try:
            rendered.append(arg.format(**vars))
        except KeyError as exc:
            raise DmsaVerifierError(
                f"template variable {exc} is not in the allowed variable set"
            ) from exc
    return rendered


def _check_operation_ready(op: Operation) -> None:
    """Raise DmsaVerifierError if the operation cannot accept a dMSA proof."""
    if op.status != "executed":
        raise DmsaVerifierError(
            f"verifier requires operation status 'executed', got {op.status!r}"
        )


def run_dmsa_verifier(
    op: Operation,
    name: str,
    command_template: list[str],
    output_proof_path: Path,
    *,
    dry_run: bool = False,
    ops_dir: Path | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Execute the external dMSA verifier and record a valid proof on the operation.

    Returns a result dict with these keys:
      ok                  — True when proof was validated and recorded.
      dry_run             — True if the command was rendered but not executed.
      name                — Verifier name from the command file.
      rendered_argv_sha256 — SHA-256 of the rendered command (no raw argv stored).
      exit_code           — Subprocess exit code; None for dry-run or launch failure.
      stdout_sha256       — SHA-256 of captured stdout; None if not captured.
      stderr_sha256       — SHA-256 of captured stderr; None if not captured.
      proof_valid         — True when the proof passed schema + operation-binding validation.
      error               — String error description, or None on success.
      proof_sha256        — SHA-256 of the proof file bytes, or None.
      proof_meta          — Sanitised proof metadata dict, or None.

    stdout and stderr are never stored in the result; only their hashes are kept.
    """
    _check_operation_ready(op)

    rendered = render_verifier_argv(command_template, op, str(output_proof_path))
    rendered_sha256 = hashlib.sha256(
        json.dumps(rendered, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    result: dict[str, Any] = {
        "ok": False,
        "dry_run": dry_run,
        "name": name,
        "rendered_argv_sha256": rendered_sha256,
        "exit_code": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "proof_valid": False,
        "error": None,
        "proof_sha256": None,
        "proof_meta": None,
    }

    if dry_run:
        result["ok"] = True
        return result

    try:
        proc = subprocess.run(
            rendered,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        result["error"] = f"verifier timed out after {timeout}s"
        return result
    except Exception as exc:
        result["error"] = f"verifier subprocess error: {exc}"
        return result

    result["exit_code"] = proc.returncode
    result["stdout_sha256"] = hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest()
    result["stderr_sha256"] = hashlib.sha256(proc.stderr.encode("utf-8")).hexdigest()

    if proc.returncode != 0:
        result["error"] = f"verifier exited with code {proc.returncode}"
        return result

    if not output_proof_path.exists():
        result["error"] = f"verifier did not produce proof file: {output_proof_path}"
        return result

    try:
        evidence, digest = load_evidence_file(output_proof_path)
    except ExternalProofError as exc:
        result["error"] = f"proof file is not valid JSON: {exc}"
        return result

    secret_findings = find_secret_material(evidence)
    if secret_findings:
        result["error"] = "proof rejected: " + "; ".join(secret_findings)
        return result

    try:
        proof_meta = validate_kerberos_dmsa_evidence(op, evidence, digest)
    except ExternalProofError as exc:
        result["error"] = f"proof validation failed: {exc}"
        return result

    record_external_verification(op, proof_meta)
    save_operation(op, ops_dir=ops_dir)

    result["ok"] = True
    result["proof_valid"] = True
    result["proof_sha256"] = digest
    result["proof_meta"] = {
        "type": proof_meta.get("type"),
        "status": proof_meta.get("status"),
        "operation_id": proof_meta.get("operation_id"),
        "domain": proof_meta.get("domain"),
        "realm": proof_meta.get("realm"),
        "created_dmsa_sam": proof_meta.get("created_dmsa_sam"),
        "target_sam": proof_meta.get("target_sam"),
        "evidence_sha256": proof_meta.get("evidence_sha256"),
    }
    return result
