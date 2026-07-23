from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from dmsa_reaper.models import CheckStatus, MapState, Operation, PathCandidate
from dmsa_reaper.paths.classifier import classify_paths
from dmsa_reaper.paths.ranking import rank_paths
from dmsa_reaper.primitives.registry import get_primitives

BADSUCCESSOR_PRIMITIVES = frozenset({
    "postpatch-mutual-pair",
    "existing-dmsa-postpatch-mutual",
    "legacy-oneway-link",
    "existing-dmsa-legacy-link",
    "dacl-container-escalate",
    "dacl-target-escalate",
})
BADSUCCESSOR_LEGACY_PRIMITIVES = frozenset({
    "legacy-oneway-link",
    "existing-dmsa-legacy-link",
})
BADSUCCESSOR_DACL_PRIMITIVES = frozenset({
    "dacl-container-escalate",
    "dacl-target-escalate",
})
BADSUCCESSOR_POSTPATCH_PRIMITIVES = frozenset({
    "postpatch-mutual-pair",
    "existing-dmsa-postpatch-mutual",
})

SENSITIVE_TARGET_MARKERS = (
    "CN=Administrator,",
    "CN=krbtgt,",
    "OU=Domain Controllers,",
)


def classified_paths(
    state: MapState,
    *,
    expand_targets: bool = True,
    only: Iterable[str] | None = None,
    exclude_legacy: bool = False,
    include_sensitive_targets: bool = False,
) -> list[PathCandidate]:
    paths = rank_paths(classify_paths(state, expand_targets=expand_targets))
    wanted = set(only or [])
    if "badsuccessor" in wanted:
        wanted.remove("badsuccessor")
        wanted.update(BADSUCCESSOR_PRIMITIVES)
    if "ouroboros" in wanted:
        wanted.remove("ouroboros")
        wanted.update({"postpatch-mutual-pair", "existing-dmsa-postpatch-mutual", "self-pkinit-loop"})
    if wanted:
        paths = [path for path in paths if path.primitive in wanted]
    if exclude_legacy:
        paths = [path for path in paths if path.primitive not in BADSUCCESSOR_LEGACY_PRIMITIVES]
    if not include_sensitive_targets:
        paths = [path for path in paths if not is_sensitive_target(path.target_dn)]
    return paths


def is_sensitive_target(dn: str | None) -> bool:
    if not dn:
        return False
    lowered = dn.lower()
    return any(marker.lower() in lowered for marker in SENSITIVE_TARGET_MARKERS)


def _path_status(path: PathCandidate) -> str:
    if path.executable:
        return "executable"
    if path.primitive in {"self-write-map", "self-pkinit-loop"}:
        return "informational"
    return "blocked"


def _badsuccessor_category(path: PathCandidate) -> str:
    if path.primitive in BADSUCCESSOR_POSTPATCH_PRIMITIVES:
        return "postpatch-mutual"
    if path.primitive in BADSUCCESSOR_LEGACY_PRIMITIVES:
        return "legacy"
    if path.primitive in BADSUCCESSOR_DACL_PRIMITIVES:
        return "dacl-assisted"
    return "unknown"


def assess_badsuccessor(
    state: MapState,
    *,
    expand_targets: bool = True,
    exclude_legacy: bool = False,
    include_sensitive_targets: bool = False,
) -> dict[str, Any]:
    paths = classified_paths(
        state,
        expand_targets=expand_targets,
        only=BADSUCCESSOR_PRIMITIVES,
        exclude_legacy=exclude_legacy,
        include_sensitive_targets=include_sensitive_targets,
    )
    findings = []
    for path in paths:
        blockers = []
        if not path.executable:
            blockers.append("path is not directly executable")
        if path.environment_warnings:
            blockers.extend(path.environment_warnings)
        if is_sensitive_target(path.target_dn) and not include_sensitive_targets:
            blockers.append("sensitive target hidden by default")
        findings.append({
            "path_id": path.id,
            "primitive": path.primitive,
            "category": _badsuccessor_category(path),
            "status": _path_status(path),
            "executable": path.executable,
            "container_dn": path.container_dn,
            "dmsa_dn": path.dmsa_dn,
            "target_dn": path.target_dn,
            "required_rights": path.required_rights,
            "candidate_targets_count": path.candidate_targets_count,
            "why": {
                "requires_create_dmsa": path.requires_create_dmsa,
                "requires_modify_dmsa": path.requires_modify_dmsa,
                "requires_modify_target": path.requires_modify_target,
                "requires_modify_container_dacl": path.requires_modify_container_dacl,
                "requires_modify_target_dacl": path.requires_modify_target_dacl,
            },
            "blockers": blockers,
            "kerberos_proof_required": path.primitive in BADSUCCESSOR_PRIMITIVES,
            "path": path.model_dump(mode="json"),
        })
    return {
        "type": "badsuccessor-assessment",
        "domain": state.environment.domain,
        "dmsa_capable_status": state.environment.dmsa_capable_status,
        "path_count": len(findings),
        "paths": findings,
        "limitations": [
            "LDAP-state verification is not Kerberos ticket proof.",
            "Full BadSuccessor validation requires operation-bound kerberos-dmsa-proof evidence.",
        ],
    }


def build_badsuccessor_plan(path: PathCandidate) -> dict[str, Any]:
    primitive = get_primitives().get(path.primitive)
    dry_run_steps: list[str]
    if primitive is None:
        dry_run_steps = [f"[{path.primitive}] no registered primitive; no LDAP plan available"]
    else:
        operation = Operation(
            id="PLAN",
            primitive=path.primitive,
            path_id=path.id,
            metadata={"path": path.model_dump(mode="json")},
        )
        dry_run_steps = primitive.dry_run_steps(operation)
    writes = _expected_writes(path)
    return {
        "type": "badsuccessor-plan",
        "path_id": path.id,
        "primitive": path.primitive,
        "created_objects": writes["created_objects"],
        "modified_attributes": writes["modified_attributes"],
        "required_rights": path.required_rights,
        "expected_ldap_post_state": writes["expected_ldap_post_state"],
        "expected_kerberos_proof_requirements": [
            "kerberos-base-proof only proves environment readiness.",
            "kerberos-dmsa-proof must be operation-bound and match target/dMSA SAM.",
            "No raw tickets, hashes, keys, passwords, or base64 ticket blobs are accepted.",
        ],
        "dry_run_steps": dry_run_steps,
        "ldap_writes_performed": False,
    }


def _expected_writes(path: PathCandidate) -> dict[str, Any]:
    target = path.target_dn or "<target-dn>"
    container = path.container_dn or "<container-dn>"
    dmsa = path.dmsa_dn or f"CN=<generated-dmsa>,{container}"
    created: list[dict[str, Any]] = []
    modified: list[dict[str, str]] = []
    post_state: list[dict[str, str]] = []
    if path.primitive in {"postpatch-mutual-pair", "legacy-oneway-link", "dacl-container-escalate", "dacl-target-escalate"}:
        created.append({"dn": dmsa, "object_class": "msDS-DelegatedManagedServiceAccount"})
    if path.primitive in {
        "postpatch-mutual-pair",
        "legacy-oneway-link",
        "existing-dmsa-postpatch-mutual",
        "existing-dmsa-legacy-link",
    }:
        modified.extend([
            {"dn": dmsa, "attribute": "msDS-ManagedAccountPrecededByLink", "after": target},
            {"dn": dmsa, "attribute": "msDS-DelegatedMSAState", "after": "2"},
        ])
    if path.primitive in {"postpatch-mutual-pair", "existing-dmsa-postpatch-mutual"}:
        modified.extend([
            {"dn": target, "attribute": "msDS-SupersededManagedAccountLink", "after": dmsa},
            {"dn": target, "attribute": "msDS-SupersededServiceAccountState", "after": "2"},
        ])
    if path.primitive == "dacl-container-escalate":
        modified.append({"dn": container, "attribute": "nTSecurityDescriptor", "after": "scoped ACE"})
    if path.primitive == "dacl-target-escalate":
        modified.append({"dn": target, "attribute": "nTSecurityDescriptor", "after": "scoped ACE"})
    post_state.extend(modified)
    return {
        "created_objects": created,
        "modified_attributes": modified,
        "expected_ldap_post_state": post_state,
    }


def operation_lifecycle_summary(operation: Operation) -> dict[str, Any]:
    ldap_meta = operation.metadata.get("ldap_verification")
    external_meta = operation.metadata.get("external_verification")
    base_meta = operation.metadata.get("kerberos_base_check")
    full_badsuccessor_success = operation.verified_ldap and operation.verified_ticket
    return {
        "operation_id": operation.id,
        "primitive": operation.primitive,
        "status": operation.status,
        "executed": operation.status == "executed",
        "ldap_verified": operation.verified_ldap,
        "ldap_verification_status": (
            ldap_meta.get("status") if isinstance(ldap_meta, dict) else None
        ),
        "kerberos_base_verified": isinstance(base_meta, dict) and base_meta.get("ok") is True,
        "kerberos_dmsa_verified": operation.verified_ticket,
        "external_verified": False,
        "full_badsuccessor_success": full_badsuccessor_success,
        "external_verification_status": (
            external_meta.get("status") if isinstance(external_meta, dict) else None
        ),
        "cleaned_up": operation.cleaned_up,
        "cleanup_verified": operation.cleanup_verified,
        "limitations": _operation_limitations(operation),
    }


def _operation_limitations(operation: Operation) -> list[str]:
    limitations = []
    if operation.verified_ldap and not operation.verified_ticket:
        limitations.append("LDAP state was verified, but no operation-bound dMSA Kerberos proof is recorded.")
    if operation.metadata.get("kerberos_base_check") and not operation.verified_ticket:
        limitations.append("Base Kerberos proof was recorded; it does not prove dMSA abuse.")
    return limitations


def build_operation_report(operation: Operation) -> dict[str, Any]:
    base = operation.metadata.get("kerberos_base_check")
    kerberos_base_ready = isinstance(base, dict) and base.get("ok") is True
    kerberos_dmsa_verified = operation.verified_ticket
    full_badsuccessor_success = operation.verified_ldap and kerberos_dmsa_verified
    return {
        "type": "operation-report",
        "operation_id": operation.id,
        "path_id": operation.path_id,
        "primitive": operation.primitive,
        "scope_file_hash": operation.scope_file_hash,
        "ldap_verified": operation.verified_ldap,
        "kerberos_base_ready": kerberos_base_ready,
        "kerberos_dmsa_verified": kerberos_dmsa_verified,
        "full_badsuccessor_success": full_badsuccessor_success,
        "ouroboros_status": str(operation.metadata.get("ouroboros_status") or "not-assessed"),
        "required_next_proof": _required_next_proof(operation),
        "operation_lifecycle": operation_lifecycle_summary(operation),
        "ldap_artifacts": {
            "created_dmsa_objects": operation.created_dns,
            "maybe_created_dns": operation.maybe_created_dns,
            "modified_attributes": [
                {
                    "dn": change.dn,
                    "attribute": change.attribute,
                    "mode": change.mode,
                    "step_status": change.step_status,
                }
                for change in operation.changed_attrs
            ],
        },
        "rights_used": _operation_required_rights(operation),
        "kerberos": {
            "base_proof_recorded": isinstance(base, dict),
            "base_ready": kerberos_base_ready,
            "base_evidence_sha256": base.get("evidence_sha256") if isinstance(base, dict) else None,
            "dmsa_proof_verified": kerberos_dmsa_verified,
            "ticket_artifact": (operation.metadata.get("ticket") or {}).get("tgt_ccache"),
            "service_ticket_artifact": (
                operation.metadata.get("ticket") or {}
            ).get("service_ccache"),
        },
        "detection_indicators": [
            "Created dMSA object DN(s)",
            "msDS-ManagedAccountPrecededByLink writes",
            "msDS-SupersededManagedAccountLink writes",
            "msDS-SupersededServiceAccountState writes",
            "nTSecurityDescriptor changes for DACL-assisted paths",
        ],
        "operator_notes": [
            "Review recorded created objects and modified attributes for external change tracking.",
            f"Resume exact cleanup with: dmsa-reaper cleanup --op {operation.id}",
        ],
        "final_conclusion": (
            "full-badsuccessor-success"
            if full_badsuccessor_success
            else "ldap-verified-kerberos-proof-missing"
            if operation.verified_ldap
            else "verification-incomplete"
        ),
        "errors": operation.errors,
        "recovery_notes": operation.recovery_notes,
        "secrets_logged": False,
    }


def _required_next_proof(operation: Operation) -> str:
    if not operation.verified_ldap:
        return "ldap-state-verification"
    if not operation.verified_ticket:
        return "native dMSA ccache and service-ticket validation"
    return "none"


def _operation_required_rights(operation: Operation) -> list[str]:
    path = operation.metadata.get("path")
    if isinstance(path, dict):
        rights = path.get("required_rights")
        if isinstance(rights, list):
            return [str(right) for right in rights]
    return []


def operation_report_markdown(report: dict[str, Any]) -> str:
    lifecycle = report["operation_lifecycle"]
    artifacts = report["ldap_artifacts"]
    lines = [
        f"# dMSA-Reaper Operation {lifecycle['operation_id']}",
        "",
        "## Lifecycle",
        "",
        f"- Path ID: `{report.get('path_id')}`",
        f"- Primitive: `{lifecycle['primitive']}`",
        f"- Scope file hash: `{report.get('scope_file_hash')}`",
        f"- Status: `{lifecycle['status']}`",
        f"- LDAP verified: `{str(lifecycle['ldap_verified']).lower()}`",
        f"- Kerberos base ready: `{str(report['kerberos_base_ready']).lower()}`",
        f"- Kerberos dMSA proof verified: `{str(report['kerberos_dmsa_verified']).lower()}`",
        f"- Full BadSuccessor success: `{str(report['full_badsuccessor_success']).lower()}`",
        f"- Required next proof: `{report['required_next_proof']}`",
        f"- External dMSA proof verified: `{str(lifecycle['external_verified']).lower()}`",
        f"- Final conclusion: `{report.get('final_conclusion')}`",
        "",
        "## LDAP Artifacts",
        "",
    ]
    for dn in artifacts["created_dmsa_objects"]:
        lines.append(f"- Created dMSA: `{dn}`")
    for change in artifacts["modified_attributes"]:
        lines.append(f"- Modified `{change['attribute']}` on `{change['dn']}`")
    if not artifacts["created_dmsa_objects"] and not artifacts["modified_attributes"]:
        lines.append("- No LDAP changes recorded.")
    lines.extend([
        "",
        "## Kerberos Proof",
        "",
        f"- Base proof recorded: `{str(report['kerberos']['base_proof_recorded']).lower()}`",
        f"- dMSA proof verified: `{str(report['kerberos']['dmsa_proof_verified']).lower()}`",
        "",
        "## Limitations",
        "",
    ])
    limitations = lifecycle.get("limitations") or ["No additional limitations recorded."]
    lines.extend(f"- {limitation}" for limitation in limitations)
    return "\n".join(lines) + "\n"


def assess_ouroboros(
    state: MapState,
    *,
    include_sensitive_targets: bool = False,
    kerberos_ready: bool | None = None,
) -> dict[str, Any]:
    paths = classified_paths(
        state,
        expand_targets=True,
        only={"postpatch-mutual-pair", "existing-dmsa-postpatch-mutual", "self-pkinit-loop"},
        include_sensitive_targets=include_sensitive_targets,
    )
    blockers = _ouroboros_environment_blockers(state)
    warnings = list(state.dmsa_read_warnings)
    if state.unreadable_dmsa_candidates:
        warnings.append("one or more dMSA candidates were unreadable")
    if kerberos_ready is False:
        blockers.append("Kerberos readiness checks are not passing")
    if not paths:
        blockers.append("no dMSA migration or self-PKINIT assessment path found")
    self_paths = [path for path in paths if path.primitive == "self-pkinit-loop"]
    if blockers:
        status = "blocked"
    elif self_paths:
        status = "capable"
    elif paths:
        status = "ldap-path-present-proof-required"
        warnings.append(
            "LDAP transition path exists, but native Ouroboros credential proof is not "
            "implemented; operation-bound kerberos-dmsa-proof is required."
        )
    else:
        status = "unknown"
    required_proofs = [
        "kerberos-base-proof for environment readiness",
        "operation-bound kerberos-dmsa-proof for dMSA ticket behavior",
        "external Ouroboros proof adapter evidence; native secret extraction is not implemented",
    ]
    capable = status == "capable"
    return {
        "type": "ouroboros-assessment",
        "domain": state.environment.domain,
        "ouroboros_capable": capable,
        "ouroboros_status": status,
        "kerberos_dmsa_verified": False,
        "verified_external": False,
        "full_badsuccessor_success": False,
        "native_extraction": "not_implemented",
        "external_proof_required": True,
        "required_next_proof": "operation-bound kerberos-dmsa-proof",
        "ouroboros_blockers": blockers,
        "ouroboros_warnings": warnings,
        "ouroboros_required_proofs": required_proofs,
        "paths": [path.model_dump(mode="json") for path in paths],
        "safety_constraints": [
            "No native credential extraction is implemented.",
            "No raw tickets, keys, hashes, passwords, or session keys may be logged.",
            "Verification requires structured external proof while operation state is active.",
        ],
    }


def _ouroboros_environment_blockers(state: MapState) -> list[str]:
    env = state.environment
    blockers = []
    if env.dmsa_schema_status != CheckStatus.present:
        blockers.append(f"dMSA schema status is {env.dmsa_schema_status}")
    if env.server_2025_dc_status != CheckStatus.present:
        blockers.append(f"Server 2025 DC status is {env.server_2025_dc_status}")
    if env.kds_root_key_status != CheckStatus.present:
        blockers.append(f"KDS root key status is {env.kds_root_key_status}")
    return blockers


def build_ouroboros_plan(state: MapState, path: PathCandidate | None = None) -> dict[str, Any]:
    assessment = assess_ouroboros(state)
    return {
        "type": "ouroboros-plan",
        "status": assessment["ouroboros_status"],
        "path_id": path.id if path else None,
        "ldap_state_transition": (
            build_badsuccessor_plan(path)["expected_ldap_post_state"] if path else []
        ),
        "expected_kerberos_proof_requirement": assessment["ouroboros_required_proofs"],
        "expected_artifacts": [
            "created or linked dMSA LDAP state",
            "operation-bound external Kerberos proof hash",
        ],
        "safety_constraints": assessment["safety_constraints"],
        "native_secret_extraction_implemented": False,
    }


def build_ouroboros_simulation(state: MapState) -> dict[str, Any]:
    assessment = assess_ouroboros(state)
    return {
        "type": "ouroboros-simulation",
        "status": assessment["ouroboros_status"],
        "would_require": assessment["ouroboros_required_proofs"],
        "secrets_generated": False,
        "notes": [
            "Simulation uses map state only.",
            "No live credential, ticket, or secret retrieval is performed.",
        ],
    }
