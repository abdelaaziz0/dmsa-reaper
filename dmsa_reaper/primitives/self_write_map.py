from __future__ import annotations

from typing import TYPE_CHECKING

from dmsa_reaper.models import Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation
from dmsa_reaper.primitives.base import Primitive

if TYPE_CHECKING:
    from ldap3 import Connection


class SelfWriteMapPrimitive(Primitive):
    """Informational: maps self-write surfaces a controlled dMSA holds on itself.

    This primitive does not perform LDAP writes.  It surfaces which self-write
    attributes are available so the operator can decide which out-of-band technique
    to apply (shadow credential, group membership, etc.).
    """

    name = "self-write-map"
    modifies_directory = False

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
        operation.status = "informational"
        return operation

    def verify(self, operation: Operation, *, conn: "Connection | None" = None) -> bool:
        return True

    def dry_run_steps(self, operation: Operation) -> list[str]:
        return [
            "[self-write-map] informational — no LDAP writes",
            "  Review required_rights in path output to determine available self-write surfaces.",
        ]
