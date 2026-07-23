from __future__ import annotations

from typing import TYPE_CHECKING

from dmsa_reaper.models import Operation, PathCandidate
from dmsa_reaper.ops.operation_log import new_operation
from dmsa_reaper.primitives.base import Primitive

if TYPE_CHECKING:
    from ldap3 import Connection


class SelfPkinitLoopPrimitive(Primitive):
    """Informational: dMSA can write both msDS-KeyCredentialLink and
    msDS-GroupMSAMembership on itself (Ouroboros / self-PKINIT loop).

    This primitive does not perform LDAP writes.  Exploitation requires a dMSA
    TGT and PKINIT authentication, which are out-of-band from this tool.
    """

    name = "self-pkinit-loop"
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
            "[self-pkinit-loop] informational — no LDAP writes",
            "  Exploitation requires a dMSA TGT and PKINIT authentication (out-of-band).",
        ]
