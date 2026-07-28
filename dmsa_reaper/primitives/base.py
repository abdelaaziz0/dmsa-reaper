from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from dmsa_reaper.models import Operation, PathCandidate

if TYPE_CHECKING:
    from ldap3 import Connection


class PrimitiveError(RuntimeError):
    pass


class Primitive(ABC):
    name: str
    modifies_directory: bool = True

    @abstractmethod
    def check(self, path: PathCandidate) -> bool:
        raise NotImplementedError

    @abstractmethod
    def plan(self, path: PathCandidate) -> Operation:
        raise NotImplementedError

    def preflight(
        self,
        path: PathCandidate,
        *,
        target_dn: str | None = None,
        container_dn: str | None = None,
    ) -> list[str]:
        """Pre-execution checks. Returns advisory warnings; raises PrimitiveError for hard blockers.

        Concrete primitives should call super().preflight(...) and extend as needed.
        """
        del path, target_dn, container_dn
        return []

    @abstractmethod
    def execute(
        self,
        operation: Operation,
        *,
        confirm: bool = False,
        conn: "Connection | None" = None,
    ) -> Operation:
        raise NotImplementedError

    def dry_run_steps(self, operation: Operation) -> list[str]:
        """Return a human-readable description of what execute() would do."""
        return [f"[{self.name}] no LDAP write description is available"]
