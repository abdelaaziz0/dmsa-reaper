from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from dmsa_reaper.models import Operation, PathCandidate

if TYPE_CHECKING:
    from ldap3 import Connection

    from dmsa_reaper.scope import Scope


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
        scope: "Scope | None" = None,
        target_dn: str | None = None,
        container_dn: str | None = None,
    ) -> list[str]:
        """Pre-execution checks. Returns advisory warnings; raises PrimitiveError for hard blockers.

        Default implementation validates scope constraints for created and modified DNs.
        Concrete primitives should call super().preflight(...) and extend as needed.
        """
        from dmsa_reaper.scope import check_dn_in_scope

        warnings: list[str] = []

        if scope is None:
            return warnings

        # Check DNs that will be created (container_dn passed for primitives that need it).
        for dn in self._planned_created_dns(path, target_dn=target_dn, container_dn=container_dn):
            try:
                check_dn_in_scope(dn, scope, created=True, label="Created DN")
            except ValueError as exc:
                raise PrimitiveError(str(exc)) from exc

        # Check DNs that will be modified.
        for dn in self._planned_modified_dns(path, target_dn=target_dn):
            try:
                check_dn_in_scope(dn, scope, created=False, label="Modified DN")
            except ValueError as exc:
                raise PrimitiveError(str(exc)) from exc

        return warnings

    def _planned_created_dns(
        self,
        path: PathCandidate,
        *,
        target_dn: str | None = None,
        container_dn: str | None = None,
    ) -> list[str]:
        """DNs that will be created by this primitive. Override to return actual values."""
        effective_container = container_dn or path.container_dn
        if effective_container:
            return [f"CN=<dmsa-name>,{effective_container}"]
        return []

    def _planned_modified_dns(self, path: PathCandidate, *, target_dn: str | None = None) -> list[str]:
        """DNs that will be modified by this primitive. Override to return actual values."""
        dns = []
        if path.dmsa_dn:
            dns.append(path.dmsa_dn)
        effective_target = target_dn or path.target_dn
        if effective_target:
            dns.append(effective_target)
        return dns

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
