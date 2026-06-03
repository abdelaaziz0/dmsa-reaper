from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Scope(BaseModel):
    domain: str
    allowed_ous: list[str] = Field(default_factory=list, alias="allowedOUs")
    allowed_targets: list[str] = Field(default_factory=list, alias="allowedTargets")
    deny_targets: list[str] = Field(default_factory=list, alias="denyTargets")
    deny_subtrees: list[str] = Field(default_factory=list, alias="denySubtrees")
    allow_dacl_primitives: bool = Field(False, alias="allowDaclPrimitives")
    allow_broad_dacl: bool = Field(False, alias="allowBroadDacl")
    require_confirm_string: bool = Field(True, alias="requireConfirmString")
    allow_default_sensitive_deny_override: bool = Field(
        False,
        alias="allowDefaultSensitiveDenyOverride",
    )

    model_config = {"populate_by_name": True}

    def file_hash(self, raw_json: str) -> str:
        return hashlib.sha256(raw_json.encode()).hexdigest()


def load_scope(path: str | Path) -> tuple[Scope, str]:
    """Load and validate a scope JSON file. Returns (Scope, sha256_hex_hash)."""
    raw = Path(path).read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(raw)
    scope = Scope.model_validate(data)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return scope, digest


def _dn_under_parent(dn: str, parent: str) -> bool:
    """Return True if dn is equal to parent or is a direct/indirect child of parent."""
    dn_lower = dn.strip().lower()
    parent_lower = parent.strip().lower()
    return dn_lower == parent_lower or dn_lower.endswith("," + parent_lower)


def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _default_sensitive_denies(scope: Scope) -> tuple[set[str], set[str]]:
    """Return (exact_dns, subtree_dns) denied by default for this scope."""
    if scope.allow_default_sensitive_deny_override:
        return set(), set()
    domain_dn = _domain_to_dn(scope.domain)
    if not domain_dn:
        return set(), set()
    config_nc = f"CN=Configuration,{domain_dn}"
    return (
        {domain_dn},
        {
            f"OU=Domain Controllers,{domain_dn}",
            f"CN=AdminSDHolder,CN=System,{domain_dn}",
            f"CN=System,{domain_dn}",
            config_nc,
            f"CN=Schema,{config_nc}",
        },
    )


def is_dn_in_allowed_scope(dn: str, scope: Scope, *, created: bool = False) -> bool:
    """Check whether a DN is within the allowed scope for a write operation.

    created=True  → must be under allowedOUs (object we are creating).
    created=False → may be under allowedOUs OR allowedTargets (object we are modifying).
    """
    if not dn:
        return False
    allowed = scope.allowed_ous
    if not created:
        allowed = allowed + scope.allowed_targets
    return any(_dn_under_parent(dn, parent) for parent in allowed)


def is_dn_in_deny_subtree(dn: str, scope: Scope) -> bool:
    """Return True if the DN is equal to or below an explicit denySubtrees entry."""
    return any(_dn_under_parent(dn, deny) for deny in scope.deny_subtrees)


def is_dn_default_denied(dn: str, scope: Scope) -> bool:
    """Return True if the DN falls into a built-in sensitive deny location."""
    exact_dns, subtree_dns = _default_sensitive_denies(scope)
    dn_lower = dn.strip().lower()
    if any(dn_lower == denied.strip().lower() for denied in exact_dns):
        return True
    return any(_dn_under_parent(dn, denied) for denied in subtree_dns)


def is_dn_denied(dn: str, scope: Scope) -> bool:
    """Return True if the DN is explicitly or default-denied.

    denyTargets blocks exact DNs. denySubtrees blocks the subtree and always
    wins over allowedOUs/allowedTargets. Built-in sensitive locations are also
    denied by default unless allowDefaultSensitiveDenyOverride is set.
    """
    dn_lower = dn.strip().lower()
    return (
        any(dn_lower == deny.strip().lower() for deny in scope.deny_targets)
        or is_dn_in_deny_subtree(dn, scope)
        or is_dn_default_denied(dn, scope)
    )


def check_domain_match(mapped_domain: str | None, scope: Scope) -> None:
    """Raise ValueError if mapped_domain does not match scope.domain (case-insensitive)."""
    if mapped_domain is None:
        return
    if mapped_domain.lower() != scope.domain.lower():
        raise ValueError(
            f"Scope domain '{scope.domain}' does not match mapped domain '{mapped_domain}'. "
            "Aborting to prevent out-of-scope writes."
        )


def check_dn_in_scope(dn: str, scope: Scope, *, created: bool = False, label: str = "DN") -> None:
    """Raise ValueError if dn is denied or not within allowed scope."""
    if is_dn_denied(dn, scope):
        raise ValueError(f"{label} '{dn}' is denied by scope policy - blocked.")
    if not is_dn_in_allowed_scope(dn, scope, created=created):
        category = "allowedOUs" if created else "allowedOUs or allowedTargets"
        raise ValueError(
            f"{label} '{dn}' is not under any {category} in the scope file - blocked."
        )


def check_dacl_scope_gates(
    scope: Scope | None,
    *,
    lab_unsafe: bool,
    broad_requested: bool,
) -> None:
    """Raise ValueError unless scope and CLI flags permit DACL modification."""
    if scope is None:
        raise ValueError("DACL primitives require --scope <file>.")
    if not scope.allow_dacl_primitives:
        raise ValueError("DACL primitives require allowDaclPrimitives=true in the scope file.")
    if not lab_unsafe:
        raise ValueError("DACL primitives require --lab-unsafe.")
    if broad_requested and not scope.allow_broad_dacl:
        raise ValueError(
            "Broad DACL ACEs require allowBroadDacl=true in the scope file and "
            "--allow-broad-dacl on the CLI."
        )
