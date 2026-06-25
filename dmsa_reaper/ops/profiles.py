from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperatorProfile:
    name: str
    allowed_primitives: tuple[str, ...]
    rollback_policy: str
    expand_targets: bool = True
    exclude_legacy: bool = True
    include_sensitive_targets: bool = False
    require_scope_for_confirm: bool = True
    require_confirm_string: bool = True
    execute_allowed: bool = True


PROFILES: dict[str, OperatorProfile] = {
    "badsuccessor-lab": OperatorProfile(
        name="badsuccessor-lab",
        allowed_primitives=("postpatch-mutual-pair",),
        rollback_policy="always",
    ),
    "badsuccessor-assess-only": OperatorProfile(
        name="badsuccessor-assess-only",
        allowed_primitives=("postpatch-mutual-pair", "existing-dmsa-postpatch-mutual"),
        rollback_policy="manual",
        execute_allowed=False,
    ),
    "badsuccessor-no-rollback": OperatorProfile(
        name="badsuccessor-no-rollback",
        allowed_primitives=("postpatch-mutual-pair",),
        rollback_policy="never",
    ),
    "ouroboros-assess-only": OperatorProfile(
        name="ouroboros-assess-only",
        allowed_primitives=("postpatch-mutual-pair", "existing-dmsa-postpatch-mutual"),
        rollback_policy="manual",
        execute_allowed=False,
    ),
}


def get_profile(name: str) -> OperatorProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"unknown profile {name!r}; expected one of {', '.join(sorted(PROFILES))}"
        ) from exc


def valid_rollback_policy(value: str) -> bool:
    return value in {"always", "on-failure", "manual", "never"}
