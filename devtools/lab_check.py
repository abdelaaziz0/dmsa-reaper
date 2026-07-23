from __future__ import annotations

from typing import Any

from dmsa_reaper.models import MapState, PathCandidate


def validate_lab_contract(
    contract: dict[str, Any],
    state: MapState,
    paths: list[PathCandidate],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    expected_domain = _first_present(contract, "domain", "expected_domain", "lab")
    if expected_domain:
        actual_domain = (state.environment.domain or "").lower()
        add(
            "domain",
            actual_domain == str(expected_domain).lower(),
            f"expected={expected_domain} actual={actual_domain}",
        )

    expected_principal = _first_present(contract, "principal", "expected_principal")
    if expected_principal:
        actual_principal: str | None = (
            state.current_principal.name if state.current_principal else None
        )
        add(
            "principal",
            actual_principal == expected_principal,
            f"expected={expected_principal} actual={actual_principal}",
        )

    expected_guid = _first_present(
        contract,
        "expected_dmsa_class_guid",
        "expected-dmsa-class-guid",
        "dmsa_class_guid",
    )
    if expected_guid:
        actual_guid = state.schema_cache.dmsa_class_guid
        add(
            "dmsa_class_guid",
            str(actual_guid).lower() == str(expected_guid).lower(),
            f"expected={expected_guid} actual={actual_guid}",
        )

    attr_guids = _first_present(contract, "expected_attribute_guids", "expected-attribute-guids")
    if isinstance(attr_guids, dict):
        for attr, expected in attr_guids.items():
            actual_attr_guid: str | None = state.schema_cache.attr_guids.get(str(attr))
            add(
                f"attribute_guid:{attr}",
                str(actual_attr_guid).lower() == str(expected).lower(),
                f"expected={expected} actual={actual_attr_guid}",
            )

    expected_paths = _expected_paths(contract)
    for idx, expected in enumerate(expected_paths, start=1):
        match = _find_expected_path(paths, expected)
        label = str(expected.get("id") or expected.get("primitive") or idx)
        add(f"path_exists:{label}", match is not None, _path_expectation_detail(expected))
        if match is None:
            continue
        if "executable" in expected:
            add(
                f"path_executable:{label}",
                match.executable is bool(expected["executable"]),
                f"expected={expected['executable']} actual={match.executable}",
            )
        expected_rights = expected.get("rights") or expected.get("required_rights")
        if isinstance(expected_rights, list):
            missing = sorted(set(str(right) for right in expected_rights) - set(match.required_rights))
            add(
                f"path_rights:{label}",
                not missing,
                "missing=" + ",".join(missing) if missing else "all expected rights present",
            )

    ok = all(check["ok"] for check in checks)
    return {
        "type": "lab-contract-check",
        "ok": ok,
        "checks": checks,
        "failures": [check for check in checks if not check["ok"]],
        "secrets_logged": False,
    }


def _first_present(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _expected_paths(contract: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = (
        contract.get("expected_paths")
        or contract.get("expected-paths")
        or contract.get("expected-badsuccessor-paths")
        or []
    )
    if not isinstance(candidates, list):
        return []
    return [item for item in candidates if isinstance(item, dict)]


def _find_expected_path(
    paths: list[PathCandidate],
    expected: dict[str, Any],
) -> PathCandidate | None:
    for path in paths:
        if expected.get("id") and path.id != expected["id"]:
            continue
        if expected.get("primitive") and path.primitive != expected["primitive"]:
            continue
        if expected.get("target_dn") and path.target_dn != expected["target_dn"]:
            continue
        if expected.get("container_dn") and path.container_dn != expected["container_dn"]:
            continue
        if expected.get("target_dn_contains") and (
            not path.target_dn
            or str(expected["target_dn_contains"]).lower() not in path.target_dn.lower()
        ):
            continue
        if expected.get("container_dn_contains") and (
            not path.container_dn
            or str(expected["container_dn_contains"]).lower() not in path.container_dn.lower()
        ):
            continue
        return path
    return None


def _path_expectation_detail(expected: dict[str, Any]) -> str:
    parts = []
    for key in (
        "id",
        "primitive",
        "target_dn",
        "target_dn_contains",
        "container_dn",
        "container_dn_contains",
    ):
        if key in expected:
            parts.append(f"{key}={expected[key]}")
    return " ".join(parts)
