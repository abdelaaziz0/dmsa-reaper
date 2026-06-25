"""CLI-level tests for DACL-primitive exploit command validations.

Tests cover:
  Fix 4 - dacl-container-escalate requires explicit --chain (no default)
  DACL primitives require scope allow-listing
  Fix 2 - --paths mode loads state.json best-effort (non-fatal if missing)
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

from dmsa_reaper.cli import app

_RUNNER = CliRunner()

# ── minimal fixtures ──────────────────────────────────────────────────────────

def _state_json(tmp_path) -> str:
    state = {
        "environment": {
            "domain": "corp.local",
            "dmsa_capable": True,
            "has_dmsa_schema": True,
        },
        "schema_cache": {
            "dmsa_class_guid": None,
            "attr_guids": {},
        },
        "current_principal": {"sid": "S-1-5-21-1-2-3-500", "name": "testuser"},
        "dmsas": [],
        "containers": [
            {"dn": "OU=Reaper,DC=corp,DC=local", "rights": []}
        ],
        "targets": [{"dn": "CN=svc,DC=corp,DC=local"}],
        "findings": [],
    }
    p = tmp_path / "state.json"
    p.write_text(json.dumps(state), encoding="utf-8")
    return str(p)


def _paths_json(tmp_path, primitive: str, path_id: str = "P-0001") -> str:
    path = {
        "id": path_id,
        "primitive": primitive,
        "principal": "S-1-5-21-1-2-3-500",
        "container_dn": "OU=Reaper,DC=corp,DC=local",
        "target_dn": "CN=svc,DC=corp,DC=local",
        "requires_modify_container_dacl": primitive == "dacl-container-escalate",
        "requires_modify_target_dacl": primitive == "dacl-target-escalate",
        "executable": True,
        "rollback_available": True,
    }
    p = tmp_path / "paths.json"
    p.write_text(json.dumps([path]), encoding="utf-8")
    return str(p)


def _scope_json(tmp_path) -> str:
    scope = {
        "domain": "corp.local",
        "allowedOUs": ["OU=Reaper,DC=corp,DC=local"],
        "allowedTargets": ["CN=svc,DC=corp,DC=local"],
        "denyTargets": [],
        "denySubtrees": [],
        "allowDaclPrimitives": True,
        "allowBroadDacl": True,
    }
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope), encoding="utf-8")
    return str(p)


# ── Fix 4: --chain is required for dacl-container-escalate ───────────────────

def test_exploit_chain_required_for_dacl_container_escalate(tmp_path, monkeypatch):
    """exploit must reject dacl-container-escalate without an explicit --chain flag."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope = _scope_json(tmp_path)

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--scope", scope,
        "--dry-run",
        # No --chain
    ])
    assert result.exit_code != 0
    assert "--chain is required" in result.output


def test_exploit_chain_legacy_accepted_for_dacl_container_escalate(tmp_path, monkeypatch):
    """exploit must accept --chain legacy for dacl-container-escalate (dry-run)."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope = _scope_json(tmp_path)

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--scope", scope,
        "--chain", "legacy",
        "--allow-broad-dacl",
        "--dry-run",
    ])
    # Should not fail with a chain error; may succeed or fail for other reasons (no state, etc.)
    assert "--chain is required" not in result.output


def test_exploit_chain_invalid_value_rejected(tmp_path, monkeypatch):
    """exploit must reject --chain with an unrecognized value."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope = _scope_json(tmp_path)

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--scope", scope,
        "--chain", "invalid-mode",
        "--dry-run",
    ])
    assert result.exit_code != 0
    assert "legacy" in result.output or "postpatch" in result.output


# ── Fix 5: --scope is required for dacl-* primitives ─────────────────────────

def test_exploit_scope_required_for_dacl_container_escalate(tmp_path, monkeypatch):
    """exploit must require --scope for dacl-container-escalate."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--chain", "legacy",
        "--dry-run",
        # No --scope
    ])
    assert result.exit_code != 0
    assert "requires" in result.output and "--scope" in result.output


def test_exploit_scope_required_for_dacl_target_escalate(tmp_path, monkeypatch):
    """exploit must require --scope for dacl-target-escalate."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-target-escalate")

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--dry-run",
        # No --scope
    ])
    assert result.exit_code != 0
    assert "requires" in result.output and "--scope" in result.output


def test_exploit_dacl_no_longer_requires_lab_flag(tmp_path, monkeypatch):
    """DACL primitives are gated by scope, not an extra lab flag."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope = _scope_json(tmp_path)

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--chain", "legacy",
        "--scope", scope,
        "--dry-run",
    ])
    assert result.exit_code == 0, result.output


def test_exploit_dacl_scope_must_allow_primitive(tmp_path, monkeypatch):
    """DACL primitives require allowDaclPrimitives=true in scope."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "domain": "corp.local",
        "allowedOUs": ["OU=Reaper,DC=corp,DC=local"],
        "allowedTargets": ["CN=svc,DC=corp,DC=local"],
        "allowDaclPrimitives": False,
    }), encoding="utf-8")

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--chain", "legacy",
        "--scope", str(scope_path),
        "--dry-run",
    ])
    assert result.exit_code != 0
    assert "allowDaclPrimitives" in result.output


# ── Fix 2: --paths best-effort state loading ──────────────────────────────────

def test_exploit_paths_mode_missing_state_is_nonfatal(tmp_path, monkeypatch):
    """--paths mode must not fail if state.json is missing (best-effort load)."""
    monkeypatch.chdir(tmp_path)
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope = _scope_json(tmp_path)
    # No state.json written — must be non-fatal

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--scope", scope,
        "--chain", "legacy",
        "--allow-broad-dacl",
        "--dry-run",
    ])
    # Should not fail because state.json is missing; may fail for other reasons
    # but the key thing is no "state.json not found" / FileNotFoundError exit
    assert "FileNotFoundError" not in result.output
    assert "No such file" not in result.output


def test_exploit_paths_mode_with_state_injects_principal_sid(tmp_path, monkeypatch):
    """--paths mode must inject principal_sid from state.json into operation metadata."""
    monkeypatch.chdir(tmp_path)
    _state_json(tmp_path)  # writes state.json with principal sid S-1-5-21-1-2-3-500
    paths = _paths_json(tmp_path, "dacl-container-escalate")
    scope = _scope_json(tmp_path)

    result = _RUNNER.invoke(app, [
        "exploit",
        "--paths", paths,
        "--path", "P-0001",
        "--scope", scope,
        "--chain", "legacy",
        "--allow-broad-dacl",
        "--dry-run",
    ])
    # The dry-run output must include the principal SID (embedded from state into the preview op)
    assert "S-1-5-21-1-2-3-500" in result.output
