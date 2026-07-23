"""Runtime state revalidation tests for the exploit command.

Verifies that confirmed execution re-checks the exact mapped object in
state.json for each primitive, and that override flags record warnings
without silently bypassing unrelated checks.

Covered scenarios per spec:
  - postpatch-mutual-pair: container lacks CreateChild => blocked
  - existing-dmsa-postpatch-mutual: dMSA has only KeyCredentialLink => blocked
  - existing-dmsa-postpatch-mutual: dMSA has only one migration attr => blocked
  - existing-dmsa-legacy-link: dMSA lacks migration rights => blocked
  - legacy-oneway-link: container lacks CreateChild => blocked
  - dacl-container-escalate: container lacks WriteDACL/WriteOwner/GenericAll => blocked
  - dacl-target-escalate: target lacks WriteDACL/WriteOwner/GenericAll => blocked
  - --allow-unmapped-container bypasses its own check and records metadata warning
  - --allow-unmapped-dmsa bypasses its own check and records metadata warning
  - required_rights text inside paths.json does not substitute for state proof
"""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import Principal
from dmsa_reaper.ops.operation_log import load_operation

_RUNNER = CliRunner()

_CONTAINER = "OU=Reaper,DC=corp,DC=local"
_TARGET = "CN=svc,DC=corp,DC=local"
_DMSA = "CN=dmsa1,OU=Reaper,DC=corp,DC=local"
_DOMAIN = "corp.local"
_PRINCIPAL = "S-1-5-21-1-2-3-500"


@pytest.fixture(autouse=True)
def _bound_identity(monkeypatch):
    monkeypatch.setattr(
        "dmsa_reaper.cli.get_current_principal",
        lambda *_args, **_kwargs: Principal(name="operator", sid=_PRINCIPAL),
    )


# ── fixture helpers ───────────────────────────────────────────────────────────

def _right(right: str, dn: str) -> dict:
    return {"principal_sid": _PRINCIPAL, "right": right, "object_dn": dn}


def _scope(tmp_path, *, allow_dacl: bool = False) -> str:
    scope = {
        "domain": _DOMAIN,
        "allowedOUs": [_CONTAINER],
        "allowedTargets": [_TARGET],
        "denyTargets": [],
        "denySubtrees": [],
        "allowDaclPrimitives": allow_dacl,
        "allowBroadDacl": allow_dacl,
        "requireConfirmString": False,
    }
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope), encoding="utf-8")
    return str(p)


_OTHER_SID = "S-1-5-21-1-2-3-999"


def _right_for(right: str, dn: str, principal: str) -> dict:
    return {"principal_sid": principal, "right": right, "object_dn": dn}


def _state(
    tmp_path,
    *,
    container_rights: list[str] | None = None,
    dmsa_rights: list[str] | None = None,
    target_rights: list[str] | None = None,
    target_writable_attrs: list[str] | None = None,
    capable: bool = True,
    principal: str | None = _PRINCIPAL,
    container_rights_sid: str | None = None,
    dmsa_rights_sid: str | None = None,
    target_rights_sid: str | None = None,
) -> str:
    """Write state.json.  Pass principal=None to omit current_principal entirely.

    container_rights_sid / dmsa_rights_sid / target_rights_sid override the SID
    used for those object rights (default: principal or _PRINCIPAL).
    """
    cr_sid = container_rights_sid or principal or _PRINCIPAL
    dr_sid = dmsa_rights_sid or principal or _PRINCIPAL
    tr_sid = target_rights_sid or principal or _PRINCIPAL

    containers = [{"dn": _CONTAINER, "rights": [
        _right_for(r, _CONTAINER, cr_sid) for r in (container_rights or [])
    ]}]
    dmsas = [{"dn": _DMSA, "rights": [
        _right_for(r, _DMSA, dr_sid) for r in (dmsa_rights or [])
    ]}]
    targets = [{
        "dn": _TARGET,
        "rights": [_right_for(r, _TARGET, tr_sid) for r in (target_rights or [])],
        "writable_attrs": target_writable_attrs or [],
    }]
    data: dict = {
        "environment": {
            "domain": _DOMAIN,
            "dmsa_capable": capable,
            "has_dmsa_schema": capable,
            "has_server_2025_dc": capable,
            "has_kds_root_key": capable,
        },
        "schema_cache": {},
        "containers": containers,
        "dmsas": dmsas,
        "targets": targets,
        "findings": [],
    }
    if principal is not None:
        data["current_principal"] = {"sid": principal}
    else:
        data["current_principal"] = None
    p = tmp_path / "state.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _paths(tmp_path, primitive: str, *, extra: dict | None = None) -> str:
    path: dict = {
        "id": "P-0001",
        "primitive": primitive,
        "principal": _PRINCIPAL,
        "container_dn": _CONTAINER if primitive not in ("existing-dmsa-postpatch-mutual", "existing-dmsa-legacy-link") else None,
        "target_dn": _TARGET if primitive not in ("postpatch-mutual-pair", "legacy-oneway-link", "dacl-container-escalate") else None,
        "dmsa_dn": _DMSA if primitive in ("existing-dmsa-postpatch-mutual", "existing-dmsa-legacy-link") else None,
        "requires_create_dmsa": primitive in ("postpatch-mutual-pair", "legacy-oneway-link", "dacl-container-escalate", "dacl-target-escalate"),
        "requires_modify_dmsa": True,
        "requires_modify_target": primitive in ("postpatch-mutual-pair", "existing-dmsa-postpatch-mutual", "dacl-target-escalate"),
        "requires_modify_container_dacl": primitive == "dacl-container-escalate",
        "requires_modify_target_dacl": primitive == "dacl-target-escalate",
        "requires_operator_target": primitive in ("postpatch-mutual-pair", "legacy-oneway-link", "dacl-container-escalate"),
        "executable": True,
        "required_rights": [],
    }
    if extra:
        path.update(extra)
    p = tmp_path / "paths.json"
    p.write_text(json.dumps([path]), encoding="utf-8")
    return str(p)


class _MockConn:
    def __init__(self):
        self.added: list = []
        self.modified: list = []
        self._entries: list = []
        self._sd: bytes | None = None

    def add(self, dn, object_class, attributes) -> bool:
        self.added.append((dn, object_class, attributes))
        return True

    def modify(self, dn, changes, controls=None) -> bool:
        self.modified.append((dn, changes))
        return True

    def search(self, search_base, search_filter, search_scope, attributes, controls=None):
        if attributes == ["objectGUID"] and any(item[0] == search_base for item in self.added):
            class _Attr:
                raw_values = [bytes(range(16))]
                values = []
                value = None

            class _Entry:
                def __contains__(self, key):
                    return key == "objectGUID"

                def __getitem__(self, key):
                    return _Attr()

            self._entries = [_Entry()]
            return True
        self._entries = []
        return True

    @property
    def entries(self):
        return self._entries

    @property
    def result(self):
        return {}


def _confirm_args(
    tmp_path,
    *,
    target_dn: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    args = [
        "exploit",
        "--paths", str(tmp_path / "paths.json"),
        "--state", str(tmp_path / "state.json"),
        "--path", "P-0001",
        "--scope", str(tmp_path / "scope.json"),
        "--domain", _DOMAIN,
        "--username", "operator",
        "--confirm",
    ]
    if target_dn:
        args += ["--target-dn", target_dn, "--allow-grouped-target-selection"]
    if extra_args:
        args += extra_args
    return args


# ── postpatch-mutual-pair: container check ────────────────────────────────────

def test_postpatch_container_no_createchild_blocks_confirm(tmp_path, monkeypatch):
    """Container lacking CreateChild must block confirmed postpatch-mutual-pair execution."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["WriteDACL"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "CreateChild" in result.output
    assert "allow-unmapped-container" in result.output


def test_postpatch_container_not_in_state_blocks_confirm(tmp_path, monkeypatch):
    """Container absent from state.containers must block confirmed postpatch-mutual-pair."""
    monkeypatch.chdir(tmp_path)
    # Write state with NO containers at all.
    data = {
        "environment": {"domain": _DOMAIN, "dmsa_capable": True, "has_dmsa_schema": True,
                        "has_server_2025_dc": True, "has_kds_root_key": True},
        "schema_cache": {},
        "current_principal": {"sid": _PRINCIPAL},
        "containers": [],
        "dmsas": [],
        "targets": [{"dn": _TARGET, "writable_attrs": ["msDS-SupersededManagedAccountLink",
                                                         "msDS-SupersededServiceAccountState"]}],
        "findings": [],
    }
    (tmp_path / "state.json").write_text(json.dumps(data), encoding="utf-8")
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "state.containers" in result.output
    assert "allow-unmapped-container" in result.output


def test_postpatch_container_with_createchild_allows_confirm(tmp_path, monkeypatch):
    """Container with CreateChild must allow confirmed postpatch-mutual-pair."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild:dMSA"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET) + ["--ops-dir", str(ops_dir)])

    assert result.exit_code == 0, result.output


def test_allow_unmapped_container_bypasses_check_and_records_warning(tmp_path, monkeypatch):
    """--allow-unmapped-container must bypass the container check and record a warning."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=[],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-unmapped-container", "--ops-dir", str(ops_dir)]),
    )

    assert result.exit_code == 0, result.output
    op_file = next(ops_dir.glob("OP-*.json"))
    op = load_operation(op_file.stem, ops_dir=ops_dir)
    assert op.metadata.get("allow_unmapped_container") is True
    assert any("allow-unmapped-container" in w for w in op.metadata.get("warnings", []))


# ── existing-dmsa-postpatch-mutual: dMSA check ───────────────────────────────

def test_existing_dmsa_postpatch_key_cred_only_blocks_confirm(tmp_path, monkeypatch):
    """dMSA with only KeyCredentialLink must block existing-dmsa-postpatch-mutual."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=["WriteProperty:msDS-KeyCredentialLink"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "migration rights" in result.output
    assert "allow-unmapped-dmsa" in result.output


def test_existing_dmsa_postpatch_only_preceded_by_link_blocks_confirm(tmp_path, monkeypatch):
    """dMSA with only WriteProperty:msDS-ManagedAccountPrecededByLink (not DelegatedMSAState) must block."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=["WriteProperty:msDS-ManagedAccountPrecededByLink"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "migration rights" in result.output
    assert "allow-unmapped-dmsa" in result.output


def test_existing_dmsa_postpatch_both_migration_attrs_allows_confirm(tmp_path, monkeypatch):
    """dMSA with both migration attrs must allow existing-dmsa-postpatch-mutual --confirm."""
    monkeypatch.chdir(tmp_path)
    _state(
        tmp_path,
        dmsa_rights=[
            "WriteProperty:msDS-ManagedAccountPrecededByLink",
            "WriteProperty:msDS-DelegatedMSAState",
        ],
        target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                "msDS-SupersededServiceAccountState"],
    )
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET) + ["--ops-dir", str(ops_dir)])

    assert result.exit_code == 0, result.output


def test_existing_dmsa_postpatch_generic_all_allows_confirm(tmp_path, monkeypatch):
    """dMSA with GenericAll must satisfy migration rights check."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=["GenericAll"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET) + ["--ops-dir", str(ops_dir)])

    assert result.exit_code == 0, result.output


def test_allow_unmapped_dmsa_bypasses_check_and_records_warning(tmp_path, monkeypatch):
    """--allow-unmapped-dmsa must bypass the dMSA check and record a warning in metadata."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=["WriteProperty:msDS-KeyCredentialLink"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-unmapped-dmsa", "--ops-dir", str(ops_dir)]),
    )

    assert result.exit_code == 0, result.output
    op_file = next(ops_dir.glob("OP-*.json"))
    op = load_operation(op_file.stem, ops_dir=ops_dir)
    assert op.metadata.get("allow_unmapped_dmsa") is True
    assert any("allow-unmapped-dmsa" in w for w in op.metadata.get("warnings", []))


# ── existing-dmsa-legacy-link: dMSA check ────────────────────────────────────

def test_existing_dmsa_legacy_lacking_migration_rights_blocks_confirm(tmp_path, monkeypatch):
    """dMSA with only GroupMSAMembership right must block existing-dmsa-legacy-link."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=["WriteProperty:msDS-GroupMSAMembership"])
    _paths(tmp_path, "existing-dmsa-legacy-link")
    _scope(tmp_path)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-existing-dmsa-legacy-link"]),
    )

    assert result.exit_code != 0, result.output
    assert "migration rights" in result.output
    assert "allow-unmapped-dmsa" in result.output


def test_existing_dmsa_legacy_not_in_state_dmsas_blocks_confirm(tmp_path, monkeypatch):
    """dMSA absent from state.dmsas must block existing-dmsa-legacy-link."""
    monkeypatch.chdir(tmp_path)
    # State with NO dmsas
    data = {
        "environment": {"domain": _DOMAIN, "dmsa_capable": True, "has_dmsa_schema": True,
                        "has_server_2025_dc": True, "has_kds_root_key": True},
        "schema_cache": {},
        "current_principal": {"sid": _PRINCIPAL},
        "containers": [{"dn": _CONTAINER, "rights": []}],
        "dmsas": [],
        "targets": [{"dn": _TARGET, "writable_attrs": []}],
        "findings": [],
    }
    (tmp_path / "state.json").write_text(json.dumps(data), encoding="utf-8")
    _paths(tmp_path, "existing-dmsa-legacy-link")
    _scope(tmp_path)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-existing-dmsa-legacy-link"]),
    )

    assert result.exit_code != 0, result.output
    assert "state.dmsas" in result.output
    assert "allow-unmapped-dmsa" in result.output


# ── legacy-oneway-link: container check ──────────────────────────────────────

def test_legacy_oneway_container_lacking_createchild_blocks_confirm(tmp_path, monkeypatch):
    """Container without CreateChild must block legacy-oneway-link --confirm."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["WriteProperty:someAttr"])
    _paths(tmp_path, "legacy-oneway-link")
    _scope(tmp_path)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-legacy-oneway-link"]),
    )

    assert result.exit_code != 0, result.output
    assert "CreateChild" in result.output
    assert "allow-unmapped-container" in result.output


def test_legacy_oneway_container_with_createchild_allows_confirm(tmp_path, monkeypatch):
    """Container with CreateChild:dMSA must allow legacy-oneway-link --confirm."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild:dMSA"])
    _paths(tmp_path, "legacy-oneway-link")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET,
                      extra_args=["--allow-legacy-oneway-link", "--ops-dir", str(ops_dir)]),
    )

    assert result.exit_code == 0, result.output


# ── dacl-container-escalate: container DACL check ────────────────────────────

def test_dacl_container_lacking_dacl_control_blocks_confirm(tmp_path, monkeypatch):
    """Container with only CreateChild (not WriteDACL/WriteOwner) must block dacl-container-escalate."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild"])
    _paths(tmp_path, "dacl-container-escalate")
    _scope(tmp_path, allow_dacl=True)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET,
                      extra_args=["--chain", "legacy", "--allow-broad-dacl"]),
    )

    assert result.exit_code != 0, result.output
    assert "WriteDACL" in result.output or "DACL control" in result.output
    assert "allow-unmapped-container" in result.output


def test_dacl_container_with_writedacl_passes_state_validation(tmp_path, monkeypatch):
    """Container with WriteDACL must pass state revalidation for dacl-container-escalate.

    The test verifies that state validation does not block. Execution may fail at
    the LDAP stage due to the simplified mock (no nTSecurityDescriptor served).
    """
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["WriteDACL"])
    _paths(tmp_path, "dacl-container-escalate")
    _scope(tmp_path, allow_dacl=True)
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET,
                      extra_args=["--chain", "legacy", "--allow-broad-dacl"]),
    )

    # State validation must not fire. Any failure must NOT be a state validation block.
    assert "allow-unmapped-container" not in result.output
    assert "lacks DACL control" not in result.output
    assert "DACL control rights" not in result.output


# ── dacl-target-escalate: target DACL check ──────────────────────────────────

def test_dacl_target_lacking_dacl_control_blocks_confirm(tmp_path, monkeypatch):
    """Target without WriteDACL/WriteOwner/GenericAll must block dacl-target-escalate."""
    monkeypatch.chdir(tmp_path)
    # Container has CreateChild (so container check passes); target lacks DACL control.
    _state(tmp_path, container_rights=["CreateChild"], target_rights=["WriteProperty:someAttr"])
    _paths(tmp_path, "dacl-target-escalate")
    _scope(tmp_path, allow_dacl=True)

    result = _RUNNER.invoke(
        app,
        _confirm_args(
            tmp_path,
            extra_args=["--allow-broad-dacl",
                        "--container-dn", _CONTAINER, "--allow-unmapped-container"],
        ),
    )

    # Container check is bypassed; target DACL check must still fire.
    assert result.exit_code != 0, result.output
    assert ("allow-unmapped-target" in result.output or "WriteDACL" in result.output)


def test_dacl_target_with_writedacl_passes_state_validation(tmp_path, monkeypatch):
    """Target with WriteDACL must pass state revalidation for dacl-target-escalate.

    Verifies state validation does not block. Execution may fail at the LDAP
    stage due to the simplified mock.
    """
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild"], target_rights=["WriteDACL"])
    _paths(tmp_path, "dacl-target-escalate")
    _scope(tmp_path, allow_dacl=True)
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(
            tmp_path,
            extra_args=["--allow-broad-dacl", "--container-dn", _CONTAINER],
        ),
    )

    # State validation must not fire; any failure must NOT be a state validation block.
    assert "allow-unmapped-target" not in result.output
    assert "allow-unmapped-container" not in result.output
    assert "DACL control rights" not in result.output


# ── required_rights text does not substitute for state proof ──────────────────

def test_required_rights_text_does_not_bypass_container_check(tmp_path, monkeypatch):
    """required_rights text in paths.json must not satisfy the container CreateChild check."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["WriteDACL"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    # Embed CreateChild-sounding text in required_rights — must not bypass the state check.
    _paths(tmp_path, "postpatch-mutual-pair", extra={
        "required_rights": [
            "CreateChild:msDS-DelegatedManagedServiceAccount on container",
        ]
    })
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "CreateChild" in result.output
    assert "allow-unmapped-container" in result.output


def test_required_rights_text_does_not_bypass_dmsa_migration_check(tmp_path, monkeypatch):
    """required_rights text in paths.json must not substitute for proven dMSA migration rights."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=["WriteProperty:msDS-KeyCredentialLink"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"])
    _paths(tmp_path, "existing-dmsa-postpatch-mutual", extra={
        "required_rights": [
            "WriteProperty:msDS-ManagedAccountPrecededByLink",
            "WriteProperty:msDS-DelegatedMSAState",
        ]
    })
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "migration rights" in result.output
    assert "allow-unmapped-dmsa" in result.output


# ── allow-unmapped-container does not bypass unrelated checks ─────────────────

def test_allow_unmapped_container_does_not_bypass_target_rights_check(tmp_path, monkeypatch):
    """--allow-unmapped-container must not bypass the target-side WriteProperty check."""
    monkeypatch.chdir(tmp_path)
    # Container has no CreateChild, target has only one postpatch attr.
    _state(tmp_path, container_rights=[],
           target_writable_attrs=["msDS-SupersededManagedAccountLink"])
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-unmapped-container"]),
    )

    # Must still fail on target-side WriteProperty check even with container override.
    assert result.exit_code != 0, result.output
    assert "WriteProperty" in result.output or "target-side" in result.output


def test_allow_unmapped_dmsa_does_not_bypass_target_rights_check(tmp_path, monkeypatch):
    """--allow-unmapped-dmsa must not bypass the target-side WriteProperty check."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, dmsa_rights=[],
           target_writable_attrs=["msDS-SupersededManagedAccountLink"])
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-unmapped-dmsa"]),
    )

    assert result.exit_code != 0, result.output
    assert "WriteProperty" in result.output or "target-side" in result.output


# ── validate_dmsa_migration_rights direct unit tests ─────────────────────────

def test_validate_dmsa_migration_rights_generic_write_passes():
    """GenericWrite on dMSA must satisfy migration rights check."""
    from dmsa_reaper.cli import _validate_dmsa_migration_rights
    from dmsa_reaper.models import DmsaObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(principal_sid=_PRINCIPAL, right="GenericWrite", object_dn=_DMSA)
    dmsa = DmsaObject(dn=_DMSA, rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        dmsas=[dmsa],
        current_principal=Principal(sid=_PRINCIPAL),
    )
    warnings = _validate_dmsa_migration_rights(state, _DMSA, allow_unmapped_dmsa=False)
    assert warnings == []


def test_validate_dmsa_migration_rights_absent_raises():
    """dMSA absent from state.dmsas must raise when allow_unmapped_dmsa is False."""
    import typer
    from dmsa_reaper.cli import _validate_dmsa_migration_rights
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), dmsas=[])
    with pytest.raises(typer.BadParameter, match="state.dmsas"):
        _validate_dmsa_migration_rights(state, _DMSA, allow_unmapped_dmsa=False)


def test_validate_dmsa_migration_rights_absent_with_override_returns_warning():
    """dMSA absent from state.dmsas with allow_unmapped_dmsa must return a warning."""
    from dmsa_reaper.cli import _validate_dmsa_migration_rights
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), dmsas=[])
    warnings = _validate_dmsa_migration_rights(state, _DMSA, allow_unmapped_dmsa=True)
    assert warnings
    assert any("allow-unmapped-dmsa" in w for w in warnings)


def test_validate_container_dacl_control_absent_raises():
    """Container absent from state.containers must raise for dacl-container-escalate."""
    import typer
    from dmsa_reaper.cli import _validate_container_dacl_control
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), containers=[])
    with pytest.raises(typer.BadParameter, match="state.containers"):
        _validate_container_dacl_control(state, _CONTAINER, allow_unmapped_container=False)


def test_validate_target_dacl_control_absent_raises():
    """Target absent from state.targets must raise for dacl-target-escalate."""
    import typer
    from dmsa_reaper.cli import _validate_target_dacl_control
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), targets=[])
    with pytest.raises(typer.BadParameter, match="state.targets"):
        _validate_target_dacl_control(state, _TARGET, allow_unmapped_target=False)


def test_validate_target_dacl_control_lacking_rights_raises():
    """Target present in state but without DACL control rights must raise."""
    import typer
    from dmsa_reaper.cli import _validate_target_dacl_control
    from dmsa_reaper.models import Environment, MapState, Principal, Right, SchemaCache, TargetObject

    right = Right(principal_sid=_PRINCIPAL, right="WriteProperty:someAttr", object_dn=_TARGET)
    target = TargetObject(dn=_TARGET, rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        targets=[target],
        current_principal=Principal(sid=_PRINCIPAL),
    )
    with pytest.raises(typer.BadParameter, match="WriteDACL"):
        _validate_target_dacl_control(state, _TARGET, allow_unmapped_target=False)


# ── missing current_principal blocks confirmed execution ──────────────────────

def test_missing_principal_blocks_postpatch_container_check(tmp_path, monkeypatch):
    """Missing current_principal must block postpatch-mutual-pair confirmed execution."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild:dMSA"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           principal=None)
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "current_principal" in result.output
    assert "allow-unmapped-container" in result.output


def test_missing_principal_blocks_existing_dmsa_migration_check(tmp_path, monkeypatch):
    """Missing current_principal must block existing-dmsa-postpatch-mutual confirmed execution."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path,
           dmsa_rights=["GenericAll"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           principal=None)
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "current_principal" in result.output
    assert "allow-unmapped-dmsa" in result.output


def test_missing_principal_blocks_dacl_container_check(tmp_path, monkeypatch):
    """Missing current_principal must block dacl-container-escalate confirmed execution."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["WriteDACL"], principal=None)
    _paths(tmp_path, "dacl-container-escalate")
    _scope(tmp_path, allow_dacl=True)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET,
                      extra_args=["--chain", "legacy", "--allow-broad-dacl"]),
    )

    assert result.exit_code != 0, result.output
    assert "current_principal" in result.output
    assert "allow-unmapped-container" in result.output


def test_missing_principal_blocks_dacl_target_check(tmp_path, monkeypatch):
    """Missing current_principal must block dacl-target-escalate confirmed execution."""
    monkeypatch.chdir(tmp_path)
    # Container has CreateChild (from any SID) to pass container check, but
    # principal is None so both checks will fail. Container check fires first.
    _state(tmp_path, container_rights=["CreateChild"], target_rights=["WriteDACL"], principal=None)
    _paths(tmp_path, "dacl-target-escalate")
    _scope(tmp_path, allow_dacl=True)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, extra_args=[
            "--allow-broad-dacl", "--container-dn", _CONTAINER,
        ]),
    )

    assert result.exit_code != 0, result.output
    assert "current_principal" in result.output


def test_allow_unmapped_container_cannot_bypass_execution_identity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild:dMSA"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           principal=None)
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET,
                      extra_args=["--allow-unmapped-container", "--ops-dir", str(ops_dir)]),
    )

    assert result.exit_code != 0
    assert "fresh authenticated map" in result.output
    assert list(ops_dir.glob("OP-*.json")) == []


def test_allow_unmapped_dmsa_cannot_bypass_execution_identity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _state(tmp_path,
           dmsa_rights=["GenericAll"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           principal=None)
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)
    ops_dir = tmp_path / "ops"
    monkeypatch.setattr("dmsa_reaper.cli.bind", lambda _cfg: _MockConn())

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET,
                      extra_args=["--allow-unmapped-dmsa", "--ops-dir", str(ops_dir)]),
    )

    assert result.exit_code != 0
    assert "fresh authenticated map" in result.output
    assert list(ops_dir.glob("OP-*.json")) == []


def test_allow_unmapped_dmsa_does_not_bypass_missing_principal_for_container_check(tmp_path, monkeypatch):
    """--allow-unmapped-dmsa must NOT bypass the container's missing-principal check."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path, container_rights=["CreateChild:dMSA"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           principal=None)
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)

    result = _RUNNER.invoke(
        app,
        _confirm_args(tmp_path, target_dn=_TARGET, extra_args=["--allow-unmapped-dmsa"]),
    )

    # Container check fires first; --allow-unmapped-dmsa cannot bypass it.
    assert result.exit_code != 0, result.output
    assert "current_principal" in result.output
    assert "allow-unmapped-container" in result.output


# ── other-SID rights do not satisfy checks ───────────────────────────────────

def test_other_sid_container_rights_do_not_satisfy_createchild(tmp_path, monkeypatch):
    """CreateChild rights for a different SID must not satisfy the container check."""
    import typer
    from dmsa_reaper.cli import _check_container_create_rights
    from dmsa_reaper.models import ContainerObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(principal_sid=_OTHER_SID, right="CreateChild:dMSA",
                  object_dn=_CONTAINER)
    container = ContainerObject(dn=_CONTAINER, rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        containers=[container],
        current_principal=Principal(sid=_PRINCIPAL),
    )
    with pytest.raises(typer.BadParameter, match="no CreateChild rights"):
        _check_container_create_rights(state, _CONTAINER, allow_unmapped_container=False)


def test_other_sid_dmsa_rights_do_not_satisfy_migration_check(tmp_path, monkeypatch):
    """GenericAll for a different SID must not satisfy the dMSA migration check."""
    import typer
    from dmsa_reaper.cli import _validate_dmsa_migration_rights
    from dmsa_reaper.models import DmsaObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(principal_sid=_OTHER_SID, right="GenericAll", object_dn=_DMSA)
    dmsa = DmsaObject(dn=_DMSA, rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        dmsas=[dmsa],
        current_principal=Principal(sid=_PRINCIPAL),
    )
    with pytest.raises(typer.BadParameter, match="migration rights"):
        _validate_dmsa_migration_rights(state, _DMSA, allow_unmapped_dmsa=False)


def test_other_sid_target_rights_do_not_satisfy_dacl_control(tmp_path, monkeypatch):
    """WriteDACL for a different SID must not satisfy the target DACL control check."""
    import typer
    from dmsa_reaper.cli import _validate_target_dacl_control
    from dmsa_reaper.models import Environment, MapState, Principal, Right, SchemaCache, TargetObject

    right = Right(principal_sid=_OTHER_SID, right="WriteDACL", object_dn=_TARGET)
    target = TargetObject(dn=_TARGET, rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        targets=[target],
        current_principal=Principal(sid=_PRINCIPAL),
    )
    with pytest.raises(typer.BadParameter, match="WriteDACL"):
        _validate_target_dacl_control(state, _TARGET, allow_unmapped_target=False)


def test_other_sid_container_dacl_rights_do_not_satisfy_check(tmp_path, monkeypatch):
    """WriteDACL for a different SID must not satisfy the container DACL control check."""
    import typer
    from dmsa_reaper.cli import _validate_container_dacl_control
    from dmsa_reaper.models import ContainerObject, Environment, MapState, Principal, Right, SchemaCache

    right = Right(principal_sid=_OTHER_SID, right="WriteDACL", object_dn=_CONTAINER)
    container = ContainerObject(dn=_CONTAINER, rights=[right])
    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        containers=[container],
        current_principal=Principal(sid=_PRINCIPAL),
    )
    with pytest.raises(typer.BadParameter, match="WriteDACL"):
        _validate_container_dacl_control(state, _CONTAINER, allow_unmapped_container=False)


def test_require_current_principal_sid_missing_raises():
    """_require_current_principal_sid must raise when principal is None and override is False."""
    import typer
    from dmsa_reaper.cli import _require_current_principal_sid
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), current_principal=None)
    with pytest.raises(typer.BadParameter, match="current_principal"):
        _require_current_principal_sid(state, allow_override=False, override_flag="--allow-unmapped-container")


def test_require_current_principal_sid_missing_with_override_returns_none_and_warning():
    """_require_current_principal_sid must return (None, [warning]) when principal is None and override is True."""
    from dmsa_reaper.cli import _require_current_principal_sid
    from dmsa_reaper.models import Environment, MapState, SchemaCache

    state = MapState(environment=Environment(), schema_cache=SchemaCache(), current_principal=None)
    sid, warnings = _require_current_principal_sid(
        state, allow_override=True, override_flag="--allow-unmapped-container"
    )
    assert sid is None
    assert warnings
    assert any("allow-unmapped-container" in w for w in warnings)


def test_require_current_principal_sid_present_returns_sid():
    """_require_current_principal_sid must return (sid, []) when principal is present."""
    from dmsa_reaper.cli import _require_current_principal_sid
    from dmsa_reaper.models import Environment, MapState, Principal, SchemaCache

    state = MapState(
        environment=Environment(),
        schema_cache=SchemaCache(),
        current_principal=Principal(sid=_PRINCIPAL),
    )
    sid, warnings = _require_current_principal_sid(
        state, allow_override=False, override_flag="--allow-unmapped-container"
    )
    assert sid == _PRINCIPAL
    assert warnings == []


# ── CLI: other-SID postpatch-mutual-pair is blocked ───────────────────────────

def test_other_sid_container_rights_blocked_in_postpatch_cli(tmp_path, monkeypatch):
    """postpatch-mutual-pair must be blocked if container rights belong to a different SID."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path,
           container_rights=["CreateChild:dMSA"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           container_rights_sid=_OTHER_SID)
    _paths(tmp_path, "postpatch-mutual-pair")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "CreateChild" in result.output or "allow-unmapped-container" in result.output


def test_other_sid_dmsa_rights_blocked_in_existing_dmsa_cli(tmp_path, monkeypatch):
    """existing-dmsa-postpatch-mutual must be blocked if dMSA rights belong to a different SID."""
    monkeypatch.chdir(tmp_path)
    _state(tmp_path,
           dmsa_rights=["GenericAll"],
           target_writable_attrs=["msDS-SupersededManagedAccountLink",
                                   "msDS-SupersededServiceAccountState"],
           dmsa_rights_sid=_OTHER_SID)
    _paths(tmp_path, "existing-dmsa-postpatch-mutual")
    _scope(tmp_path)

    result = _RUNNER.invoke(app, _confirm_args(tmp_path, target_dn=_TARGET))

    assert result.exit_code != 0, result.output
    assert "migration rights" in result.output or "allow-unmapped-dmsa" in result.output
