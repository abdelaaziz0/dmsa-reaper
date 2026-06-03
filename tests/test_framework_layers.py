from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import CheckStatus, MapState, Operation
from dmsa_reaper.ops.operation_log import load_operation, save_operation

RUNNER = CliRunner()
FIXTURE = Path(__file__).parent.parent / "docs" / "lab-fixture-dmsalab.json"


def _operation(tmp_path: Path, *, rolled_back: bool = False, ldap_verified: bool = False) -> Path:
    ops_dir = tmp_path / "ops"
    op = Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        path_id="P-0001",
        status="rolled-back" if rolled_back else "executed",
        created_dns=["CN=proof-dmsa,OU=Reaper,DC=corp,DC=local"],
        rollback_available=not rolled_back,
        rolled_back=rolled_back,
        rollback_verified=rolled_back,
        verified_ldap=ldap_verified,
        verified_external=False,
        metadata={
            "created_dmsa_sam": "proof-dmsa$",
            "target_dn": "CN=target.migrate,OU=Targets,DC=corp,DC=local",
            "path": {
                "required_rights": [
                    "CreateChild:dMSA",
                    "WriteProperty:msDS-SupersededManagedAccountLink",
                    "WriteProperty:msDS-SupersededServiceAccountState",
                ],
            },
            "password": "this-must-not-appear",
        },
    )
    if ldap_verified:
        op.metadata["ldap_verification"] = {"status": "verified", "ok": True}
    save_operation(op, ops_dir=ops_dir)
    return ops_dir


def _base_evidence(tmp_path: Path) -> Path:
    path = tmp_path / "base-proof.json"
    path.write_text(
        json.dumps({
            "type": "kerberos-base-proof",
            "operation_id": None,
            "principal": "reaper.low@CORP.LOCAL",
            "service": "cifs/dc.corp.local@CORP.LOCAL",
            "tool": "smbclient.py",
            "result": "success",
            "notes": "SYSVOL listed successfully",
        }),
        encoding="utf-8",
    )
    return path


def _dmsa_evidence(tmp_path: Path) -> Path:
    path = tmp_path / "dmsa-proof.json"
    path.write_text(
        json.dumps({
            "type": "kerberos-dmsa-proof",
            "operation_id": "OP-0001",
            "target_sam": "target.migrate",
            "created_dmsa_sam": "proof-dmsa$",
            "tool": "external-verifier",
            "result": "success",
            "evidence": {
                "principal": "proof-dmsa$@CORP.LOCAL",
                "service": "cifs/dc.corp.local",
                "timestamp": "2026-06-03T10:00:00Z",
            },
        }),
        encoding="utf-8",
    )
    return path


def test_badsuccessor_assess_finds_p0001():
    result = RUNNER.invoke(app, [
        "badsuccessor",
        "assess",
        "--state",
        str(FIXTURE),
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    p0001 = next(path for path in data["paths"] if path["path_id"] == "P-0001")
    assert p0001["primitive"] == "postpatch-mutual-pair"
    assert p0001["status"] == "executable"
    assert p0001["kerberos_proof_required"] is True


def test_badsuccessor_plan_contains_exact_ldap_writes():
    result = RUNNER.invoke(app, [
        "badsuccessor",
        "plan",
        "--state",
        str(FIXTURE),
        "--path",
        "P-0001",
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    attrs = {item["attribute"] for item in data["modified_attributes"]}
    assert "msDS-ManagedAccountPrecededByLink" in attrs
    assert "msDS-DelegatedMSAState" in attrs
    assert "msDS-SupersededManagedAccountLink" in attrs
    assert "msDS-SupersededServiceAccountState" in attrs
    assert data["ldap_writes_performed"] is False
    assert any("kerberos-dmsa-proof" in item for item in data["expected_kerberos_proof_requirements"])


def test_badsuccessor_plan_does_not_create_operation_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, [
        "badsuccessor",
        "plan",
        "--state",
        str(FIXTURE),
        "--path",
        "P-0001",
        "--json",
    ])

    assert result.exit_code == 0, result.output
    assert list((tmp_path / ".reaper" / "operations").glob("OP-*.json")) == []


def test_badsuccessor_report_marks_ldap_only_success_without_kerberos_claim(tmp_path):
    ops_dir = _operation(tmp_path, ldap_verified=True)

    result = RUNNER.invoke(app, [
        "badsuccessor",
        "report",
        "--ops-dir",
        str(ops_dir),
        "--op",
        "OP-0001",
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    lifecycle = data["operation_lifecycle"]
    assert lifecycle["ldap_verified"] is True
    assert lifecycle["external_verified"] is False
    assert data["kerberos"]["dmsa_proof_verified"] is False
    assert any("Kerberos proof" in item or "dMSA Kerberos proof" in item for item in lifecycle["limitations"])


def test_paths_only_badsuccessor_macro_filters_to_expected_primitives(tmp_path):
    paths_out = tmp_path / "paths.json"
    result = RUNNER.invoke(app, [
        "paths",
        "--state",
        str(FIXTURE),
        "--expand-targets",
        "--only",
        "badsuccessor",
        "--json",
        str(paths_out),
    ])

    assert result.exit_code == 0, result.output
    paths = json.loads(paths_out.read_text(encoding="utf-8"))
    assert paths
    assert {path["primitive"] for path in paths} <= {
        "postpatch-mutual-pair",
        "existing-dmsa-postpatch-mutual",
        "legacy-oneway-link",
        "existing-dmsa-legacy-link",
        "dacl-container-escalate",
        "dacl-target-escalate",
    }


def test_ouroboros_assess_current_fixture_is_partial_and_requires_proof():
    result = RUNNER.invoke(app, [
        "ouroboros",
        "assess",
        "--state",
        str(FIXTURE),
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["ouroboros_status"] == "partially-capable"
    assert data["ouroboros_capable"] is False
    assert any("kerberos-dmsa-proof" in item for item in data["ouroboros_required_proofs"])
    assert data["safety_constraints"]


def test_ouroboros_missing_kds_is_blocked(tmp_path):
    state = MapState.load(FIXTURE)
    state.environment.kds_root_key_status = CheckStatus.absent
    state.environment.has_kds_root_key = False
    out = tmp_path / "state.json"
    state.save(out)

    result = RUNNER.invoke(app, [
        "ouroboros",
        "assess",
        "--state",
        str(out),
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["ouroboros_status"] == "blocked"
    assert any("KDS root key" in blocker for blocker in data["ouroboros_blockers"])


def test_ouroboros_base_proof_does_not_mark_external_verified(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _base_evidence(tmp_path)

    result = RUNNER.invoke(app, [
        "ouroboros",
        "verify",
        "--ops-dir",
        str(ops_dir),
        "--op",
        "OP-0001",
        "--evidence-file",
        str(evidence),
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert data["verified"] is False
    assert stored.verified_external is False
    assert stored.metadata["kerberos_base_check"]["type"] == "kerberos-base-proof"


def test_ouroboros_dmsa_proof_marks_external_verified(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _dmsa_evidence(tmp_path)

    result = RUNNER.invoke(app, [
        "ouroboros",
        "verify",
        "--ops-dir",
        str(ops_dir),
        "--op",
        "OP-0001",
        "--evidence-file",
        str(evidence),
        "--json",
    ])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert data["verified"] is True
    assert stored.verified_external is True
    assert stored.metadata["external_verification"]["type"] == "kerberos-dmsa-proof"


def test_ouroboros_dmsa_proof_after_rollback_is_rejected(tmp_path):
    ops_dir = _operation(tmp_path, rolled_back=True)
    evidence = _dmsa_evidence(tmp_path)

    result = RUNNER.invoke(app, [
        "ouroboros",
        "verify",
        "--ops-dir",
        str(ops_dir),
        "--op",
        "OP-0001",
        "--evidence-file",
        str(evidence),
    ])

    assert result.exit_code != 0
    assert "rolled-back" in result.output


def test_operation_report_excludes_secrets_and_marks_kerberos_absent(tmp_path):
    ops_dir = _operation(tmp_path, ldap_verified=True)

    result = RUNNER.invoke(app, [
        "report",
        "--ops-dir",
        str(ops_dir),
        "--op",
        "OP-0001",
        "--format",
        "json",
    ])

    assert result.exit_code == 0, result.output
    assert "this-must-not-appear" not in result.output
    data = json.loads(result.output)
    assert data["secrets_logged"] is False
    assert data["kerberos"]["dmsa_proof_verified"] is False
    assert data["ldap_artifacts"]["modified_attributes"] == []
