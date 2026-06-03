from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import Operation
from dmsa_reaper.ops.operation_log import load_operation, save_operation

RUNNER = CliRunner()


def _operation(tmp_path: Path, *, rolled_back: bool = False) -> Path:
    ops_dir = tmp_path / "ops"
    op = Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        status="rolled-back" if rolled_back else "executed",
        created_dns=["CN=proof-dmsa,OU=Reaper,DC=corp,DC=local"],
        rollback_available=not rolled_back,
        rolled_back=rolled_back,
        metadata={
            "created_dmsa_sam": "proof-dmsa$",
            "target_dn": "CN=target.migrate,OU=Targets,DC=corp,DC=local",
        },
    )
    save_operation(op, ops_dir=ops_dir)
    return ops_dir


def _evidence(tmp_path: Path, **overrides) -> Path:
    data = {
        "type": "kerberos-dmsa-proof",
        "operation_id": "OP-0001",
        "target_sam": "target.migrate",
        "created_dmsa_sam": "proof-dmsa$",
        "tool": "external",
        "evidence": {
            "ticket_cache_path": "/tmp/proof.ccache",
            "principal": "proof-dmsa$@CORP.LOCAL",
            "service": "cifs/dc.corp.local",
            "timestamp": "2026-06-02T10:00:00Z",
        },
    }
    data.update(overrides)
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _base_evidence(tmp_path: Path, **overrides) -> Path:
    data = {
        "type": "kerberos-base-proof",
        "operation_id": None,
        "principal": "reaper.low@CORP.LOCAL",
        "service": "cifs/dc.corp.local@CORP.LOCAL",
        "tool": "smbclient.py",
        "result": "success",
        "notes": "SYSVOL listed successfully",
    }
    data.update(overrides)
    path = tmp_path / "base-proof.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({
            "domain": "corp.local",
            "allowedOUs": ["OU=Reaper,DC=corp,DC=local"],
            "allowedTargets": ["CN=target.migrate,OU=Targets,DC=corp,DC=local"],
            "requireConfirmString": True,
        }),
        encoding="utf-8",
    )
    return path


def test_evidence_file_marks_external_verified_and_records_hash(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _evidence(tmp_path)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code == 0, result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    meta = stored.metadata["external_verification"]
    assert stored.verified_external is True
    assert stored.external_verified_at is not None
    assert meta["ok"] is True
    assert meta["evidence_sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert "ticket_cache_path" in meta["evidence"]


def test_base_proof_does_not_mark_operation_externally_verified(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _base_evidence(tmp_path)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code == 0, result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert stored.verified_external is False
    assert "external_verification" not in stored.metadata
    assert stored.metadata["kerberos_base_check"]["type"] == "kerberos-base-proof"
    assert "verified_external=false" in result.output


def test_evidence_wrong_operation_id_rejected(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _evidence(tmp_path, operation_id="OP-other")

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code != 0
    assert "operation_id" in result.output


def test_evidence_mismatched_target_rejected(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _evidence(tmp_path, target_sam="administrator")

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code != 0
    assert "target_sam" in result.output


def test_evidence_secret_looking_fields_rejected(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _evidence(tmp_path)
    data = json.loads(evidence.read_text())
    data["evidence"]["raw_ticket"] = "A" * 120
    evidence.write_text(json.dumps(data), encoding="utf-8")

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code != 0
    assert "secret-looking" in result.output


def test_dmsa_evidence_rejected_after_rollback(tmp_path):
    ops_dir = _operation(tmp_path, rolled_back=True)
    evidence = _evidence(tmp_path)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code != 0
    assert "rolled-back" in result.output


def test_evidence_mismatched_dmsa_sam_rejected(tmp_path):
    ops_dir = _operation(tmp_path)
    evidence = _evidence(tmp_path, created_dmsa_sam="other-dmsa$")

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--evidence-file", str(evidence),
    ])

    assert result.exit_code != 0
    assert "created_dmsa_sam" in result.output


def test_adapter_dry_run_renders_command_without_executing(tmp_path):
    ops_dir = _operation(tmp_path)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--kerberos-adapter", "external",
        "--adapter-command", "echo {operation_id} {created_dmsa_sam}",
        "--adapter-dry-run",
    ])

    assert result.exit_code == 0, result.output
    assert "OP-0001" in result.output
    assert "proof-dmsa$" in result.output


def test_adapter_confirm_requires_lab_flag(tmp_path):
    ops_dir = _operation(tmp_path)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--kerberos-adapter", "external",
        "--adapter-command", "echo {operation_id}",
    ])

    assert result.exit_code != 0
    assert "lab-unsafe-kerberos-proof" in result.output


def test_adapter_output_parser_accepts_structured_success_marker(tmp_path):
    ops_dir = _operation(tmp_path)
    scope = _scope(tmp_path)
    evidence = _evidence(tmp_path)
    script = tmp_path / "emit_proof.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"print(Path({str(evidence)!r}).read_text())\n",
        encoding="utf-8",
    )
    script.chmod(0o755)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--kerberos-adapter", "external",
        "--adapter-command", str(script),
        "--scope", str(scope),
        "--confirm-string", "corp.local",
        "--lab-unsafe-kerberos-proof",
    ])

    assert result.exit_code == 0, result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert stored.verified_external is True
    assert stored.metadata["external_verification"]["adapter"]["name"] == "external"


def test_adapter_failure_records_dmsa_failure_class_without_raw_output(tmp_path):
    ops_dir = _operation(tmp_path)
    scope = _scope(tmp_path)
    script = tmp_path / "fail_proof.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('Kerberos SessionError: KRB_ERR_GENERIC', file=sys.stderr)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--kerberos-adapter", "external",
        "--adapter-command", str(script),
        "--scope", str(scope),
        "--confirm-string", "corp.local",
        "--lab-unsafe-kerberos-proof",
    ])

    assert result.exit_code != 0
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    adapter = stored.metadata["external_adapter"]
    assert adapter["failure_class"] == "kerberos-dmsa-proof-failed"
    assert "stderr" not in adapter
    assert "stdout" not in adapter


def test_adapter_cannot_run_after_rollback(tmp_path):
    ops_dir = _operation(tmp_path, rolled_back=True)

    result = RUNNER.invoke(app, [
        "verify",
        "--mode", "external",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--kerberos-adapter", "external",
        "--adapter-command", "echo {operation_id}",
        "--adapter-dry-run",
    ])

    assert result.exit_code != 0
    assert "rolled-back" in result.output
