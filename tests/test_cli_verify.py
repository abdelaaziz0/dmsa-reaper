import hashlib

from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import Operation
from dmsa_reaper.ops.operation_log import load_operation, save_operation


def test_verify_external_shell_blocked_without_explicit_allow(tmp_path):
    ops_dir = tmp_path / "ops"
    save_operation(Operation(id="OP-0001", primitive="postpatch-mutual-pair"), ops_dir=ops_dir)

    result = CliRunner().invoke(app, [
        "verify",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--mode", "external",
        "--external-cmd", "true",
    ])

    assert result.exit_code != 0
    assert "--allow-shell-external" in result.output


def _external_script(tmp_path):
    script = tmp_path / "emit_external.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('external ok')\n"
        "print('external warning', file=sys.stderr)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_verify_external_argv_stores_hashes_and_lengths_by_default(tmp_path):
    ops_dir = tmp_path / "ops"
    save_operation(Operation(id="OP-0001", primitive="postpatch-mutual-pair"), ops_dir=ops_dir)
    script = _external_script(tmp_path)

    result = CliRunner().invoke(app, [
        "verify",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--mode", "external",
        "--external-argv", str(script),
    ])

    assert result.exit_code == 0
    op = load_operation("OP-0001", ops_dir=ops_dir)
    meta = op.metadata["external_verification"]
    assert meta["exit_code"] == 0
    assert meta["stdout_length"] == len("external ok\n".encode())
    assert meta["stderr_length"] == len("external warning\n".encode())
    assert meta["stdout_sha256"] == hashlib.sha256(b"external ok\n").hexdigest()
    assert meta["stderr_sha256"] == hashlib.sha256(b"external warning\n").hexdigest()
    assert "stdout" not in meta
    assert "stderr" not in meta


def test_verify_external_argv_stores_full_output_when_requested(tmp_path):
    ops_dir = tmp_path / "ops"
    save_operation(Operation(id="OP-0001", primitive="postpatch-mutual-pair"), ops_dir=ops_dir)
    script = _external_script(tmp_path)

    result = CliRunner().invoke(app, [
        "verify",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--mode", "external",
        "--external-argv", str(script),
        "--store-external-output",
    ])

    assert result.exit_code == 0
    op = load_operation("OP-0001", ops_dir=ops_dir)
    meta = op.metadata["external_verification"]
    assert meta["stdout"] == "external ok\n"
    assert meta["stderr"] == "external warning\n"
