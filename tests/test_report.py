from pathlib import Path

from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import Operation
from dmsa_reaper.ops.operation_log import save_operation


def test_root_report_marks_ldap_only_as_incomplete(tmp_path: Path):
    ops_dir = tmp_path / "ops"
    operation = Operation(
        id="OP-20260604-deadbeef",
        primitive="postpatch-mutual-pair",
        status="executed",
        verified_ldap=True,
        scope_file_hash="abc123",
        metadata={"ldap_verification": {"status": "verified", "ok": True}},
    )
    save_operation(operation, ops_dir=ops_dir)
    out = tmp_path / "report.md"

    result = CliRunner().invoke(app, [
        "report",
        "--op", operation.id,
        "--ops-dir", str(ops_dir),
        "--format", "markdown",
        "--out", str(out),
    ])

    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "Full BadSuccessor success: `false`" in text
    assert "Scope file hash: `abc123`" in text
