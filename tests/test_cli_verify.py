from typer.testing import CliRunner

from dmsa_reaper.cli import app
from dmsa_reaper.models import Operation
from dmsa_reaper.ops.operation_log import load_operation, save_operation


def test_external_exit_zero_can_never_verify(tmp_path):
    ops_dir = tmp_path / "ops"
    save_operation(Operation(id="OP-0001", primitive="postpatch-mutual-pair"), ops_dir=ops_dir)

    result = CliRunner().invoke(app, [
        "verify",
        "--ops-dir", str(ops_dir),
        "--op", "OP-0001",
        "--mode", "external",
        "--external-argv", "true",
    ])

    assert result.exit_code != 0
    assert "external proof modes were removed" in result.output
    stored = load_operation("OP-0001", ops_dir=ops_dir)
    assert stored.verified_external is False
    assert stored.verified_ticket is False


def test_external_flags_are_absent_from_public_help():
    result = CliRunner().invoke(app, ["verify", "--help"])

    assert result.exit_code == 0
    assert "external-cmd" not in result.output
    assert "external-argv" not in result.output
    assert "evidence-file" not in result.output


def test_removed_framework_groups_are_absent_from_public_help():
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "│ campaign " not in result.output
    assert "│ ouroboros " not in result.output
    assert "│ proof " not in result.output
    assert "│ graph " not in result.output
