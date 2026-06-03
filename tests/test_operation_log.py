import json
import os
import time
from pathlib import Path

import pytest

from dmsa_reaper.models import AttributeChange, Operation
from dmsa_reaper.ops.operation_log import (
    _best_effort_lock,
    load_operation,
    new_operation,
    save_operation,
)


def test_operation_log_created(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    op = new_operation("postpatch-mutual-pair", "P-0001")
    path = Path(".reaper/operations") / f"{op.id}.json"
    assert path.exists()
    loaded = load_operation(op.id)
    assert loaded.primitive == "postpatch-mutual-pair"


def test_operation_ids_are_collision_resistant(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ids = {new_operation("postpatch-mutual-pair").id for _ in range(200)}
    assert len(ids) == 200
    assert all(op_id.startswith("OP-") for op_id in ids)


def test_save_operation_writes_valid_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    op = Operation(id="OP-0001", primitive="postpatch-mutual-pair")
    save_operation(op)
    path = Path(".reaper/operations") / "OP-0001.json"
    assert json.loads(path.read_text(encoding="utf-8"))["id"] == "OP-0001"


def test_interrupted_temp_file_does_not_corrupt_existing_operation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    op = Operation(id="OP-0001", primitive="postpatch-mutual-pair", status="planned")
    save_operation(op)
    tmp = Path(".reaper/operations") / ".OP-0001.stale.tmp"
    tmp.write_text("{not json", encoding="utf-8")
    loaded = load_operation("OP-0001")
    assert loaded.status == "planned"


def test_stale_operation_log_lock_is_removed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ops_dir = Path(".reaper/operations")
    ops_dir.mkdir(parents=True)
    lock = ops_dir / ".operation_log.lock"
    lock.write_text(str(os.getpid()), encoding="ascii")
    old = time.time() - 3600
    os.utime(lock, (old, old))

    save_operation(Operation(id="OP-0001", primitive="postpatch-mutual-pair"))

    assert not lock.exists()
    assert load_operation("OP-0001").primitive == "postpatch-mutual-pair"


def test_live_recent_operation_log_lock_blocks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ops_dir = Path(".reaper/operations")
    ops_dir.mkdir(parents=True)
    lock = ops_dir / ".operation_log.lock"
    lock.write_text(str(os.getpid()), encoding="ascii")

    with pytest.raises(RuntimeError, match="operation log lock is busy"):
        with _best_effort_lock(ops_dir, wait_seconds=0):
            pass

    lock.unlink()


def test_load_operation_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    try:
        load_operation("../OP-0001")
    except ValueError as exc:
        assert "invalid operation id" in str(exc)
    else:
        raise AssertionError("load_operation accepted path traversal")


def test_operation_log_preserves_bytes_as_base64(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    op = Operation(
        id="OP-0001",
        primitive="postpatch-mutual-pair",
        changed_attrs=[
            AttributeChange(
                dn="CN=x,DC=corp,DC=local",
                attribute="unicodePwd",
                before=[b"\x00\xff"],
                after=[b"abc"],
                mode="replace",
            )
        ],
    )
    path = Path(".reaper/operations") / f"{op.id}.json"
    path.parent.mkdir(parents=True)
    path.write_text(op.model_dump_json(indent=2), encoding="utf-8")

    loaded = load_operation(op.id)

    assert loaded.changed_attrs[0].before[0].type == "bytes"
    assert loaded.changed_attrs[0].before[0].value == "AP8="
    assert loaded.changed_attrs[0].before_python() == [b"\x00\xff"]


def test_old_operation_log_missing_new_semantic_fields_loads_safely(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = Path(".reaper/operations") / "OP-0001.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({
            "id": "OP-0001",
            "primitive": "postpatch-mutual-pair",
            "verified": True,
            "verified_external": False,
        }),
        encoding="utf-8",
    )

    loaded = load_operation("OP-0001")

    assert loaded.verified is True
    assert loaded.verified_ldap is False
    assert loaded.rolled_back is False
    assert loaded.rollback_verified is False
    assert loaded.ldap_verified_at is None
