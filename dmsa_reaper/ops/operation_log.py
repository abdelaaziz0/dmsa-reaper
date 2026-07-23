from __future__ import annotations

import os
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from dmsa_reaper import __version__
from dmsa_reaper.models import Operation

DEFAULT_OPS_DIR = Path(".reaper/operations")
OPS_DIR_ENV = "DMSA_REAPER_OPS_DIR"
LOCK_STALE_SECONDS = 300
LOCK_WAIT_SECONDS = 5.0
_OP_ID_RE = re.compile(r"^OP-(?:\d{4}|\d{8}-[0-9a-f]{8}|[0-9a-f]{8,32})$")
_configured_ops_dir: Path | None = None


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def configure_ops_dir(path: str | Path | None) -> None:
    """Set the process-local operation directory used by CLI commands."""
    global _configured_ops_dir
    _configured_ops_dir = Path(path) if path is not None else None


def get_ops_dir(ops_dir: str | Path | None = None) -> Path:
    if ops_dir is not None:
        return Path(ops_dir)
    if _configured_ops_dir is not None:
        return _configured_ops_dir
    env_value = os.environ.get(OPS_DIR_ENV)
    if env_value:
        return Path(env_value)
    return DEFAULT_OPS_DIR


def ensure_ops_dir(ops_dir: str | Path | None = None) -> Path:
    path = get_ops_dir(ops_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_operation_id(op_id: str) -> str:
    if not _OP_ID_RE.fullmatch(op_id):
        raise ValueError(f"invalid operation id: {op_id!r}")
    return op_id


def next_operation_id(ops_dir: str | Path | None = None) -> str:
    directory = ensure_ops_dir(ops_dir)
    for _ in range(32):
        op_id = f"OP-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(4)}"
        if not (directory / f"{op_id}.json").exists():
            return op_id
    raise RuntimeError("could not allocate a collision-free operation id")


def operation_path(op_id: str, ops_dir: str | Path | None = None) -> Path:
    op_id = validate_operation_id(op_id)
    directory = ensure_ops_dir(ops_dir).resolve()
    path = (directory / f"{op_id}.json").resolve()
    if path.parent != directory:
        raise ValueError(f"invalid operation path for id: {op_id!r}")
    return path


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _lock_is_stale(lock_path: Path, *, stale_seconds: int = LOCK_STALE_SECONDS) -> bool:
    try:
        raw_pid = lock_path.read_text(encoding="ascii").strip()
    except OSError:
        raw_pid = ""
    if raw_pid:
        try:
            pid = int(raw_pid)
        except ValueError:
            pid = 0
        if pid and not _pid_is_alive(pid):
            return True
    try:
        age = time.time() - lock_path.stat().st_mtime
    except OSError:
        return True
    return age > stale_seconds


def _remove_stale_lock(lock_path: Path) -> bool:
    if not lock_path.exists() or not _lock_is_stale(lock_path):
        return False
    try:
        lock_path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


@contextmanager
def _best_effort_lock(directory: Path, *, wait_seconds: float = LOCK_WAIT_SECONDS) -> Iterator[None]:
    lock_path = directory / ".operation_log.lock"
    deadline = time.monotonic() + wait_seconds
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if _remove_stale_lock(lock_path):
                continue
            if time.monotonic() >= deadline:
                raise RuntimeError(f"operation log lock is busy: {lock_path}") from None
            time.sleep(0.05)
    try:
        os.write(fd, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(fd)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _fsync_parent(directory: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_operation(op: Operation, ops_dir: str | Path | None = None) -> None:
    path = operation_path(op.id, ops_dir)
    directory = path.parent
    op.updated_at = _utc_now_iso()
    payload = op.model_dump_json(indent=2)

    with _best_effort_lock(directory):
        fd, tmp_name = tempfile.mkstemp(prefix=f".{op.id}.", suffix=".tmp", dir=directory)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            _fsync_parent(directory)
        except Exception:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
            raise

    # Keep run artifacts separate from the indexed operation journal.  This
    # snapshot is also the durable anchor for ticket/cleanup artifacts.
    run_dir = directory.parent / "runs" / op.id
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    run_path = run_dir / "operation.json"
    fd, tmp_name = tempfile.mkstemp(prefix=".operation.", suffix=".tmp", dir=run_dir)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, run_path)
        os.chmod(run_path, 0o600)
        _fsync_parent(run_dir)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def load_operation(op_id: str, ops_dir: str | Path | None = None) -> Operation:
    path = operation_path(op_id, ops_dir)
    return Operation.model_validate_json(path.read_text(encoding="utf-8"))


def new_operation(
    primitive: str,
    path_id: str | None = None,
    metadata: dict | None = None,
    scope_file_hash: str | None = None,
    ops_dir: str | Path | None = None,
) -> Operation:
    op = Operation(
        id=next_operation_id(ops_dir),
        primitive=primitive,
        path_id=path_id,
        metadata=metadata or {},
        tool_version=__version__,
        scope_file_hash=scope_file_hash,
    )
    save_operation(op, ops_dir)
    return op
