from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from dmsa_reaper.ops.campaign import utc_now_iso
from dmsa_reaper.ops.external_proof import BASE_PROOF_TYPE


class ProofCollectionError(ValueError):
    pass


_DEFAULT_PRINCIPAL_RE = re.compile(r"^Default principal:\s*(?P<principal>\S+)", re.MULTILINE)
_SERVICE_RE = re.compile(r"\b(?P<service>(?:krbtgt|cifs)/[^\s]+(?:@[A-Za-z0-9_.-]+)?)")


def parse_klist_output(text: str, *, preferred_service: str | None = None) -> dict[str, str | None]:
    principal_match = _DEFAULT_PRINCIPAL_RE.search(text)
    principal = principal_match.group("principal") if principal_match else None
    services = [match.group("service") for match in _SERVICE_RE.finditer(text)]
    tgt_present = any(service.lower().startswith("krbtgt/") for service in services)
    selected_service = None
    if preferred_service:
        preferred_lower = _service_compare_key(preferred_service)
        selected_service = next(
            (service for service in services if _service_compare_key(service) == preferred_lower),
            None,
        )
    if selected_service is None:
        selected_service = next(
            (service for service in services if service.lower().startswith("cifs/")),
            None,
        )
    if selected_service is None and services:
        selected_service = services[0]
    realm = None
    if principal and "@" in principal:
        realm = principal.rsplit("@", 1)[1].upper()
    elif selected_service and "@" in selected_service:
        realm = selected_service.rsplit("@", 1)[1].upper()
    return {
        "principal": principal,
        "service": selected_service,
        "realm": realm,
        "tgt_present": str(tgt_present).lower(),
        "service_ticket_present": str(selected_service is not None).lower(),
    }


def collect_base_proof_from_klist(
    *,
    ccache: Path,
    service: str | None = None,
    krb5_config: Path | None = None,
    dc_host: str | None = None,
    klist_bin: str = "klist",
) -> dict[str, Any]:
    if not ccache.exists():
        raise ProofCollectionError(f"ccache does not exist: {ccache}")
    env = os.environ.copy()
    env["KRB5CCNAME"] = str(ccache)
    if krb5_config is not None:
        env["KRB5_CONFIG"] = str(krb5_config)
    proc = subprocess.run(
        [klist_bin, "-e"],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise ProofCollectionError(f"klist failed with exit code {proc.returncode}")
    parsed = parse_klist_output(proc.stdout, preferred_service=service)
    if not parsed.get("principal"):
        raise ProofCollectionError("could not determine TGT principal from ccache metadata")
    if parsed.get("tgt_present") != "true":
        raise ProofCollectionError("ccache does not contain a TGT")
    if service and parsed.get("service_ticket_present") != "true":
        raise ProofCollectionError(f"ccache does not contain requested service ticket: {service}")
    return build_base_proof(
        parsed,
        ccache=ccache,
        krb5_config=krb5_config,
        dc_host=dc_host,
        requested_service=service,
    )


def build_base_proof(
    parsed: dict[str, str | None],
    *,
    ccache: Path | None = None,
    krb5_config: Path | None = None,
    dc_host: str | None = None,
    requested_service: str | None = None,
) -> dict[str, Any]:
    proof: dict[str, Any] = {
        "type": BASE_PROOF_TYPE,
        "operation_id": None,
        "principal": parsed.get("principal"),
        "service": parsed.get("service"),
        "realm": parsed.get("realm"),
        "tool": "klist",
        "result": "success",
        "timestamp": utc_now_iso(),
        "tickets": {
            "tgt_present": parsed.get("tgt_present") == "true",
            "service_ticket_present": parsed.get("service_ticket_present") == "true",
        },
        "environment": {
            "ccache_style": _ccache_style(str(ccache)) if ccache else None,
            "ccache_exists": ccache.exists() if ccache else None,
            "krb5_config": str(krb5_config) if krb5_config else os.environ.get("KRB5_CONFIG"),
            "dc_host": dc_host,
            "requested_service": requested_service,
        },
        "notes": "Kerberos cache metadata collected without storing raw ticket material.",
    }
    proof["proof_sha256"] = _proof_hash(proof)
    return proof


def _service_compare_key(value: str) -> str:
    lowered = value.lower()
    return lowered.split("@", 1)[0]


def _ccache_style(value: str | None) -> str:
    if not value:
        return "unset"
    if value.startswith("FILE:"):
        return "file-prefix"
    if value.startswith("DIR:"):
        return "dir"
    if value.startswith("KEYRING:"):
        return "keyring"
    return "raw-file-path"


def _proof_hash(proof: dict[str, Any]) -> str:
    payload = {key: value for key, value in proof.items() if key != "proof_sha256"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
