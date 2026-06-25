from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def new_campaign_id() -> str:
    return f"CMP-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(4)}"


def campaign_step(name: str, status: str, **fields: Any) -> dict[str, Any]:
    step = {"name": name, "status": status, "timestamp": utc_now_iso()}
    step.update({key: value for key, value in fields.items() if value is not None})
    return step


def final_status(
    *,
    ldap_verified: bool,
    kerberos_base_ready: bool,
    full_success: bool,
    failed: bool,
    dry_run: bool,
    rollback_status: str | None = None,
    rollback_verified: bool = False,
) -> str:
    if failed and rollback_status == "rolled-back" and rollback_verified:
        return "failed-rolled-back"
    if failed:
        return "failed"
    if dry_run:
        return "dry-run-complete"
    if full_success:
        return "full-badsuccessor-success"
    if ldap_verified and kerberos_base_ready:
        return "ldap-verified-kerberos-base-ready-dmsa-proof-missing"
    if ldap_verified:
        return "ldap-verified-kerberos-proof-missing"
    if rollback_status == "rolled-back" and rollback_verified:
        return "rolled-back"
    return "ldap-not-verified"


def campaign_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "campaign_id": payload.get("campaign_id"),
        "profile": payload.get("profile"),
        "domain": payload.get("domain"),
        "dc": payload.get("dc"),
        "operation_id": payload.get("operation_id"),
        "ldap_verified": payload.get("ldap_verified", False),
        "kerberos_base_ready": payload.get("kerberos_base_ready", False),
        "kerberos_dmsa_verified": payload.get("kerberos_dmsa_verified", False),
        "full_badsuccessor_success": payload.get("full_badsuccessor_success", False),
        "rollback_status": payload.get("rollback_status"),
        "rollback_verified": payload.get("rollback_verified", False),
        "final_status": payload.get("final_status"),
        "step_count": len(payload.get("steps") or []),
    }


def campaign_markdown(payload: dict[str, Any]) -> str:
    summary = campaign_summary(payload)
    lines = [
        f"# dMSA-Reaper Campaign {summary['campaign_id']}",
        "",
        f"- Profile: `{summary['profile']}`",
        f"- Domain: `{summary['domain']}`",
        f"- DC: `{summary['dc']}`",
        f"- Operation ID: `{summary['operation_id']}`",
        f"- LDAP verified: `{str(summary['ldap_verified']).lower()}`",
        f"- Kerberos base ready: `{str(summary['kerberos_base_ready']).lower()}`",
        f"- Kerberos dMSA proof verified: `{str(summary['kerberos_dmsa_verified']).lower()}`",
        f"- Full BadSuccessor success: `{str(summary['full_badsuccessor_success']).lower()}`",
        f"- Rollback status: `{summary['rollback_status']}`",
        f"- Rollback verified: `{str(summary['rollback_verified']).lower()}`",
        f"- Final status: `{summary['final_status']}`",
        "",
        "## Steps",
        "",
    ]
    for step in payload.get("steps") or []:
        artifact = f" ({step['artifact']})" if step.get("artifact") else ""
        lines.append(f"- `{step['name']}`: `{step['status']}`{artifact}")
    lines.extend([
        "",
        "## Limitations",
        "",
        "- LDAP verification proves directory state only.",
        "- Full BadSuccessor success requires operation-bound kerberos-dmsa-proof evidence.",
        "- Raw tickets, keys, hashes, passwords, and session keys are not stored.",
    ])
    return "\n".join(lines) + "\n"
