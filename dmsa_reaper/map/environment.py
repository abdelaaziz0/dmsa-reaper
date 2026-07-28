from __future__ import annotations

from ldap3 import Connection

from dmsa_reaper.ldap.rootdse import read_rootdse
from dmsa_reaper.map.kds import kds_root_key_status
from dmsa_reaper.models import CheckStatus, Environment, SchemaCache


def compute_dmsa_capable_status(
    dmsa_schema_status: CheckStatus,
    server_2025_dc_status: CheckStatus,
    kds_status: CheckStatus,
) -> CheckStatus:
    prereqs = (dmsa_schema_status, server_2025_dc_status, kds_status)
    if all(status == CheckStatus.present for status in prereqs):
        return CheckStatus.present
    if any(status == CheckStatus.absent for status in prereqs):
        return CheckStatus.absent
    return CheckStatus.unknown


def detect_server_2025_dcs(conn: Connection, default_nc: str) -> list[dict]:
    ok = conn.search(
        search_base=default_nc,
        search_filter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        attributes=["dNSHostName", "operatingSystem", "operatingSystemVersion"],
    )
    if not ok:
        raise RuntimeError("domain controller discovery failed")
    dcs: list[dict] = []
    for e in conn.entries:
        os_name = str(e.operatingSystem.value) if "operatingSystem" in e else ""
        version = str(e.operatingSystemVersion.value) if "operatingSystemVersion" in e else ""
        is_2025 = "2025" in os_name or version.startswith("10.0 (26100")
        dcs.append({
            "dnsHostName": str(e.dNSHostName.value) if "dNSHostName" in e else None,
            "operatingSystem": os_name,
            "operatingSystemVersion": version,
            "isServer2025": is_2025,
        })
    return dcs


def build_environment(conn: Connection, domain: str | None, schema_cache: SchemaCache) -> Environment:
    root = read_rootdse(conn)
    default_nc = root["defaultNamingContext"]
    config_nc = root["configurationNamingContext"]
    schema_nc = root["schemaNamingContext"]

    if not default_nc or not config_nc or not schema_nc:
        raise RuntimeError("RootDSE missing required naming contexts")

    try:
        dcs = detect_server_2025_dcs(conn, default_nc)
        server_2025_dc_status = (
            CheckStatus.present if any(dc["isServer2025"] for dc in dcs) else CheckStatus.absent
        )
    except Exception:
        dcs = []
        server_2025_dc_status = CheckStatus.unknown

    kds_status = kds_root_key_status(conn, config_nc)
    if schema_cache.dmsa_class_guid_resolved:
        dmsa_schema_status = CheckStatus.present
    elif schema_cache.dmsa_class_guid:
        dmsa_schema_status = CheckStatus.unknown
    else:
        dmsa_schema_status = CheckStatus.absent
    capable_status = compute_dmsa_capable_status(
        dmsa_schema_status,
        server_2025_dc_status,
        kds_status,
    )

    return Environment(
        domain=domain,
        default_nc=default_nc,
        config_nc=config_nc,
        schema_nc=schema_nc,
        dmsa_schema_status=dmsa_schema_status,
        server_2025_dc_status=server_2025_dc_status,
        kds_root_key_status=kds_status,
        dmsa_capable_status=capable_status,
    )
