from __future__ import annotations

from ldap3 import Connection

from dmsa_reaper.acl.enrichment import compute_effective_rights
from dmsa_reaper.acl.parser import parse_security_descriptor
from dmsa_reaper.ldap.query import search_with_sd
from dmsa_reaper.models import ContainerObject, Principal, SchemaCache
from dmsa_reaper.map.principal import principal_sid_set
from dmsa_reaper.utils import bytes_to_guid_le

_MISSING_SD_WARNING = "nTSecurityDescriptor missing or unreadable; effective-rights result is incomplete"


def enumerate_containers(
    conn: Connection,
    default_nc: str,
    sdflags: int,
    principal: Principal | None = None,
    schema_cache: SchemaCache | None = None,
    container_filter: str | None = None,
) -> list[ContainerObject]:
    base_filter = "(|(objectClass=organizationalUnit)(objectClass=container))"
    ldap_filter = f"(&{base_filter}{container_filter})" if container_filter else base_filter
    entries = search_with_sd(
        conn,
        default_nc,
        ldap_filter,
        ["distinguishedName", "objectGUID", "objectClass"],
        sdflags,
    )
    psid = principal.sid if principal else ""
    psids = principal_sid_set(principal)
    dmsa_guid = schema_cache.dmsa_class_guid if schema_cache else None
    attr_guids = schema_cache.attr_guids if schema_cache else {}

    out: list[ContainerObject] = []
    for e in entries:
        raw_sd = (
            e["nTSecurityDescriptor"].raw_values[0]
            if "nTSecurityDescriptor" in e and e["nTSecurityDescriptor"].raw_values
            else None
        )
        psd = parse_security_descriptor(raw_sd)
        parse_warnings = list(psd.parse_warnings)
        if raw_sd is None:
            parse_warnings.append(_MISSING_SD_WARNING)
        object_classes = list(e.objectClass.values) if "objectClass" in e else []
        dn = str(e.distinguishedName.value)

        rights, _ = compute_effective_rights(
            psd.aces,
            psid,
            psids,
            dn,
            psd.owner_sid,
            dmsa_class_guid=dmsa_guid,
            attr_guids=attr_guids,
            side="any",
            null_dacl=psd.null_dacl,
        )
        if psd.parse_failed:
            rights = []

        guid_raw = (
            e["objectGUID"].raw_values[0]
            if "objectGUID" in e and e["objectGUID"].raw_values
            else None
        )
        out.append(ContainerObject(
            dn=dn,
            object_guid=(bytes_to_guid_le(bytes(guid_raw)) if guid_raw and len(guid_raw) == 16 else None),
            object_class=object_classes[-1] if object_classes else None,
            owner_sid=psd.owner_sid,
            rights=rights,
            parse_warnings=parse_warnings,
        ))
    return out
