from __future__ import annotations

from ldap3 import Connection

from dmsa_reaper.acl.enrichment import compute_effective_rights
from dmsa_reaper.acl.parser import parse_security_descriptor
from dmsa_reaper.ldap.query import search_with_sd
from dmsa_reaper.models import Principal, SchemaCache, TargetObject
from dmsa_reaper.map.principal import principal_sid_set
from dmsa_reaper.ldap.sid import entry_sid
from dmsa_reaper.utils import bytes_to_guid_le

_MISSING_SD_WARNING = "nTSecurityDescriptor missing or unreadable; effective-rights result is incomplete"


def enumerate_targets(
    conn: Connection,
    default_nc: str,
    sdflags: int,
    principal: Principal | None = None,
    schema_cache: SchemaCache | None = None,
    target_filter: str | None = None,
    max_targets: int | None = None,
    only_current_principal: bool = False,
) -> list[TargetObject]:
    base_filter = (
        "(|(objectClass=user)(objectClass=computer)"
        "(objectClass=msDS-GroupManagedServiceAccount)"
        "(objectClass=msDS-DelegatedManagedServiceAccount))"
    )
    ldap_filter = f"(&{base_filter}{target_filter})" if target_filter else base_filter
    entries = search_with_sd(
        conn,
        default_nc,
        ldap_filter,
        ["distinguishedName", "sAMAccountName", "objectSid", "objectGUID", "objectClass"],
        sdflags,
        # When filtering to the current principal, apply the cap after SID
        # matching so an unrelated early LDAP result cannot hide the account.
        max_entries=None if only_current_principal else max_targets,
    )

    psid = principal.sid if principal else ""
    psids = principal_sid_set(principal)
    dmsa_guid = schema_cache.dmsa_class_guid if schema_cache else None
    attr_guids = schema_cache.attr_guids if schema_cache else {}

    out: list[TargetObject] = []
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
        dn = str(e.distinguishedName.value)

        rights, writable_attrs = compute_effective_rights(
            psd.aces,
            psid,
            psids,
            dn,
            psd.owner_sid,
            dmsa_class_guid=dmsa_guid,
            attr_guids=attr_guids,
            side="target",
            null_dacl=psd.null_dacl,
        )
        if psd.parse_failed:
            rights, writable_attrs = [], []

        sid = entry_sid(e.objectSid) if "objectSid" in e else None
        if only_current_principal and (not principal or sid != principal.sid):
            continue

        guid_raw = (
            e["objectGUID"].raw_values[0]
            if "objectGUID" in e and e["objectGUID"].raw_values
            else None
        )
        out.append(TargetObject(
            dn=dn,
            object_guid=(bytes_to_guid_le(bytes(guid_raw)) if guid_raw and len(guid_raw) == 16 else None),
            sam=(
                str(e.sAMAccountName.value)
                if "sAMAccountName" in e and e.sAMAccountName.value
                else None
            ),
            sid=sid,
            object_classes=list(e.objectClass.values) if "objectClass" in e else [],
            owner_sid=psd.owner_sid,
            rights=rights,
            writable_attrs=writable_attrs,
            parse_warnings=parse_warnings,
        ))
        if max_targets is not None and len(out) >= max_targets:
            break
    return out
