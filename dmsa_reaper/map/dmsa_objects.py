from __future__ import annotations

from ldap3 import Connection

from dmsa_reaper.acl.enrichment import compute_effective_rights
from dmsa_reaper.acl.parser import parse_security_descriptor
from dmsa_reaper.constants import DMSA_CLASS
from dmsa_reaper.ldap.query import search_with_sd
from dmsa_reaper.models import DmsaObject, Principal, SchemaCache
from dmsa_reaper.map.principal import principal_sid_set
from dmsa_reaper.ldap.sid import entry_sid
from dmsa_reaper.utils import bytes_to_guid_le

_MISSING_SD_WARNING = "nTSecurityDescriptor missing or unreadable; effective-rights result is incomplete"

_EXPANDED_GENERIC_ALL_RIGHTS = frozenset({
    "CreateChild",
    "DeleteChild",
    "ListContents",
    "SelfWrite",
    "ReadProperty",
    "WriteProperty",
    "DeleteTree",
    "ListObject",
    "ControlAccess",
    "Delete",
    "ReadControl",
    "WriteDACL",
    "WriteOwner",
})


def enumerate_dmsas(
    conn: Connection,
    default_nc: str,
    sdflags: int,
    principal: Principal | None = None,
    schema_cache: SchemaCache | None = None,
) -> list[DmsaObject]:
    attrs = [
        "distinguishedName",
        "sAMAccountName",
        "objectSid",
        "objectGUID",
        "msDS-DelegatedMSAState",
        "msDS-ManagedAccountPrecededByLink",
        "msDS-SupersededManagedAccountLink",
        "msDS-KeyCredentialLink",
        "msDS-GroupMSAMembership",
    ]
    entries = search_with_sd(conn, default_nc, f"(objectClass={DMSA_CLASS})", attrs, sdflags)
    if not entries:
        # Fallback: search by presence of the dMSA-specific state attribute.
        # Some environments return no entries for the objectClass filter if
        # the schema GUID is not yet cached client-side or the class name
        # differs from what ldap3 expects.
        entries = search_with_sd(conn, default_nc, "(msDS-DelegatedMSAState=*)", attrs, sdflags)

    op_sid = principal.sid if principal else ""
    op_sids = principal_sid_set(principal)
    dmsa_guid = schema_cache.dmsa_class_guid if schema_cache else None
    attr_guids = schema_cache.attr_guids if schema_cache else {}

    out: list[DmsaObject] = []
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
        dmsa_sid = entry_sid(e.objectSid) if "objectSid" in e else None

        key_credential_values = (
            e["msDS-KeyCredentialLink"].raw_values or []
            if "msDS-KeyCredentialLink" in e
            else []
        )
        membership_values = (
            e["msDS-GroupMSAMembership"].raw_values or []
            if "msDS-GroupMSAMembership" in e
            else []
        )
        membership_sids: list[str] = []
        self_authorized = False
        if membership_values:
            membership_raw = membership_values[0]
            membership_bytes = (
                membership_raw.encode("latin-1")
                if isinstance(membership_raw, str)
                else bytes(membership_raw)
            )
            membership_sd = parse_security_descriptor(membership_bytes)
            if membership_sd.parse_warnings:
                parse_warnings.extend(
                    f"msDS-GroupMSAMembership: {warning}"
                    for warning in membership_sd.parse_warnings
                )
            membership_sids = sorted({ace.sid for ace in membership_sd.aces})
            self_authorized = bool(
                dmsa_sid
                and any(
                    ace.ace_type == "allow"
                    and ace.sid == dmsa_sid
                    and _EXPANDED_GENERIC_ALL_RIGHTS.issubset(ace.rights)
                    for ace in membership_sd.aces
                )
            )

        # Rights the current operator has on this dMSA.
        operator_rights, _ = compute_effective_rights(
            psd.aces,
            op_sid,
            op_sids,
            dn,
            psd.owner_sid,
            dmsa_class_guid=dmsa_guid,
            attr_guids=attr_guids,
            side="dmsa",
            null_dacl=psd.null_dacl,
        )
        if psd.parse_failed:
            operator_rights = []

        guid_raw = (
            e["objectGUID"].raw_values[0]
            if "objectGUID" in e and e["objectGUID"].raw_values
            else None
        )
        out.append(DmsaObject(
            dn=dn,
            object_guid=(bytes_to_guid_le(bytes(guid_raw)) if guid_raw and len(guid_raw) == 16 else None),
            sam=(
                str(e.sAMAccountName.value)
                if "sAMAccountName" in e and e.sAMAccountName.value
                else None
            ),
            sid=dmsa_sid,
            state=(
                int(e["msDS-DelegatedMSAState"].value)
                if "msDS-DelegatedMSAState" in e and e["msDS-DelegatedMSAState"].value is not None
                else None
            ),
            preceded_by=(
                str(e["msDS-ManagedAccountPrecededByLink"].value)
                if "msDS-ManagedAccountPrecededByLink" in e and e["msDS-ManagedAccountPrecededByLink"].value
                else None
            ),
            superseded_link=(
                str(e["msDS-SupersededManagedAccountLink"].value)
                if "msDS-SupersededManagedAccountLink" in e and e["msDS-SupersededManagedAccountLink"].value
                else None
            ),
            owner_sid=psd.owner_sid,
            rights=operator_rights,
            parse_warnings=parse_warnings,
            key_credential_count=len(key_credential_values),
            group_msa_membership_sids=membership_sids,
            ouroboros_self_authorized=self_authorized,
        ))
    return out
