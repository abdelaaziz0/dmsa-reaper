from __future__ import annotations

import base64

from ldap3 import Connection

from dmsa_reaper.acl.enrichment import compute_effective_rights
from dmsa_reaper.acl.parser import parse_security_descriptor
from dmsa_reaper.constants import DMSA_CLASS
from dmsa_reaper.ldap.query import search_with_sd
from dmsa_reaper.models import DmsaObject, Principal, Right, SchemaCache
from dmsa_reaper.map.principal import principal_sid_set
from dmsa_reaper.ldap.sid import entry_sid

_MISSING_SD_WARNING = "nTSecurityDescriptor missing or unreadable; effective-rights result is incomplete"


def dmsa_self_sid_set(dmsa_sid: str) -> set[str]:
    """Return SID set for evaluating a dMSA computer account against itself.

    TODO: expand this scaffold with the dMSA/computer account's nested group
    SIDs and primaryGroupID-derived SID.  The current minimal behavior is
    intentionally only {dmsa_sid}; it must never mix in the current operator's
    SIDs, because operator control is modeled separately as DmsaObject.rights.
    """
    return {dmsa_sid}


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
        "msDS-DelegatedMSAState",
        "msDS-GroupMSAMembership",
        "msDS-ManagedAccountPrecededByLink",
        "msDS-SupersededManagedAccountLink",
        "msDS-KeyCredentialLink",
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
        raw_gmsa = (
            e["msDS-GroupMSAMembership"].raw_values[0]
            if "msDS-GroupMSAMembership" in e and e["msDS-GroupMSAMembership"].raw_values
            else None
        )
        dn = str(e.distinguishedName.value)
        dmsa_sid = entry_sid(e.objectSid) if "objectSid" in e else None

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
        )

        # Rights the dMSA principal has on itself (acting as the dMSA computer account).
        # Used for self-write-map and self-pkinit-loop classification.
        self_rights: list[Right] = []
        if dmsa_sid:
            self_rights, _ = compute_effective_rights(
                psd.aces,
                dmsa_sid,
                dmsa_self_sid_set(dmsa_sid),
                dn,
                psd.owner_sid,
                attr_guids=attr_guids,
                side="dmsa",
                is_self=True,
            )

        out.append(DmsaObject(
            dn=dn,
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
            group_msa_membership_raw_b64=base64.b64encode(raw_gmsa).decode() if raw_gmsa else None,
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
            key_credential_link_present=bool(
                "msDS-KeyCredentialLink" in e and e["msDS-KeyCredentialLink"].values
            ),
            owner_sid=psd.owner_sid,
            rights=operator_rights,
            self_rights=self_rights,
            parse_warnings=parse_warnings,
        ))
    return out
