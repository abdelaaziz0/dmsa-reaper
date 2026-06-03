from __future__ import annotations

# SD flags from MS-ADTS LDAP_SERVER_SD_FLAGS_OID.
OWNER_SECURITY_INFORMATION = 0x1
GROUP_SECURITY_INFORMATION = 0x2
DACL_SECURITY_INFORMATION = 0x4
SACL_SECURITY_INFORMATION = 0x8

DEFAULT_SD_FLAGS = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION  # 0x5

FCONFIDENTIAL = 0x80

DMSA_CLASS = "msDS-DelegatedManagedServiceAccount"

DMSA_RELEVANT_ATTRS = [
    "msDS-DelegatedMSAState",
    "msDS-ManagedAccountPrecededByLink",
    "msDS-SupersededManagedAccountLink",
    "msDS-SupersededManagedAccountLinkBL",
    "msDS-SupersededServiceAccountState",
    "msDS-GroupMSAMembership",
    "msDS-KeyCredentialLink",
]

ATTR_LIVES_ON = {
    "msDS-DelegatedMSAState": "dmsa",
    "msDS-ManagedAccountPrecededByLink": "dmsa",
    "msDS-GroupMSAMembership": "dmsa",
    "msDS-KeyCredentialLink": "any",
    "msDS-SupersededManagedAccountLink": "target",
    "msDS-SupersededServiceAccountState": "target",
}

# Fallback GUIDs only. Runtime schema resolution should win.
FALLBACK_GUIDS = {
    "msDS-DelegatedManagedServiceAccount": "0feb936f-47b3-49f2-9386-1dedc2c23765",
    "msDS-ManagedAccountPrecededByLink": "a0945b2b-57a2-43bd-b327-4d112a4e8bd1",
    "msDS-SupersededManagedAccountLink": "3752e002-43be-48c8-b3ca-2cb2fffbc8a1",
    "msDS-GroupMSAMembership": "888eedd6-ce04-df40-b462-b8a50e41ba38",
}

KDS_ROOT_KEYS_RDN = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services"
