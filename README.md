# dMSA-Reaper

`dmsa-reaper` is a focused CLI for authorized Windows Server 2025 Active Directory
dMSA assessment workflows:

```text
map -> paths -> exploit -> verify -> rollback
```

It is intended for explicitly authorized penetration tests, internal red-team labs,
and defensive research. It is not a dashboard, reporting suite, stealth layer, mass
credential extractor, KDS root-key extractor, or native Kerberos implementation.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
mypy dmsa_reaper
```

Python 3.10 or newer is supported by the package metadata and test configuration.

## What It Does

- Maps dMSA-relevant schema, Server 2025 DC, KDS root-key, principal, target,
  container, dMSA, and effective-rights state.
- Classifies selected paths for the workflow above.
- Executes selected, scoped, operator-confirmed LDAP primitives.
- Writes durable operation logs before risky LDAP boundaries.
- Verifies LDAP directory state.
- Rolls back reversible operations from the operation log.

## What It Does Not Do

- It does not prove Kerberos ticket issuance from LDAP-state verification.
- It does not implement native Kerberos dMSA verification.
- It does not implement robust Impacket-style pass-the-hash.
- It does not extract KDS root keys or implement golden dMSA flows.
- It does not execute self-pkinit-loop/Ouroboros.
- It does not automatically exploit every path.
- It does not provide stealth, evasion, or mass credential extraction.
- It does not generate HTML/PDF reports or blue-team packaging.

## Safety Model

LDAP writes require a selected path, `--confirm`, and a scope file. DACL primitives
are additionally lab-unsafe and require all of:

- `allowDaclPrimitives=true` in scope
- `--lab-unsafe`
- `--confirm` for execution

Broad DACL ACEs are blocked unless both `allowBroadDacl=true` is present in scope
and `--allow-broad-dacl` is passed. The preferred DACL behavior is object-specific
ACE construction from schema-resolved GUIDs.

The mapper treats dMSA usability as a top-level environment gate. A confirmed
usable environment requires dMSA schema support, at least one Server 2025 DC, and
a KDS root key. Unknown KDS/schema/DC checks remain `unknown`, not `false`.
`ldap_signing_status` and `channel_binding_status` are placeholders and remain
`unknown` until active checks are implemented.

## Auth Support

Currently supported:

- password bind through ldap3 NTLM
- LDAPS with `--use-ldaps`
- environment Kerberos through ldap3 SASL/GSSAPI (`--kerberos`), with lab
  validation still required

Not yet supported:

- robust Impacket-style pass-the-hash
- native Kerberos ticket handling

## Scope File

```json
{
  "domain": "corp.local",
  "allowedOUs": [
    "OU=Reaper,DC=corp,DC=local"
  ],
  "allowedTargets": [
    "OU=Targets,OU=Reaper,DC=corp,DC=local"
  ],
  "denyTargets": [
    "CN=krbtgt,CN=Users,DC=corp,DC=local"
  ],
  "denySubtrees": [
    "OU=Tier0,DC=corp,DC=local"
  ],
  "allowDaclPrimitives": false,
  "allowBroadDacl": false,
  "requireConfirmString": true
}
```

Created objects must be under `allowedOUs`. Modified objects must be under
`allowedOUs` or `allowedTargets`. `denyTargets` blocks exact DNs and
`denySubtrees` blocks the subtree, overriding allow lists. Sensitive locations
such as Domain Controllers, AdminSDHolder, System, Configuration, Schema, and
the domain root are denied by default.

## Real Exploitation Workflow

```bash
dmsa-reaper map --domain corp.local --dc-ip 10.0.0.10 \
  -u analyst -p 'pass' --use-ldaps --json state.json

dmsa-reaper paths --state state.json --expand-targets --json paths.json

dmsa-reaper exploit --paths paths.json --path P-0001 \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' \
  --scope scope.json --dry-run

dmsa-reaper exploit --paths paths.json --path P-0001 \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' \
  --scope scope.json --confirm

dmsa-reaper verify --op OP-20260528-deadbeef --mode ldap \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass'

dmsa-reaper rollback --op OP-20260528-deadbeef \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass'
```

Use `--ops-dir` on `exploit`, `verify`, and `rollback` to store operation logs
outside the default `.reaper/operations` directory. `DMSA_REAPER_OPS_DIR` is also
honored.

## Supported Primitives

| Primitive | Status | Notes |
|---|---|---|
| `postpatch-mutual-pair` | primary | Creates a controlled dMSA and writes the mutual post-patch target relationship. |
| `existing-dmsa-postpatch-mutual` | controlled | Uses an existing dMSA only when the selected path proves dMSA-side and target-side writes. |
| `existing-dmsa-legacy-link` | lab/legacy | Requires `--allow-existing-dmsa-legacy-link`; writes only dMSA-side attributes. |
| `legacy-oneway-link` | lab/legacy | Requires `--allow-legacy-oneway-link`; patched KDCs may reject ticket semantics. |
| `dacl-container-escalate` | lab-unsafe | Requires scope DACL gates and `--lab-unsafe`; rollback restores prior SD bytes. |
| `dacl-target-escalate` | lab-unsafe | Requires scope DACL gates and `--lab-unsafe`; rollback restores prior SD bytes. |
| `self-write-map` | informational | Maps self-write surfaces only. |
| `self-pkinit-loop` | informational | Candidate identification only; no executable Ouroboros primitive. |

## Operation Logs

Operations are stored as collision-resistant IDs such as
`OP-20260528-deadbeef.json`. Saves are atomic: write temporary file, fsync, then
replace. Create attempts are recorded as `maybe_created_dns` before LDAP add and
moved to `created_dns` only after confirmed success.

Rollback checks `maybe_created_dns` and deletes matching tool-created objects if
they exist. If a rollback step fails, the operation is marked partial rather than
silently claimed as clean.

## Verification Limitations

`verify --mode ldap` checks only directory state: object existence, expected
attribute values, and restored DACL bytes where applicable. It prints:

```text
LDAP-state verification does not prove Kerberos ticket issuance.
```

`verify --mode external --external-argv ...` records exit code, stdout, and stderr
without using a shell. Shell mode requires `--allow-shell-external` and remains a
legacy escape hatch.

## Rollback Limitations

Rollback depends on the operation log and live LDAP access. It can restore recorded
attribute values and exact prior security descriptors for DACL primitives. It
cannot prove cleanup for unrecorded out-of-band changes, replication races, or
objects renamed by another operator after creation.

## Known Limitations

- LDAP-state verification is not Kerberos verification.
- Native Kerberos dMSA verification is not implemented.
- KDS/golden dMSA extraction is out of scope.
- self-pkinit-loop/Ouroboros is not executable.
- ACL effective-rights output may still have false positives/negatives until
  validated against the full Server 2025 lab matrix.
- Multi-DC replication lag is not modeled.
- Mission-ready status requires a documented full Server 2025 lab run:
  map -> paths -> exploit --dry-run -> exploit --confirm -> verify --mode ldap
  -> rollback -> verify rollback.
