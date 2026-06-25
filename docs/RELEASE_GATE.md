# V1 Release Gate

A build may be called **V1** only after all items below are confirmed.

## Required: Code Quality

| Check | Command | Required result |
|---|---|---|
| Unit tests | `pytest -q` | All pass, zero failures |
| Lint | `ruff check .` | Zero errors |
| Type check | `mypy dmsa_reaper` | Zero errors |
| Compile | `python3 -m compileall dmsa_reaper tests` | Zero errors |
| Package archive | `bash scripts/package.sh` | Zero artifact entries in zip |

## Required: Correctness Invariants

These invariants must hold at the code level before any lab run:

- [ ] No primitive claims Kerberos success from LDAP state alone. LDAP-state
      verify output must include the explicit disclaimer.
- [ ] No executable path is produced from stale or unproven rights. State
      revalidation must block `--confirm` when state.json is absent or rights
      are not proven (without an explicit lab-override flag).
- [ ] Each override flag (`--allow-unmapped-target`, `--allow-unmapped-container`,
      `--allow-unmapped-dmsa`) records a warning in `operation.metadata["warnings"]`
      and stores the flag name. No single flag silently bypasses a check it
      is not responsible for.
- [ ] `existing-dmsa-legacy-link` and `legacy-oneway-link` require explicit
      lab flags and are blocked by default.
- [ ] `dacl-*` primitives require scope `allowDaclPrimitives` and confirmed
      state revalidation before any LDAP write.

## Required: Lab Run Documentation

One complete Windows Server 2025 (patched) lab run must be documented in
`docs/lab-validation-checklist.json` with all required sections set to `true`
and all notes fields filled in.

The lab run must execute this exact sequence end-to-end:

```
map
  → paths --expand-targets (--json paths.json)
  → exploit --dry-run
  → exploit --confirm
  → verify --mode ldap
  → external Kerberos verifier (Rubeus or equivalent, exit 0)
  → verify --mode external (record exit code + hashes)
  → rollback
  → verify --mode ldap (confirm rollback)
```

## Required: Kerberos Verification

External Kerberos verification (not LDAP-state verification) must be recorded
for the primary postpatch-mutual-pair path before V1.

- The external verifier must exit 0 and its argv, exit code, and
  stdout/stderr SHA-256 hashes must be stored in the operation log.
- `verified_external=true` must be set on the operation.
- LDAP-only verification does not satisfy this gate.

## Forbidden at V1

The following must not be present in any V1 build:

- Golden dMSA extraction or KDS key derivation
- Self-pkinit-loop executable primitive
- Mass credential extraction or bulk enumeration helpers
- Stealth/evasion-oriented path selection ("quietest path", MDI bypass,
  SACL avoidance)
- Any claim that LDAP-state verification proves Kerberos ticket issuance

## Checklist

- [ ] `pytest -q` passes
- [ ] `ruff check .` passes
- [ ] `mypy dmsa_reaper` passes
- [ ] `python3 -m compileall dmsa_reaper tests` passes
- [ ] Package archive has zero artifact entries
- [ ] `lab-validation-checklist.json` — all required sections `true`
- [ ] `lab-validation-checklist.json` — external Kerberos result recorded
- [ ] README states LDAP verify does not prove Kerberos ticket issuance
- [ ] No new exploit primitive added beyond the five documented families
