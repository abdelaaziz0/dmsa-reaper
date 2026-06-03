# ADBuilder Advanced Regression Scenarios

These scenarios define expected dMSA-Reaper mapper/classifier behavior for the
authorized Windows Server 2025 lab. They are represented in
`docs/lab-fixture-dmsalab.json`, `docs/lab-fixture-live-dmsalab.json`,
`docs/expected-dmsa-reaper-contract.json`, and the tests in
`tests/test_lab_fixture.py` / `tests/test_framework_layers.py`.

## Matrix

| Scenario | ADBuilder setup | Expected dMSA-Reaper result |
| --- | --- | --- |
| Direct group ACE | Operator is in a group with `CreateChild:dMSA` on the dMSA container and both target-side `WriteProperty` rights | `postpatch-mutual-pair` path emitted |
| Nested group ACE | Operator -> L1 -> L2, ACE granted to L2 | mapper expands groups; path emitted for the nested principal fixture |
| Primary group ACE | Rights granted only to primary group | primaryGroupID-derived SID grants are included; path emitted |
| Negative GenericWrite container | Container grants only `GenericWrite` | no CreateChild-based path |
| Wrong object-specific GUID | `CreateChild` ACE objectType is unrelated to dMSA class GUID | no dMSA CreateChild path |
| Existing dMSA readable | Existing dMSA attrs and DACL readable | existing-dMSA path may be emitted only when exact migration attrs are writable |
| Existing dMSA unreadable | Object exists but useful attrs cannot be read | state records dMSA read warnings/unreadable candidates; no silent success |
| Sensitive targets | Administrator, krbtgt, DC computer | excluded by default; require explicit inclusion in future sensitive-target mode |
| BadSuccessor postpatch mutual | `CreateChild:dMSA` on container plus both target-side superseded attrs | `badsuccessor assess` reports executable `postpatch-mutual-pair` and `badsuccessor plan` lists both dMSA-side and target-side writes |
| Ouroboros-capable lab | dMSA migration path, KDS, Server 2025 DC, and external proof readiness | `ouroboros assess` reports capable/partial/blocked/unknown with explicit blockers; no native secret extraction |

## Assertions

Run:

```bash
pytest -q tests/test_lab_fixture.py tests/test_cli_state_revalidation.py
```

Expected controls:

- `GenericWrite` on a container does not imply `CreateChild:dMSA`.
- Wrong objectType GUIDs do not satisfy dMSA-specific CreateChild checks.
- `WriteDACL` and `WriteOwner` are not direct existing-dMSA migration proof.
- Existing-dMSA postpatch paths require dMSA-side migration writes and exact
  target-side postpatch writes.
- Unmapped dMSA/container/target overrides require explicit flags and are
  recorded in the operation log.
- `kerberos-base-proof` records readiness only and does not set
  `verified_external=true`.
- `kerberos-dmsa-proof` must be operation-bound and active before external
  dMSA proof can be marked verified.

## Contract Fixture

`docs/expected-dmsa-reaper-contract.json` is a machine-readable contract for
ADBuilder-driven regression runs. It names the expected BadSuccessor path class,
negative controls, accepted Ouroboros assessment statuses, and reporting fields
that must not contain secrets.

## Cleanup/Rebuild

Rebuild the ADBuilder lab, then refresh local fixtures:

```bash
dmsa-reaper map --domain dmsalab.local --dc-ip <DC_IP> \
  -u reaper.low -p '<PASSWORD>' --json state.json

dmsa-reaper paths --state state.json --expand-targets --json paths.json

dmsa-reaper lab-report --state state.json --paths paths.json --json lab-report.json
```

Do not carry live operation logs into fixtures. Operation logs belong under
`.reaper/operations` and are excluded from release archives.
