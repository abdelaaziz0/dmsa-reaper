# Exegol Kerberos Lab Notes

These notes document Kerberos validation behavior observed in the Windows Server
2025 ADBuilder dMSA lab.

## Time Skew

Kerberos requires client and DC clocks to be close enough, normally within five
minutes. In this lab the Linux/Exegol clock and the DC clock drifted far enough
to produce `KRB_AP_ERR_SKEW`.

Temporary lab workaround:

```bash
faketime '<dc-time>' getTGT.py ...
```

Preferred fix: synchronize the host and DC clocks.

## Credential Cache Format

MIT Kerberos tools can accept:

```bash
export KRB5CCNAME=FILE:/workspace/reaper.low.ccache
```

In this Exegol/Impacket setup, Impacket and NXC treated the `FILE:` value as a
literal filename. For Impacket-like tools, use the raw path:

```bash
export KRB5CCNAME=/workspace/reaper.low.ccache
export KRB5_CONFIG=/etc/krb5.conf
```

## DNS

BloodHound.py failed when the resolver was `127.0.0.53` and SRV lookup failed
for:

```text
_ldap._tcp.pdc._msdcs.dmsalab.local
```

Use the DC as DNS resolver:

```bash
bloodhound-python -ns 192.168.56.10 -dc DMSA.dmsalab.local ...
```

Alternatively, configure `/etc/resolv.conf` to use the DC.

## SMB Kerberos

Use the DC FQDN for Kerberos, not the IP address:

```bash
smbclient.py -k -no-pass -target-ip 192.168.56.10 \
  dmsalab.local/reaper.low@DMSA.dmsalab.local
```

`C$` access denied is expected for `reaper.low`; it is not a local administrator
on the DC. SYSVOL and NETLOGON are valid low-privilege SMB proof targets.

If NXC fails but Impacket `smbclient.py` works, classify that as an NXC tooling
issue rather than a Kerberos failure.

## Base Proof Collection

Base Kerberos proof can now be collected inside Exegol and supplied to the
campaign runner. This proves the operator Kerberos environment only; it does not
prove dMSA ticket issuance.

```bash
export DOMAIN=dmsalab.local
export DC_HOST=DMSA.dmsalab.local
export KRB5_CONFIG=/etc/krb5.conf
export KRB5CCNAME=/workspace/reaper.low.ccache

scripts/exegol_collect_base_proof.sh
```

The helper validates that the ccache exists, a TGT is present, and
`cifs/<DC_HOST>` is present or obtainable with `kvno`. If `smbclient.py` is
available, it also checks low-privilege SYSVOL/NETLOGON access. It never prints
the password and never stores raw tickets, keys, hashes, or session keys.

Pass the resulting proof to a campaign:

```bash
dmsa-reaper campaign run \
  --profile badsuccessor-lab \
  --domain dmsalab.local --dc-ip 192.168.56.10 \
  -u reaper.low -p '<password>' \
  --scope docs/lab-scope-dmsalab.json \
  --confirm-string dmsalab.local \
  --base-proof kerberos-base-proof.json \
  --rollback-policy always \
  --json campaign.json
```

Expected conclusion without dMSA proof:

```text
kerberos_base_ready=true
kerberos_dmsa_verified=false
full_badsuccessor_success=false
final_status=ldap-verified-kerberos-base-ready-dmsa-proof-missing
```

## Current dMSA Proof Boundary

The live lab has validated:

- LDAP postpatch state: success.
- Rollback: success.
- Base Kerberos for `reaper.low`: success in Exegol.
- dMSA Kerberos proof through the tested Impacket `getST.py -dmsa` flow:
  failed/inconclusive with `KRB_ERR_GENERIC`.

Do not set `verified_external=true` from base Kerberos proof. Only an
operation-bound `kerberos-dmsa-proof` may mark external verification successful.
