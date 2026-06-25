#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-dmsalab.local}"
DC_HOST="${DC_HOST:-DMSA.dmsalab.local}"
KRB5_CONFIG="${KRB5_CONFIG:-/etc/krb5.conf}"
OUT="${1:-${OUT:-kerberos-base-proof.json}}"
SERVICE="${SERVICE:-cifs/${DC_HOST}}"
KRB5CCNAME_VALUE="${KRB5CCNAME:-}"

if [[ -z "$KRB5CCNAME_VALUE" ]]; then
  echo "KRB5CCNAME is required" >&2
  exit 2
fi

CCACHE_PATH="$KRB5CCNAME_VALUE"
if [[ "$CCACHE_PATH" == FILE:* ]]; then
  echo "warning: FILE: prefix works with MIT krb5 tools but may fail with Impacket/NXC." >&2
  echo "recommendation: export KRB5CCNAME=${CCACHE_PATH#FILE:}" >&2
  CCACHE_PATH="${CCACHE_PATH#FILE:}"
fi

if [[ ! -f "$CCACHE_PATH" ]]; then
  echo "ccache not found: $CCACHE_PATH" >&2
  exit 2
fi

export KRB5CCNAME="$CCACHE_PATH"
export KRB5_CONFIG

if ! klist -s; then
  echo "ccache does not contain a usable TGT" >&2
  exit 2
fi

if ! klist -e | grep -qi "$SERVICE"; then
  if command -v kvno >/dev/null 2>&1; then
    kvno "$SERVICE" >/dev/null
  else
    echo "service ticket for $SERVICE is absent and kvno is not available" >&2
    exit 2
  fi
fi

if command -v smbclient.py >/dev/null 2>&1; then
  principal="$(klist | awk -F': ' '/Default principal:/ {print $2; exit}')"
  user_part="${principal%@*}"
  smb_cmds="$(mktemp)"
  trap 'rm -f "$smb_cmds"' EXIT
  {
    echo "use SYSVOL"
    echo "ls"
    echo "use NETLOGON"
    echo "ls"
    echo "exit"
  } >"$smb_cmds"
  smbclient.py -k -no-pass -inputfile "$smb_cmds" "${DOMAIN}/${user_part}@${DC_HOST}" >/dev/null
fi

if command -v dmsa-reaper >/dev/null 2>&1; then
  dmsa-reaper proof collect-base \
    --ccache "$CCACHE_PATH" \
    --krb5-config "$KRB5_CONFIG" \
    --dc-host "$DC_HOST" \
    --service "$SERVICE" \
    --json "$OUT" >/dev/null
else
  python3 - "$OUT" "$CCACHE_PATH" "$KRB5_CONFIG" "$DC_HOST" "$SERVICE" <<'PY'
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

out, ccache, krb5_config, dc_host, requested_service = sys.argv[1:6]
env = os.environ.copy()
env["KRB5CCNAME"] = ccache
env["KRB5_CONFIG"] = krb5_config
proc = subprocess.run(["klist", "-e"], text=True, capture_output=True, env=env, check=False)
if proc.returncode != 0:
    raise SystemExit("klist failed while collecting base proof")
principal = None
services = []
for line in proc.stdout.splitlines():
    if line.startswith("Default principal:"):
        principal = line.split(":", 1)[1].strip()
    for match in re.finditer(r"\b((?:krbtgt|cifs)/[^\s]+(?:@[A-Za-z0-9_.-]+)?)", line):
        services.append(match.group(1))
if not principal:
    raise SystemExit("could not determine principal from klist")
tgt_present = any(service.lower().startswith("krbtgt/") for service in services)
requested_key = requested_service.lower().split("@", 1)[0]
service = next((item for item in services if item.lower().split("@", 1)[0] == requested_key), None)
if not tgt_present:
    raise SystemExit("TGT not present in ccache")
if not service:
    raise SystemExit(f"service ticket not present in ccache: {requested_service}")
realm = principal.rsplit("@", 1)[1].upper() if "@" in principal else None
proof = {
    "type": "kerberos-base-proof",
    "operation_id": None,
    "principal": principal,
    "service": service,
    "realm": realm,
    "tool": "klist",
    "result": "success",
    "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "tickets": {
        "tgt_present": True,
        "service_ticket_present": True,
    },
    "environment": {
        "ccache_style": "raw-file-path",
        "ccache_exists": True,
        "krb5_config": krb5_config,
        "dc_host": dc_host,
        "requested_service": requested_service,
    },
    "notes": "Kerberos cache metadata collected without storing raw ticket material.",
}
payload = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
proof["proof_sha256"] = hashlib.sha256(payload).hexdigest()
with open(out, "w", encoding="utf-8") as handle:
    json.dump(proof, handle, indent=2)
    handle.write("\n")
PY
fi

echo "wrote Kerberos base proof: $OUT"
