#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-dmsalab.local}"
DC_IP="${DC_IP:-192.168.56.10}"
LAB_USER="${DMSA_USER:-${LAB_USER:-}}"
if [[ -z "$LAB_USER" && "${USER:-}" == *.* ]]; then
  LAB_USER="$USER"
fi
LAB_USER="${LAB_USER:-reaper.low}"
PASSWORD="${PASSWORD:-}"
SCOPE="${SCOPE:-docs/lab-scope-dmsalab.json}"
OUT_DIR="${OUT_DIR:-/tmp/dmsa-reaper-live-campaign}"
ROLLBACK_POLICY="${ROLLBACK_POLICY:-always}"
DRY_RUN="${DRY_RUN:-0}"

if [[ -z "$PASSWORD" ]]; then
  echo "PASSWORD environment variable is required" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
CAMPAIGN_JSON="$OUT_DIR/campaign.json"

args=(
  campaign run
  --profile badsuccessor-lab
  --domain "$DOMAIN"
  --dc-ip "$DC_IP"
  -u "$LAB_USER"
  -p "$PASSWORD"
  --scope "$SCOPE"
  --confirm-string "$DOMAIN"
  --rollback-policy "$ROLLBACK_POLICY"
  --json "$CAMPAIGN_JSON"
)

if [[ "$DRY_RUN" == "1" ]]; then
  args+=(--dry-run)
fi

dmsa-reaper "${args[@]}"

if command -v jq >/dev/null 2>&1; then
  jq -e '.secrets_logged == false' "$CAMPAIGN_JSON" >/dev/null
  if [[ "$DRY_RUN" != "1" ]]; then
    jq -e '.ldap_verified == true' "$CAMPAIGN_JSON" >/dev/null
    jq -e '.full_badsuccessor_success == false' "$CAMPAIGN_JSON" >/dev/null
    if [[ "$ROLLBACK_POLICY" == "always" ]]; then
      jq -e '.rollback_status == "rolled-back" and .rollback_verified == true' "$CAMPAIGN_JSON" >/dev/null
    fi
  fi
fi

find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name '*.egg-info' \) -prune -print
find . -type f \( -name '*.pyc' -o -name '*.log' \) -print

echo "campaign JSON: $CAMPAIGN_JSON"
