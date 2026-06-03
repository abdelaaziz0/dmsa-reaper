#!/usr/bin/env bash
# package.sh — run tests, clean artifacts, create a clean zip archive.
#
# Usage:
#   bash scripts/package.sh [output-dir]
#
# The archive is written to the output directory (default: current directory).
# Generated artifacts (__pycache__, .pytest_cache, .mypy_cache, .ruff_cache,
# *.pyc, *.egg-info) are removed *after* tests pass to ensure the archive is
# always clean.  Internal workspace directories (.git, .reaper, .claude,
# .agents, .codex) are also excluded.
#
# Example:
#   bash scripts/package.sh /tmp/releases
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}}"

mkdir -p "${OUT_DIR}"
cd "${REPO_ROOT}"

echo "==> Running test suite..."
python3 -m pytest -q

echo "==> Cleaning generated artifacts..."
find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" -o -name "*.egg-info" \) \
    -prune -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

VERSION=$(python3 -c "
import tomllib, sys
with open('pyproject.toml', 'rb') as f:
    data = tomllib.load(f)
print(data['project']['version'])
" 2>/dev/null || grep -m1 'version' pyproject.toml | sed 's/.*= *"\(.*\)"/\1/')

ARCHIVE="${OUT_DIR}/dmsa-reaper-${VERSION}.zip"
PARENT="$(basename "${REPO_ROOT}")"

echo "==> Creating archive: ${ARCHIVE}"
rm -f "${ARCHIVE}"
cd "${REPO_ROOT}/.."
zip -r "${ARCHIVE}" "${PARENT}" \
    --exclude '*/__pycache__/*' \
    --exclude '*/.pytest_cache/*' \
    --exclude '*/.mypy_cache/*' \
    --exclude '*/.ruff_cache/*' \
    --exclude '*.pyc' \
    --exclude '*.egg-info/*' \
    --exclude '*/.reaper/*' \
    --exclude '*/.reaper' \
    --exclude '*/.git/*' \
    --exclude '*/.git' \
    --exclude '*/.claude/*' \
    --exclude '*/.claude' \
    --exclude '*/.agents/*' \
    --exclude '*/.agents' \
    --exclude '*/.codex/*' \
    --exclude '*/.codex' \
    --exclude '*.zip'

echo ""
echo "Archive: ${ARCHIVE}"
echo "Checking for artifact entries..."
ARTIFACT_COUNT=$(unzip -l "${ARCHIVE}" | grep -cE \
    '(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.pyc$|\.egg-info|/\.reaper/|/\.claude/|/\.agents/|/\.codex/|/\.git/)' \
    || true)
echo "Artifact entries: ${ARTIFACT_COUNT}"
if [ "${ARTIFACT_COUNT}" -gt 0 ]; then
    echo "ERROR: archive contains generated or internal artifact entries." >&2
    echo "Offending entries:" >&2
    unzip -l "${ARCHIVE}" | grep -E \
        '(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.pyc$|\.egg-info|/\.reaper/|/\.claude/|/\.agents/|/\.codex/|/\.git/)' \
        >&2 || true
    exit 1
fi
echo "OK: no artifact entries found."
