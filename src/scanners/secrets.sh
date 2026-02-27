#!/usr/bin/env bash
# Secret Scanner — Gitleaks
set -euo pipefail

WORKSPACE="$1"
OUTPUT_FILE="$2"

echo "[SECRETS] Running Gitleaks..."

gitleaks detect \
  --source="${WORKSPACE}" \
  --report-format=json \
  --report-path="${OUTPUT_FILE}" \
  --exit-code=0 \
  --no-banner 2>/dev/null || true

# Normalise
python3 /action/src/scanners/normalise_gitleaks.py "${OUTPUT_FILE}"

echo "[SECRETS] Done. Output: ${OUTPUT_FILE}"
