#!/usr/bin/env bash
# SAST Scanner — Semgrep
set -euo pipefail

WORKSPACE="$1"
OUTPUT_FILE="$2"
RULES="${3:-auto}"

echo "[SAST] Running Semgrep (rules: ${RULES})..."

semgrep scan \
  --config "${RULES}" \
  --json \
  --output "${OUTPUT_FILE}" \
  --no-rewrite-rule-ids \
  --metrics off \
  "${WORKSPACE}" 2>/dev/null || true

# Normalise to our findings schema
python3 /action/src/scanners/normalise_semgrep.py "${OUTPUT_FILE}"

echo "[SAST] Done. Output: ${OUTPUT_FILE}"
