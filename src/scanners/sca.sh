#!/usr/bin/env bash
# SCA Scanner — Trivy filesystem mode (detects dependency vulnerabilities)
set -euo pipefail

WORKSPACE="$1"
OUTPUT_FILE="$2"

echo "[SCA] Running Trivy SCA..."

trivy fs \
  --format json \
  --output "${OUTPUT_FILE}" \
  --scanners vuln \
  --exit-code 0 \
  "${WORKSPACE}" 2>/dev/null || true

# Normalise
python3 /action/src/scanners/normalise_trivy.py "${OUTPUT_FILE}" "sca"

echo "[SCA] Done. Output: ${OUTPUT_FILE}"
