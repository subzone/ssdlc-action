#!/usr/bin/env bash
# IaC Scanner — Checkov
set -euo pipefail

WORKSPACE="$1"
OUTPUT_FILE="$2"
FRAMEWORK="${3:-}"
CLOUD_PROVIDER="${4:-aws}"

echo "[IAC] Running Checkov (cloud: ${CLOUD_PROVIDER})..."

CHECKOV_ARGS=(
  --directory "${WORKSPACE}"
  --output json
  --output-file-path "$(dirname "${OUTPUT_FILE}")"
  --exit-code 0
  --quiet
  --compact
)

[[ -n "${FRAMEWORK}" ]] && CHECKOV_ARGS+=(--framework "${FRAMEWORK}")

checkov "${CHECKOV_ARGS[@]}" 2>/dev/null || true

# Checkov writes results_*.json — move to expected path
CHECKOV_OUT="$(dirname "${OUTPUT_FILE}")/results_json.json"
[[ -f "${CHECKOV_OUT}" ]] && mv "${CHECKOV_OUT}" "${OUTPUT_FILE}"

# Normalise
python3 /action/src/scanners/normalise_checkov.py "${OUTPUT_FILE}" "${CLOUD_PROVIDER}"

echo "[IAC] Done. Output: ${OUTPUT_FILE}"
