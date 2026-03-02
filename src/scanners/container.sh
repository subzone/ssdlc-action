#!/usr/bin/env bash
# Container Scanner — Trivy image mode
set -euo pipefail

IMAGE="$1"
OUTPUT_FILE="$2"
IGNORE_UNFIXED="${3:-false}"   # optional: skip CVEs with no available fix

if [[ -z "${IMAGE}" ]]; then
  echo "[CONTAINER] No image specified. Skipping."
  echo "[]" > "${OUTPUT_FILE}"
  exit 0
fi

echo "[CONTAINER] Scanning image: ${IMAGE}..."

EXTRA_FLAGS=()
if [[ "${IGNORE_UNFIXED}" == "true" ]]; then
  EXTRA_FLAGS+=("--ignore-unfixed")
  echo "[CONTAINER] --ignore-unfixed: skipping CVEs with no available fix"
fi

trivy image \
  --format json \
  --output "${OUTPUT_FILE}" \
  --exit-code 0 \
  ${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"} \
  "${IMAGE}" 2>/dev/null || true

# Normalise
python3 /action/src/scanners/normalise_trivy.py "${OUTPUT_FILE}" "container"

echo "[CONTAINER] Done. Output: ${OUTPUT_FILE}"
