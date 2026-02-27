#!/usr/bin/env bash
# =============================================================================
# AI SSDLC Action — Main Orchestrator
# Runs all enabled scanners, feeds findings to AI, enforces the security gate.
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()     { echo -e "${CYAN}[SSDLC]${RESET} $*"; }
success() { echo -e "${GREEN}[SSDLC] ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}[SSDLC] ⚠${RESET} $*"; }
error()   { echo -e "${RED}[SSDLC] ✗${RESET} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
OUTPUT_DIR="${OUTPUT_DIR:-.ssdlc-results}"
RESULTS_DIR="${WORKSPACE}/${OUTPUT_DIR}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-high}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-true}"

# ── Tier check / license validation ───────────────────────────────────────────
TIER="free"
LICENSE_STATUS="none"

if [[ -n "${LICENSE_KEY:-}" ]]; then
  LICENSE_VALIDATION=$(python3 /action/src/licensing/validate.py \
    --license-key "${LICENSE_KEY}" \
    --public-key-file "/action/src/licensing/public_key.pem" \
    --revocations-file "/action/src/licensing/revocations.json" \
    --allow-legacy-prefix "true" \
    2>/dev/null || echo '{"valid":false,"tier":"free","reason":"validation_error"}')

  TIER=$(echo "${LICENSE_VALIDATION}" | jq -r '.tier // "free"')
  LICENSE_STATUS=$(echo "${LICENSE_VALIDATION}" | jq -r '.reason // "unknown"')

  if [[ "${TIER}" == "free" ]]; then
    warn "License key did not unlock paid features (reason: ${LICENSE_STATUS})."
  elif [[ "${LICENSE_STATUS}" == "legacy_prefix" ]]; then
    warn "Legacy prefix license accepted. Move to signed SSDL1 tokens for production billing."
  fi
fi

log "Running as tier: ${TIER} (license: ${LICENSE_STATUS})"

# ── Setup results directory ───────────────────────────────────────────────────
mkdir -p "${RESULTS_DIR}"
FINDINGS_FILE="${RESULTS_DIR}/findings.json"
echo "[]" > "${FINDINGS_FILE}"

# ── Summary counters ─────────────────────────────────────────────────────────
TOTAL=0; CRITICAL=0; HIGH=0; MEDIUM=0; LOW_COUNT=0
SCAN_ERRORS=0

# ── Helper: merge findings into master file ───────────────────────────────────
merge_findings() {
  local tool="$1"
  local file="$2"
  if [[ -f "${file}" ]]; then
    # Tag each finding with its source tool then append to master list
    python3 /action/src/reporters/merge.py "${FINDINGS_FILE}" "${file}" "${tool}"
    log "Merged findings from ${tool}"
  fi
}

# ── Helper: set GitHub output ─────────────────────────────────────────────────
set_output() {
  local key="$1"
  local value="$2"
  local output_file="${GITHUB_OUTPUT:-/dev/null}"

  {
    echo "${key}<<__SSDLC_EOF__"
    echo "${value}"
    echo "__SSDLC_EOF__"
  } >> "${output_file}"
}

# =============================================================================
# PHASE 1 — SECRET SCANNING (always run first — fastest, highest signal)
# =============================================================================
if [[ "${ENABLE_SECRET_SCAN:-true}" == "true" ]]; then
  header "Secret Scanning (Gitleaks)"
  SECRETS_OUT="${RESULTS_DIR}/secrets.json"
  if /action/src/scanners/secrets.sh "${WORKSPACE}" "${SECRETS_OUT}"; then
    merge_findings "gitleaks" "${SECRETS_OUT}"
    success "Secret scan complete"
  else
    warn "Secret scan encountered issues — results may be partial"
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
  fi
fi

# =============================================================================
# PHASE 2 — SAST
# =============================================================================
if [[ "${ENABLE_SAST:-true}" == "true" ]]; then
  header "SAST (Semgrep)"
  SAST_OUT="${RESULTS_DIR}/sast.json"
  if /action/src/scanners/sast.sh "${WORKSPACE}" "${SAST_OUT}" "${SEMGREP_RULES:-auto}"; then
    merge_findings "semgrep" "${SAST_OUT}"
    success "SAST scan complete"
  else
    warn "SAST scan encountered issues"
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
  fi
fi

# =============================================================================
# PHASE 3 — SCA (Software Composition Analysis)
# =============================================================================
if [[ "${ENABLE_SCA:-true}" == "true" ]]; then
  header "Software Composition Analysis"
  SCA_OUT="${RESULTS_DIR}/sca.json"
  if /action/src/scanners/sca.sh "${WORKSPACE}" "${SCA_OUT}"; then
    merge_findings "trivy-sca" "${SCA_OUT}"
    success "SCA scan complete"
  else
    warn "SCA scan encountered issues"
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
  fi
fi

# =============================================================================
# PHASE 4 — IaC SCAN (Pro/Enterprise or free with basic rules)
# =============================================================================
if [[ "${ENABLE_IAC:-true}" == "true" ]]; then
  header "IaC Security (Checkov)"
  IAC_OUT="${RESULTS_DIR}/iac.json"
  if /action/src/scanners/iac.sh "${WORKSPACE}" "${IAC_OUT}" "${CHECKOV_FRAMEWORK:-}" "${CLOUD_PROVIDER:-aws}"; then
    merge_findings "checkov" "${IAC_OUT}"
    success "IaC scan complete"
  else
    warn "IaC scan encountered issues"
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
  fi
fi

# =============================================================================
# PHASE 5 — CONTAINER SCAN (Pro/Enterprise only)
# =============================================================================
if [[ "${ENABLE_CONTAINER:-false}" == "true" ]]; then
  if [[ "${TIER}" == "free" ]]; then
    warn "Container scanning requires Pro or Enterprise licence. Skipping."
  else
    header "Container Scan (Trivy)"
    CONTAINER_OUT="${RESULTS_DIR}/container.json"
    if /action/src/scanners/container.sh "${CONTAINER_IMAGE:-}" "${CONTAINER_OUT}"; then
      merge_findings "trivy-container" "${CONTAINER_OUT}"
      success "Container scan complete"
    else
      warn "Container scan encountered issues"
      SCAN_ERRORS=$((SCAN_ERRORS + 1))
    fi
  fi
fi

# =============================================================================
# PHASE 6 — AI TRIAGE & ANALYSIS
# =============================================================================
AI_SUMMARY="Security scan complete. AI analysis not enabled."
if [[ "${ENABLE_AI_TRIAGE:-true}" == "true" ]]; then
  header "AI Finding Triage"
  AI_SUMMARY=$(python3 /action/src/ai/triage.py \
    --findings "${FINDINGS_FILE}" \
    --provider "${AI_PROVIDER:-anthropic}" \
    --model "${AI_MODEL:-claude-sonnet-4-5-20250929}" \
    --cloud "${CLOUD_PROVIDER:-aws}" \
    --fix-suggestions "${ENABLE_AI_FIXES:-true}" \
    2>&1) || warn "AI triage failed — continuing without AI analysis"
  success "AI triage complete"
fi

# =============================================================================
# PHASE 7 — THREAT MODELING (Enterprise only)
# =============================================================================
THREAT_MODEL=""
if [[ "${ENABLE_THREAT_MODEL:-false}" == "true" ]]; then
  if [[ "${TIER}" != "enterprise" ]]; then
    warn "Threat modeling requires Enterprise licence. Skipping."
  else
    header "AI Threat Modeling (STRIDE)"
    THREAT_MODEL=$(python3 /action/src/ai/threat_model.py \
      --workspace "${WORKSPACE}" \
      --provider "${AI_PROVIDER:-anthropic}" \
      --model "${AI_MODEL:-claude-sonnet-4-5-20250929}" \
      --cloud "${CLOUD_PROVIDER:-aws}" \
      2>&1) || warn "Threat modeling failed — continuing"
    success "Threat modeling complete"
  fi
fi

# =============================================================================
# PHASE 8 — COUNT & GATE
# =============================================================================
header "Security Gate"
COUNTS=$(python3 /action/src/reporters/count.py "${FINDINGS_FILE}" "${SEVERITY_THRESHOLD}")
TOTAL=$(echo "${COUNTS}"    | jq -r '.total')
CRITICAL=$(echo "${COUNTS}" | jq -r '.critical')
HIGH=$(echo "${COUNTS}"     | jq -r '.high')
MEDIUM=$(echo "${COUNTS}"   | jq -r '.medium')
LOW_COUNT=$(echo "${COUNTS}"| jq -r '.low')

log "Findings: CRITICAL=${CRITICAL}  HIGH=${HIGH}  MEDIUM=${MEDIUM}  LOW=${LOW_COUNT}"

# Determine pass/fail
PASSED="true"
THRESHOLD_COUNT=$(echo "${COUNTS}" | jq -r '.threshold_count')
if [[ "${THRESHOLD_COUNT}" -gt 0 ]] && [[ "${FAIL_ON_FINDINGS}" == "true" ]]; then
  PASSED="false"
fi

# =============================================================================
# PHASE 9 — REPORTING
# =============================================================================
header "Generating Reports"

# GitHub Step Summary
python3 /action/src/reporters/summary.py \
  --findings "${FINDINGS_FILE}" \
  --ai-summary "${AI_SUMMARY}" \
  --threat-model "${THREAT_MODEL}" \
  --counts "${COUNTS}" \
  --passed "${PASSED}" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

# SARIF upload (integrates with GitHub Security tab)
if [[ "${SARIF_UPLOAD:-true}" == "true" ]]; then
  if [[ "${TOTAL}" -gt 0 ]]; then
    SARIF_FILE="${RESULTS_DIR}/results.sarif"
    python3 /action/src/reporters/sarif.py "${FINDINGS_FILE}" "${SARIF_FILE}"
    if command -v gh &>/dev/null && [[ -n "${GITHUB_TOKEN:-}" ]]; then
      gh auth setup-git 2>/dev/null || true
      gh api \
        --method POST \
        -H "Accept: application/vnd.github+json" \
        "/repos/${GITHUB_REPOSITORY}/code-scanning/sarifs" \
        -f commit_sha="${GITHUB_SHA}" \
        -f ref="${GITHUB_REF}" \
        -f sarif="$(gzip -c "${SARIF_FILE}" | base64 -w0)" \
        -f tool_name="AI SSDLC" 2>/dev/null || warn "SARIF upload failed — check repo permissions"
    fi
  else
    log "No findings to upload in SARIF. Skipping SARIF generation/upload."
  fi
fi

# PR comment
if [[ "${POST_PR_COMMENT:-true}" == "true" ]] && [[ -n "${GITHUB_TOKEN:-}" ]]; then
  python3 /action/src/reporters/pr_comment.py \
    --findings "${FINDINGS_FILE}" \
    --ai-summary "${AI_SUMMARY}" \
    --counts "${COUNTS}" \
    --passed "${PASSED}" \
    --repo "${GITHUB_REPOSITORY:-}" \
    --pr-number "${PR_NUMBER:-}" 2>/dev/null || warn "PR comment failed"
fi

# =============================================================================
# PHASE 10 — SET OUTPUTS & EXIT
# =============================================================================
set_output "findings-count" "${TOTAL}"
set_output "critical-count" "${CRITICAL}"
set_output "high-count"     "${HIGH}"
set_output "medium-count"   "${MEDIUM}"
set_output "low-count"      "${LOW_COUNT}"
set_output "ai-summary"     "${AI_SUMMARY}"
set_output "threat-model"   "${THREAT_MODEL}"
set_output "passed"         "${PASSED}"
set_output "report-path"    "${RESULTS_DIR}/findings.json"

echo ""
if [[ "${PASSED}" == "true" ]]; then
  success "Security gate PASSED ✓ (${TOTAL} total findings, none at or above ${SEVERITY_THRESHOLD} threshold)"
  exit 0
else
  error "Security gate FAILED ✗ — ${THRESHOLD_COUNT} finding(s) at or above ${SEVERITY_THRESHOLD} severity"
  error "Review findings in the Security tab, PR comment, or ${RESULTS_DIR}/findings.json"
  exit 1
fi
