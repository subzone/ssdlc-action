# 🛡️ AI SSDLC Security Suite — GitHub Action

> AI-powered Secure SDLC scanning. One action. All layers.
> SAST · Secret Detection · SCA · IaC · Container · AI Triage · STRIDE Threat Modeling

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AI%20SSDLC-blue?logo=github)](https://github.com/marketplace/actions/ai-ssdlc-security-suite)
[![License](https://img.shields.io/badge/License-Proprietary-blue)](LICENSE)

---

## Quick Start

Add this to your repository's `.github/workflows/security.yml`:

```yaml
- uses: subzone/ssdlc-action@v1
  with:
    ai-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

That's it. No tooling to install, no configuration required.

---

## What It Does

| Phase | Tool | Free | Pro | Enterprise |
|-------|------|:----:|:---:|:----------:|
| Secret Scanning | Gitleaks | ✅ | ✅ | ✅ |
| SAST | Semgrep | ✅ | ✅ | ✅ |
| SCA (Dependencies) | Trivy | ❌ | ✅ | ✅ |
| IaC Security | Checkov | ❌ | ✅ | ✅ |
| Container Scanning | Trivy | ❌ | ✅ | ✅ |
| AI Finding Triage | Anthropic/OpenAI | ❌ | ✅ | ✅ |
| AI Fix Suggestions | Anthropic/OpenAI | ❌ | ✅ | ✅ |
| STRIDE Threat Modeling | Anthropic/OpenAI | ❌ | ❌ | ✅ |
| WAF Control Mapping | Built-in | ❌ | ✅ | ✅ |
| SARIF Upload | GitHub Security tab | ✅ | ✅ | ✅ |
| PR Comment | AI summary | ❌ | ✅ | ✅ |

---

## Inputs

### Required

| Input | Description |
|-------|-------------|
| `ai-api-key` | Anthropic or OpenAI API key |

### Optional

| Input | Default | Description |
|-------|---------|-------------|
| `ai-provider` | `anthropic` | `anthropic` or `openai` |
| `ai-model` | `claude-sonnet-4-5-20250929` | Model name |
| `license-key` | *(empty)* | Pro/Enterprise licence key |
| `severity-threshold` | `high` | `critical`, `high`, `medium`, or `low` |
| `fail-on-findings` | `true` | Block the workflow on findings |
| `enable-sast` | `true` | Run Semgrep SAST |
| `enable-secret-scan` | `true` | Run Gitleaks |
| `enable-sca` | `true` | Run Trivy SCA |
| `enable-iac-scan` | `true` | Run Checkov IaC scan |
| `enable-container-scan` | `false` | Run Trivy container scan |
| `container-image` | *(empty)* | Image to scan (if container scan enabled) |
| `enable-threat-modeling` | `false` | Run STRIDE threat modeling |
| `enable-ai-triage` | `true` | AI finding triage |
| `enable-ai-fix-suggestions` | `true` | Include fix suggestions |
| `cloud-provider` | `aws` | `aws`, `azure`, or `gcp` |
| `semgrep-rules` | `auto` | Semgrep ruleset |
| `post-pr-comment` | `true` | Post AI summary to PR |
| `sarif-upload` | `true` | Upload to GitHub Security tab |

---

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings |
| `critical-count` | Critical findings |
| `high-count` | High findings |
| `medium-count` | Medium findings |
| `low-count` | Low findings |
| `ai-summary` | AI-generated summary (JSON) |
| `threat-model` | STRIDE threat model (JSON) |
| `passed` | `true` if gate passed |
| `report-path` | Path to `findings.json` |

---

## Using Outputs in Your Workflow

```yaml
- name: Run AI SSDLC
  id: security
  uses: subzone/ssdlc-action@v1
  with:
    ai-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Check results
  run: |
    echo "Total findings: ${{ steps.security.outputs.findings-count }}"
    echo "Gate passed: ${{ steps.security.outputs.passed }}"
```

---

## Required Permissions

```yaml
permissions:
  contents:        read
  security-events: write   # SARIF upload
  pull-requests:   write   # PR comments
```

---

## Architecture

```
entrypoint.sh
├── Phase 1 — Secret Scan    (Gitleaks)
├── Phase 2 — SAST           (Semgrep)
├── Phase 3 — SCA            (Trivy fs)
├── Phase 4 — IaC Scan       (Checkov)
├── Phase 5 — Container      (Trivy image)  [Pro+]
├── Phase 6 — AI Triage      (Claude/GPT)   [Pro+]
├── Phase 7 — Threat Model   (STRIDE + AI)  [Enterprise]
├── Phase 8 — Security Gate  (policy check)
└── Phase 9 — Reports        (SARIF, PR comment, Step Summary)
```

All scanners output to a unified finding schema — the AI triage receives
a single normalised list regardless of which tools ran.

---

## Well-Architected Framework Alignment

Findings from IaC scanning are automatically mapped to the
[AWS/Azure/GCP Well-Architected Framework Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
controls, giving teams immediate context on compliance posture.

---

## Support / Contact

Need help, found a bug, or want enterprise onboarding?

- Open an issue: [GitHub Issues](https://github.com/subzone/ssdlc-action/issues)
- Security disclosures: please open a [private security advisory](https://github.com/subzone/ssdlc-action/security/advisories/new) in this repository
- Commercial/support enquiries: use your organization contact channel for `subzone`

---

## Licence

Proprietary © subzone. Use is governed by the EULA in [`LICENSE`](LICENSE).

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for third-party license obligations.
