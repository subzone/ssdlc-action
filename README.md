# 🛡️ AI SSDLC Security Suite — GitHub Action

> AI-powered Secure SDLC scanning. One action. All layers.
> SAST · Secret Detection · SCA · IaC · Container · AI Triage · STRIDE Threat Modeling

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AI%20SSDLC-blue?logo=github)](https://github.com/marketplace/actions/ai-ssdlc-security-suite)
[![License](https://img.shields.io/badge/License-Proprietary-blue)](LICENSE)

---

## Quick Start

Add this to `.github/workflows/security.yml`. No API key required — GitHub Models is free.

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents:        read
  security-events: write   # SARIF upload
  pull-requests:   write   # PR comment
  models:          read    # GitHub Models (free AI)

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: SSDLC Security Scan
        uses: subzone/ssdlc-action@v1
        with:
          github-token: ${{ github.token }}
          ai-provider: github
```

> **Tip:** Always pin to `@v1` (or a specific release tag) in production — never use `@main`.

---

## What It Does

| Phase | Tool | Free | Pro | Enterprise |
|-------|------|:----:|:---:|:----------:|
| Secret Scanning | Gitleaks | ✅ | ✅ | ✅ |
| SAST | Semgrep | ✅ | ✅ | ✅ |
| SCA (Dependencies) | pip-audit / npm audit | ✅ | ✅ | ✅ |
| IaC Security | Checkov | ✅ | ✅ | ✅ |
| Container Scanning | Trivy | ❌ | ✅ | ✅ |
| AI Finding Triage | GitHub Models / Claude / GPT | ✅ | ✅ | ✅ |
| AI Fix Suggestions | GitHub Models / Claude / GPT | ✅ | ✅ | ✅ |
| STRIDE Threat Modeling | GitHub Models / Claude / GPT | ❌ | ❌ | ✅ |
| WAF Control Mapping | Built-in | ✅ | ✅ | ✅ |
| SARIF Upload | GitHub Security tab | ✅ | ✅ | ✅ |
| PR Comment | AI summary | ✅ | ✅ | ✅ |

---

## Inputs

### Required

| Input | Description |
|-------|-------------|
| `github-token` | Required for SARIF upload, PR comments, and GitHub Models. Use `${{ github.token }}`. |

### Optional

| Input | Default | Description |
|-------|---------|-------------|
| `ai-api-key` | *(empty)* | Anthropic or OpenAI API key. Not needed when using `ai-provider: github`. |
| `ai-provider` | `github` | AI provider: `github` (zero-cost), `anthropic`, or `openai`. |
| `ai-model` | `claude-sonnet-4-6` | Model name, e.g. `claude-sonnet-4-6` or `gpt-4o`. |
| `license-key` | *(empty)* | Signed SSDL1 Pro/Enterprise licence token. |
| `severity-threshold` | `high` | Minimum severity that fails the build: `critical`, `high`, `medium`, or `low`. |
| `fail-on-findings` | `true` | Set to `false` to report findings without blocking the workflow. |
| `enable-sast` | `true` | Run SAST scanning with Semgrep. |
| `enable-secret-scan` | `true` | Run secret scanning with Gitleaks. |
| `enable-sca` | `true` | Run Software Composition Analysis (pip-audit / npm audit). |
| `enable-iac-scan` | `true` | Run IaC security scanning with Checkov. |
| `enable-container-scan` | `false` | Run container image scan with Trivy. Requires `container-image`. |
| `trivy-ignore-unfixed` | `false` | Ignore unfixed vulnerabilities in Trivy scans. |
| `container-image` | *(empty)* | Container image to scan, e.g. `myapp:${{ github.sha }}`. |
| `enable-threat-modeling` | `false` | Run AI-powered STRIDE threat modeling (Enterprise only). |
| `enable-ai-triage` | `true` | Use AI to triage, deduplicate, and prioritise findings. |
| `enable-ai-fix-suggestions` | `true` | Include AI-generated fix suggestions in the PR comment. |
| `post-pr-comment` | `true` | Post AI security summary as a PR comment. |
| `sarif-upload` | `true` | Upload SARIF results to GitHub Security tab. |
| `cloud-provider` | `aws` | Primary cloud target for WAF control mapping: `aws`, `azure`, or `gcp`. |
| `semgrep-rules` | `auto` | Custom Semgrep ruleset, e.g. `p/owasp-top-ten p/python`. |
| `checkov-framework` | *(all)* | Checkov framework filter, e.g. `terraform,cloudformation`. |
| `output-dir` | `.ssdlc-results` | Directory to write scan artefacts and reports. |

---

## Licence Key Management (Pro / Enterprise)

This project includes an offline signing/validation flow for paid tiers.

- Runtime validator: `src/licensing/validate.py`
- Public verification key: `src/licensing/public_key.pem`
- Revocations: `src/licensing/revocations.json`
- Issuer tooling:
  - `tools/licensing/generate_keypair.py`
  - `tools/licensing/issue_license.py`
  - `tools/licensing/revoke_license.py`

### Issuance flow

1. Generate keypair once (keep private key out of git).
2. Commit only `src/licensing/public_key.pem`.
3. Issue a token for each customer (`pro` or `enterprise`).
4. Customer stores token in GitHub secret and passes it as `license-key`.
5. Revoke compromised keys by adding their `jti` to `src/licensing/revocations.json`.

Legacy prefix keys (`PRO-*`, `ENT-*`) are accepted for backward compatibility,
but signed `SSDL1.<payload>.<signature>` tokens are recommended for production.

---

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings across all scanners. |
| `critical-count` | Critical severity findings. |
| `high-count` | High severity findings. |
| `medium-count` | Medium severity findings. |
| `low-count` | Low severity findings. |
| `ai-summary` | AI-generated plain-English security summary. |
| `threat-model` | AI-generated STRIDE threat model (Enterprise only). |
| `passed` | `true` if the security gate passed, `false` if findings blocked the build. |
| `report-path` | Path to `findings.json` on the runner. |

---

## Using Outputs in Your Workflow

```yaml
- name: Run AI SSDLC
  id: security
  uses: subzone/ssdlc-action@v1
  with:
    github-token: ${{ github.token }}
    ai-provider: github

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
  models:          read    # GitHub Models provider (free AI)
```

---

## Architecture

```
entrypoint.sh
├── Phase 1 — Secret Scan    (Gitleaks)
├── Phase 2 — SAST           (Semgrep)
├── Phase 3 — SCA            (pip-audit / npm audit)
├── Phase 4 — IaC Scan       (Checkov)
├── Phase 5 — Container      (Trivy image)  [Pro+]
├── Phase 6 — AI Triage      (GitHub Models / Claude / GPT)
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
- Commercial/support enquiries (existing customers): please use your usual organisation contact channel for `subzone`

---

## Licence

Proprietary © subzone. Use is governed by the EULA in [`LICENSE`](LICENSE).

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for third-party license obligations.
