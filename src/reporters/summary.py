#!/usr/bin/env python3
"""Generate GitHub Actions Step Summary (appears in the Actions run UI)."""
import argparse
import json
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings",     required=True)
    parser.add_argument("--ai-summary",   required=True)
    parser.add_argument("--threat-model", default="")
    parser.add_argument("--counts",       required=True)
    parser.add_argument("--passed",       required=True)
    args = parser.parse_args()

    findings = json.loads(Path(args.findings).read_text()) if Path(args.findings).exists() else []

    try:
        ai_summary = json.loads(args.ai_summary)
    except (json.JSONDecodeError, TypeError):
        ai_summary = {"executive_summary": str(args.ai_summary)}

    try:
        threat_model = json.loads(args.threat_model) if args.threat_model else {}
    except (json.JSONDecodeError, TypeError):
        threat_model = {}

    try:
        counts = json.loads(args.counts)
    except (json.JSONDecodeError, TypeError):
        counts = {}

    gate_icon = "✅" if args.passed == "true" else "❌"
    gate_text = "PASSED" if args.passed == "true" else "FAILED"

    lines = [
        f"# 🛡️ AI SSDLC Security Report",
        "",
        f"## Security Gate: {gate_icon} {gate_text}",
        "",
        "## Findings by Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {counts.get('critical', 0)} |",
        f"| 🟠 High     | {counts.get('high', 0)} |",
        f"| 🟡 Medium   | {counts.get('medium', 0)} |",
        f"| 🔵 Low      | {counts.get('low', 0)} |",
        f"| **Total**   | **{counts.get('total', 0)}** |",
        "",
    ]

    # AI Analysis
    if isinstance(ai_summary, dict):
        exec_sum = ai_summary.get("executive_summary", "")
        if exec_sum:
            lines += ["## 🤖 AI Security Analysis", "", exec_sum, ""]

        top = ai_summary.get("top_findings", [])
        if top:
            lines += ["## Top Findings", ""]
            for f in top[:10]:
                sev   = f.get("severity", "low").upper()
                lines.append(f"### [{sev}] {f.get('title', 'Finding')}")
                lines.append(f"> {f.get('why_it_matters', '')}")
                lines.append(f"**Fix:** {f.get('fix', '')}")
                waf = f.get('waf_control', '')
                if waf:
                    lines.append(f"**WAF Control:** {waf}")
                lines.append("")

        qw = ai_summary.get("quick_wins", [])
        if qw:
            lines += ["## ⚡ Quick Wins", ""]
            for item in qw:
                lines.append(f"- {item}")
            lines.append("")

    # Threat Model
    if threat_model and isinstance(threat_model, dict):
        lines += ["## 🔍 STRIDE Threat Model", ""]
        summary = threat_model.get("summary", "")
        if summary:
            lines.append(summary)
            lines.append("")

        stride = threat_model.get("stride_analysis", {})
        if stride:
            lines += ["| Threat Category | Risk | Key Threats |",
                      "|-----------------|------|-------------|"]
            for category, data in stride.items():
                risk    = data.get("risk", "none").upper()
                threats = "; ".join(data.get("threats", [])[:2])
                lines.append(f"| {category.replace('_', ' ').title()} | {risk} | {threats} |")
            lines.append("")

        actions = threat_model.get("recommended_actions", [])
        if actions:
            lines += ["### Recommended Actions", ""]
            for i, action in enumerate(actions, 1):
                lines.append(f"{i}. {action}")
            lines.append("")

    # Findings table (top 20)
    if findings:
        lines += ["## All Findings (top 20)", ""]
        lines += ["| Tool | Severity | Title | File |",
                  "|------|----------|-------|------|"]
        SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "low"), 4))
        for f in sorted_findings[:20]:
            sev   = f.get("severity", "low").upper()
            title = f.get("title", "")[:60]
            file_ = f.get("file", "")[-50:] if f.get("file") else "N/A"
            tool  = f.get("tool", "unknown")
            lines.append(f"| {tool} | {sev} | {title} | {file_} |")
        lines.append("")

    print("\n".join(lines))

if __name__ == "__main__":
    main()
