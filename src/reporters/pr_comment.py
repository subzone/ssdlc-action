#!/usr/bin/env python3
"""Post AI security summary as a GitHub PR comment via the GitHub API."""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
STATUS_EMOJI   = {"true": "✅", "false": "❌"}

def post_comment(repo: str, pr_number: str, body: str, token: str) -> None:
    url  = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type",  "application/json")
    req.add_header("Accept",        "application/vnd.github+json")
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"PR comment posted (HTTP {resp.status})")
    except urllib.error.HTTPError as e:
        print(f"Failed to post PR comment: {e}", file=sys.stderr)

def build_comment(findings: list, ai_summary: dict, counts: dict, passed: str) -> str:
    status = "✅ PASSED" if passed == "true" else "❌ FAILED"
    badge  = "brightgreen" if passed == "true" else "red"

    lines = [
        f"## 🛡️ AI SSDLC Security Report — {status}",
        "",
        f"![Security Gate](https://img.shields.io/badge/Security%20Gate-{status.replace(' ', '%20')}-{badge})",
        "",
        "### 📊 Findings Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {counts.get('critical', 0)} |",
        f"| 🟠 High     | {counts.get('high', 0)} |",
        f"| 🟡 Medium   | {counts.get('medium', 0)} |",
        f"| 🔵 Low      | {counts.get('low', 0)} |",
        f"| **Total**   | **{counts.get('total', 0)}** |",
        "",
    ]

    # AI Executive Summary
    if isinstance(ai_summary, dict):
        exec_summary = ai_summary.get("executive_summary", "")
        if exec_summary:
            lines += ["### 🤖 AI Security Analysis", "", exec_summary, ""]

        # Top findings from AI
        top = ai_summary.get("top_findings", [])
        if top:
            lines += ["### ⚠️ Top Findings", ""]
            for finding in top[:5]:
                sev   = finding.get("severity", "low")
                emoji = SEVERITY_EMOJI.get(sev, "⚪")
                lines += [
                    f"<details>",
                    f"<summary>{emoji} <b>{finding.get('title', 'Finding')}</b> [{sev.upper()}]</summary>",
                    "",
                    f"**Why it matters:** {finding.get('why_it_matters', '')}",
                    "",
                    f"**Fix:** {finding.get('fix', '')}",
                    "",
                    f"**WAF Control:** {finding.get('waf_control', 'N/A')}",
                    "",
                    "</details>",
                    "",
                ]

        # Quick wins
        quick_wins = ai_summary.get("quick_wins", [])
        if quick_wins:
            lines += ["### ⚡ Quick Wins", ""]
            for qw in quick_wins:
                lines.append(f"- {qw}")
            lines.append("")

        waf = ai_summary.get("waf_summary", "")
        if waf:
            lines += ["### 🏗️ Well-Architected Framework", "", waf, ""]

    lines += [
        "---",
        (
            "_Powered by [AI SSDLC Action]"
            "(https://github.com/subzone/ssdlc-action) · "
            "Review the full report in the **Security** tab and "
            "**Actions Summary**._"
        )
        ,
    ]

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings",   required=True)
    parser.add_argument("--ai-summary", required=True)
    parser.add_argument("--counts",     required=True)
    parser.add_argument("--passed",     required=True)
    parser.add_argument("--repo",       required=True)
    parser.add_argument("--pr-number",  required=True)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token or not args.pr_number:
        print("No GITHUB_TOKEN or PR number — skipping PR comment", file=sys.stderr)
        return

    findings = json.loads(Path(args.findings).read_text()) if Path(args.findings).exists() else []

    try:
        ai_summary = json.loads(args.ai_summary)
    except (json.JSONDecodeError, TypeError):
        ai_summary = {"executive_summary": str(args.ai_summary)}

    try:
        counts = json.loads(args.counts)
    except (json.JSONDecodeError, TypeError):
        counts = {}

    body = build_comment(findings, ai_summary, counts, args.passed)
    post_comment(args.repo, args.pr_number, body, token)

if __name__ == "__main__":
    main()
