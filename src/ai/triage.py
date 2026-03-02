#!/usr/bin/env python3
"""
AI Finding Triage
Sends aggregated scan findings to an AI provider and returns a structured analysis.
"""
import argparse
import json
import os
import sys
from pathlib import Path

# ── Provider clients ──────────────────────────────────────────────────────────

def call_anthropic(system_prompt: str, user_prompt: str, model: str, api_key: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text

def call_openai(system_prompt: str, user_prompt: str, model: str, api_key: str) -> str:
    import openai
    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
    )
    return response.choices[0].message.content

def call_github_models(system_prompt: str, user_prompt: str, model: str, github_token: str) -> str:
    import openai
    client = openai.OpenAI(
        base_url="https://models.inference.ai.azure.com",
        api_key=github_token,
    )
    response = client.chat.completions.create(
        model=model,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
    )
    return response.choices[0].message.content

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings",       required=True)
    parser.add_argument("--provider",       default="anthropic")
    parser.add_argument("--model",          default="claude-sonnet-4-6")
    parser.add_argument("--cloud",          default="aws")
    parser.add_argument("--fix-suggestions", default="true")
    args = parser.parse_args()

    api_key = os.environ.get("AI_API_KEY", "")
    if not api_key:
        print("No AI_API_KEY set — skipping AI triage", file=sys.stderr)
        print(json.dumps({"executive_summary": "AI triage skipped — no API key provided.",
                          "risk_rating": "unknown", "top_findings": [], "quick_wins": []}))
        return

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print("Findings file not found", file=sys.stderr)
        sys.exit(1)

    findings = json.loads(findings_path.read_text())

    system_prompt_path = Path("/action/src/ai/prompts/triage_system.txt")
    system_prompt = system_prompt_path.read_text() if system_prompt_path.exists() else ""

    if not findings:
        user_prompt = f"""All enabled security scanners completed with zero findings.
Cloud provider: {args.cloud}
Scanners run: SAST (Semgrep), Secret Scanning (Gitleaks), SCA (dependency audit), IaC (Checkov).

Please provide a brief security assurance summary confirming the clean scan result, and include
any proactive hardening recommendations relevant to a {args.cloud}-hosted application.

Return ONLY valid JSON with this exact structure:
{{"risk_rating": "pass", "executive_summary": "...", "true_positive_count": 0, "false_positive_count": 0, "top_findings": [], "quick_wins": [...], "waf_summary": "..."}}
No markdown, no code blocks."""
    else:
        # Limit findings sent to AI (cost control) — top 50 by severity
        SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 4))
        findings_sample = findings_sorted[:50]

        user_prompt = f"""Please analyse these {len(findings)} security findings from an automated SSDLC scan.
Cloud provider: {args.cloud}
Total findings: {len(findings)}
Sending top {len(findings_sample)} by severity for analysis.
Include fix suggestions: {args.fix_suggestions}

FINDINGS:
{json.dumps(findings_sample, indent=2)}

Return ONLY valid JSON matching the schema in your instructions. No markdown, no code blocks."""

    try:
        if args.provider.lower() == "anthropic":
            raw = call_anthropic(system_prompt, user_prompt, args.model, api_key)
        elif args.provider.lower() == "github":
            raw = call_github_models(system_prompt, user_prompt, args.model, api_key)
        else:
            raw = call_openai(system_prompt, user_prompt, args.model, api_key)

        # Validate it's JSON
        parsed = json.loads(raw)
        print(json.dumps(parsed, indent=2))

    except json.JSONDecodeError:
        # AI returned non-JSON — wrap it
        print(json.dumps({"executive_summary": raw, "risk_rating": "unknown",
                          "top_findings": [], "quick_wins": []}))
    except Exception as e:
        print(f"AI triage error: {e}", file=sys.stderr)
        print(json.dumps({"executive_summary": f"AI triage failed: {e}",
                          "risk_rating": "unknown", "top_findings": [], "quick_wins": []}))

if __name__ == "__main__":
    main()
