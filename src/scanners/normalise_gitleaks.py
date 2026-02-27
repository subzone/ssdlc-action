#!/usr/bin/env python3
"""Normalise Gitleaks JSON output → unified SSDLC finding schema."""
import json
import sys
from pathlib import Path

def normalise(path: str) -> None:
    p = Path(path)
    if not p.exists():
        p.write_text("[]")
        return

    text = p.read_text().strip()
    if not text or text == "null":
        p.write_text("[]")
        return

    raw = json.loads(text)
    if not isinstance(raw, list):
        p.write_text("[]")
        return

    findings = []
    for r in raw:
        findings.append({
            "id":          f"gitleaks-{r.get('RuleID', 'unknown')}",
            "tool":        "gitleaks",
            "severity":    "critical",   # Secrets are always critical
            "title":       f"Secret detected: {r.get('Description', r.get('RuleID', 'Secret'))}",
            "description": f"A secret matching rule '{r.get('RuleID')}' was found. "
                           f"Commit: {r.get('Commit', 'N/A')}",
            "file":        r.get("File", ""),
            "line":        r.get("StartLine", 0),
            "code":        r.get("Match", ""),
            "cwe":         ["CWE-798"],
            "owasp":       ["A07:2021 – Identification and Authentication Failures"],
            "fix":         "Revoke this credential immediately, rotate it, and remove it from git history.",
            "references":  ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"],
        })

    p.write_text(json.dumps(findings, indent=2))

if __name__ == "__main__":
    normalise(sys.argv[1])
