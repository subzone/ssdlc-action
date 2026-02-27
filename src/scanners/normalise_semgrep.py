#!/usr/bin/env python3
"""Normalise Semgrep JSON output → unified SSDLC finding schema."""
import json
import sys
from pathlib import Path

SEVERITY_MAP = {
    "ERROR":   "critical",
    "WARNING": "high",
    "INFO":    "medium",
    "HINT":    "low",
}

def normalise(path: str) -> None:
    p = Path(path)
    if not p.exists():
        p.write_text("[]")
        return

    raw = json.loads(p.read_text())
    results = raw.get("results", [])
    findings = []

    for r in results:
        severity_raw = r.get("extra", {}).get("severity", "INFO").upper()
        findings.append({
            "id":          r.get("check_id", "unknown"),
            "tool":        "semgrep",
            "severity":    SEVERITY_MAP.get(severity_raw, "low"),
            "title":       r.get("check_id", "Semgrep finding"),
            "description": r.get("extra", {}).get("message", ""),
            "file":        r.get("path", ""),
            "line":        r.get("start", {}).get("line", 0),
            "code":        r.get("extra", {}).get("lines", ""),
            "cwe":         r.get("extra", {}).get("metadata", {}).get("cwe", []),
            "owasp":       r.get("extra", {}).get("metadata", {}).get("owasp", []),
            "fix":         r.get("extra", {}).get("fix", ""),
            "references":  r.get("extra", {}).get("metadata", {}).get("references", []),
        })

    p.write_text(json.dumps(findings, indent=2))

if __name__ == "__main__":
    normalise(sys.argv[1])
