#!/usr/bin/env python3
"""Normalise Checkov JSON output → unified SSDLC finding schema."""
import json
import sys
from pathlib import Path

# Map Checkov check IDs to WAF Security Pillar controls
WAF_MAPPING = {
    "aws": {
        "CKV_AWS_": "WAF-SEC: Infrastructure Protection",
        "CKV2_AWS_": "WAF-SEC: Infrastructure Protection",
    },
    "azure": {
        "CKV_AZURE_": "WAF-SEC: Infrastructure Protection",
    },
    "gcp": {
        "CKV_GCP_": "WAF-SEC: Infrastructure Protection",
    },
}

def get_waf_control(check_id: str, cloud: str) -> str:
    prefix_map = WAF_MAPPING.get(cloud, {})
    for prefix, control in prefix_map.items():
        if check_id.startswith(prefix):
            return control
    return "WAF-SEC: Security"

def normalise(path: str, cloud_provider: str = "aws") -> None:
    p = Path(path)
    if not p.exists():
        p.write_text("[]")
        return

    raw = json.loads(p.read_text())

    # Checkov output can be a list or dict depending on version
    if isinstance(raw, list):
        checks = []
        for r in raw:
            checks.extend(r.get("results", {}).get("failed_checks", []))
    else:
        checks = raw.get("results", {}).get("failed_checks", [])

    findings = []
    for check in checks:
        check_id = check.get("check_id", "unknown")
        findings.append({
            "id":          check_id,
            "tool":        "checkov",
            "severity":    "high",  # Checkov doesn't provide severity; default to high
            "title":       check.get("check", {}).get("name", check_id),
            "description": check.get("check", {}).get("name", "IaC misconfiguration detected"),
            "file":        check.get("repo_file_path", check.get("file_path", "")),
            "line":        check.get("file_line_range", [0])[0],
            "code":        json.dumps(check.get("code_block", []), indent=2)[:500],
            "cwe":         [],
            "owasp":       [],
            "waf_control": get_waf_control(check_id, cloud_provider),
            "fix":         check.get("check", {}).get("guideline", "Review Checkov documentation for remediation."),
            "references":  [check.get("check", {}).get("guideline", "")] if check.get("check", {}).get("guideline") else [],
        })

    p.write_text(json.dumps(findings, indent=2))

if __name__ == "__main__":
    cloud = sys.argv[2] if len(sys.argv) > 2 else "aws"
    normalise(sys.argv[1], cloud)
