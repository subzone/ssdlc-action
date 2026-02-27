#!/usr/bin/env python3
"""Normalise Trivy JSON output → unified SSDLC finding schema."""
import json
import sys
from pathlib import Path

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "low",
}

def normalise(path: str, scan_type: str = "sca") -> None:
    p = Path(path)
    if not p.exists():
        p.write_text("[]")
        return

    raw = json.loads(p.read_text())
    findings = []

    for result in raw.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            sev = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN").upper(), "low")
            findings.append({
                "id":          vuln.get("VulnerabilityID", "unknown"),
                "tool":        f"trivy-{scan_type}",
                "severity":    sev,
                "title":       f"{vuln.get('VulnerabilityID')} in {vuln.get('PkgName', 'unknown')}",
                "description": vuln.get("Description", ""),
                "file":        target,
                "line":        0,
                "code":        f"Package: {vuln.get('PkgName')} @ {vuln.get('InstalledVersion')} "
                               f"(fixed in {vuln.get('FixedVersion', 'no fix available')})",
                "cwe":         vuln.get("CweIDs", []),
                "owasp":       [],
                "fix":         f"Upgrade {vuln.get('PkgName')} to {vuln.get('FixedVersion', 'latest')}",
                "references":  vuln.get("References", [])[:3],
                "cvss":        vuln.get("CVSS", {}),
            })

    p.write_text(json.dumps(findings, indent=2))

if __name__ == "__main__":
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "sca"
    normalise(sys.argv[1], scan_type)
