#!/usr/bin/env python3
"""Convert unified findings to SARIF 2.1.0 for GitHub Security tab upload."""
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

SEVERITY_SARIF = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
}

def main():
    findings_path = Path(sys.argv[1])
    sarif_path    = Path(sys.argv[2])

    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []

    # Group findings by tool
    tools: dict[str, list] = {}
    for f in findings:
        tool = f.get("tool", "unknown")
        tools.setdefault(tool, []).append(f)

    runs = []
    for tool_name, tool_findings in tools.items():
        rules = {}
        results = []

        for f in tool_findings:
            rule_id = f.get("id", "unknown")
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.get("title", rule_id),
                    "shortDescription": {"text": f.get("title", rule_id)},
                    "fullDescription":  {"text": f.get("description", f.get("title", ""))},
                    "helpUri": f.get("references", [""])[0] if f.get("references") else "",
                    "defaultConfiguration": {
                        "level": SEVERITY_SARIF.get(f.get("severity", "low"), "note")
                    },
                    "properties": {
                        "tags": f.get("cwe", []) + f.get("owasp", []),
                        "security-severity": {
                            "critical": "9.5", "high": "7.5",
                            "medium": "5.0", "low": "2.0"
                        }.get(f.get("severity", "low"), "2.0"),
                    },
                }

            file_path  = f.get("file", "")
            line       = max(1, f.get("line", 1))

            result = {
                "ruleId": rule_id,
                "level": SEVERITY_SARIF.get(f.get("severity", "low"), "note"),
                "message": {"text": f.get("description", f.get("title", ""))},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.lstrip("/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line,
                            "snippet":   {"text": f.get("code", "")[:200]},
                        },
                    }
                }],
                "properties": {
                    "severity": f.get("severity", "low"),
                    "tool": tool_name,
                },
            }
            results.append(result)

        runs.append({
            "tool": {
                "driver": {
                    "name": f"AI-SSDLC / {tool_name}",
                    "version": "1.0.0",
                    "informationUri": (
                        "https://github.com/subzone/ssdlc-action"
                    ),
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }

    sarif_path.write_text(json.dumps(sarif, indent=2))
    print(f"SARIF written to {sarif_path} ({len(findings)} findings across {len(runs)} tools)")

if __name__ == "__main__":
    main()
