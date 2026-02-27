#!/usr/bin/env python3
"""Count findings by severity and determine threshold breach."""
import json
import sys
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

def main():
    findings_path     = Path(sys.argv[1])
    threshold         = sys.argv[2].lower() if len(sys.argv) > 2 else "high"

    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["low"] += 1

    total = sum(counts.values())

    # Count findings at or above the threshold
    threshold_sevs = SEVERITY_ORDER[:SEVERITY_ORDER.index(threshold) + 1]
    threshold_count = sum(counts[s] for s in threshold_sevs)

    result = {
        "total":           total,
        "critical":        counts["critical"],
        "high":            counts["high"],
        "medium":          counts["medium"],
        "low":             counts["low"],
        "threshold":       threshold,
        "threshold_count": threshold_count,
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
