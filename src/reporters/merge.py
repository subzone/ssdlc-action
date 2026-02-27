#!/usr/bin/env python3
"""Merge tool-specific findings into the master findings.json file."""
import json
import sys
from pathlib import Path

def main():
    master_path = Path(sys.argv[1])
    new_path    = Path(sys.argv[2])
    tool_name   = sys.argv[3] if len(sys.argv) > 3 else "unknown"

    master = json.loads(master_path.read_text()) if master_path.exists() else []
    if not isinstance(master, list):
        master = []

    new_findings = json.loads(new_path.read_text()) if new_path.exists() else []
    if not isinstance(new_findings, list):
        new_findings = []

    # Tag each finding with the tool name (in case normaliser didn't)
    for f in new_findings:
        if "tool" not in f:
            f["tool"] = tool_name

    master.extend(new_findings)
    master_path.write_text(json.dumps(master, indent=2))
    print(f"Merged {len(new_findings)} findings from {tool_name}. Total: {len(master)}")

if __name__ == "__main__":
    main()
