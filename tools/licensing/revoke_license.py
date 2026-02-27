#!/usr/bin/env python3
"""Revoke issued licenses by jti."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jti", required=True, help="License jti to revoke")
    parser.add_argument(
        "--revocations-file",
        default="src/licensing/revocations.json",
        help="Path to revocations JSON",
    )
    args = parser.parse_args()

    path = Path(args.revocations_file)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = {"revoked_jti": []}

    revoked = data.get("revoked_jti", [])
    if args.jti not in revoked:
        revoked.append(args.jti)

    data["revoked_jti"] = sorted(set(revoked))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    print(f"Revoked jti added: {args.jti}")
    print(f"Updated: {path}")


if __name__ == "__main__":
    main()
