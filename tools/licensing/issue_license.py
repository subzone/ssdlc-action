#!/usr/bin/env python3
"""Issue signed SSDL1 license tokens."""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--private-key",
        required=True,
        help="Path to Ed25519 private key PEM",
    )
    parser.add_argument("--plan", required=True, choices=["pro", "enterprise"])
    parser.add_argument(
        "--customer",
        required=True,
        help="Customer identifier (email/org)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Validity window in days",
    )
    parser.add_argument(
        "--features",
        default="",
        help="Comma-separated feature flags",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Optional path to write issued token",
    )
    parser.add_argument(
        "--passphrase-env",
        default="PRIVATE_KEY_PASSPHRASE",
        metavar="ENV_VAR",
        help=(
            "Name of the environment variable containing the passphrase "
            "used to decrypt the private key (default: PRIVATE_KEY_PASSPHRASE)"
        ),
    )
    args = parser.parse_args()

    passphrase = os.environ.get(args.passphrase_env, "")
    key_bytes = Path(args.private_key).read_bytes()
    if not passphrase and b"ENCRYPTED" in key_bytes:
        raise SystemExit(
            f"Private key is encrypted but environment variable '{args.passphrase_env}' "
            "was not provided (it may be unset or empty). Set it to the passphrase used when generating the key."
        )
    private_key = serialization.load_pem_private_key(
        key_bytes,
        password=passphrase.encode("utf-8") if passphrase else None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519")

    now = int(time.time())
    claims = {
        "v": 1,
        "jti": str(uuid.uuid4()),
        "plan": args.plan,
        "sub": args.customer,
        "iat": now,
        "nbf": now,
        "exp": now + (args.days * 86400),
    }

    features = [x.strip() for x in args.features.split(",") if x.strip()]
    if features:
        claims["features"] = features

    payload = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = private_key.sign(payload)

    token = f"SSDL1.{b64url_encode(payload)}.{b64url_encode(signature)}"

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(token + "\n", encoding="utf-8")
        print(f"License token written to: {out_path}")
    else:
        print(token)

    print(json.dumps({"claims": claims}, indent=2))


if __name__ == "__main__":
    main()
