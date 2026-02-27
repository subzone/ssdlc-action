#!/usr/bin/env python3
"""Validate signed license tokens for tier entitlements."""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def load_revocations(path: Path) -> set[str] | None:
    """Return the set of revoked JTIs, or None if the file is unreadable/corrupt (fail closed)."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None  # fail closed: corrupted or unreadable file
    if not isinstance(data, dict):
        return None  # fail closed: unexpected JSON structure
    revoked = data.get("revoked_jti")
    if revoked is None:
        return set()
    if not isinstance(revoked, list):
        return None  # fail closed: revoked_jti has unexpected type
    return set(revoked)


def load_public_key(path: Path) -> Ed25519PublicKey | None:
    if not path.exists():
        return None
    pem = path.read_text(encoding="utf-8")
    if "REPLACE_WITH_YOUR_ED25519_PUBLIC_KEY" in pem:
        return None
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except Exception:
        return None
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key must be an Ed25519 key")
    return key


def validate_signed_token(
    token: str,
    public_key: Ed25519PublicKey,
    revoked_jti: set[str],
) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "SSDL1":
        return {
            "valid": False,
            "tier": "free",
            "reason": "invalid_format",
        }

    payload_part = parts[1]
    signature_part = parts[2]

    try:
        payload_bytes = b64url_decode(payload_part)
        signature = b64url_decode(signature_part)
    except Exception:
        return {
            "valid": False,
            "tier": "free",
            "reason": "invalid_encoding",
        }

    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return {
            "valid": False,
            "tier": "free",
            "reason": "invalid_signature",
        }

    try:
        claims = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "valid": False,
            "tier": "free",
            "reason": "invalid_payload",
        }
    now = int(time.time())

    plan = str(claims.get("plan", "free")).lower()
    if plan not in {"free", "pro", "enterprise"}:
        return {
            "valid": False,
            "tier": "free",
            "reason": "invalid_plan",
            "claims": claims,
        }

    exp = claims.get("exp")
    if exp is not None and int(exp) < now:
        return {
            "valid": False,
            "tier": "free",
            "reason": "expired",
            "claims": claims,
        }

    nbf = claims.get("nbf")
    if nbf is not None and int(nbf) > now:
        return {
            "valid": False,
            "tier": "free",
            "reason": "not_yet_valid",
            "claims": claims,
        }

    jti = claims.get("jti")
    if jti and str(jti) in revoked_jti:
        return {
            "valid": False,
            "tier": "free",
            "reason": "revoked",
            "claims": claims,
        }

    return {
        "valid": True,
        "tier": plan,
        "reason": "ok",
        "claims": claims,
    }


def validate_legacy_prefix(key: str) -> dict[str, Any]:
    key_upper = key.upper()
    if key_upper.startswith("ENT-"):
        return {
            "valid": True,
            "tier": "enterprise",
            "reason": "legacy_prefix",
            "claims": {
                "jti": str(uuid.uuid4()),
                "plan": "enterprise",
            },
        }
    if key_upper.startswith("PRO-"):
        return {
            "valid": True,
            "tier": "pro",
            "reason": "legacy_prefix",
            "claims": {
                "jti": str(uuid.uuid4()),
                "plan": "pro",
            },
        }
    return {
        "valid": False,
        "tier": "free",
        "reason": "unknown_legacy_key",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--public-key-file",
        default="/action/src/licensing/public_key.pem",
    )
    parser.add_argument(
        "--revocations-file",
        default="/action/src/licensing/revocations.json",
    )
    parser.add_argument(
        "--allow-legacy-prefix",
        default="false",
        choices=["true", "false"],
    )
    args = parser.parse_args()

    # Read license key from environment variable only to avoid leaking in process listings
    key = os.environ.get("LICENSE_KEY", "").strip()
    if not key:
        print(json.dumps({"valid": False, "tier": "free", "reason": "no_key"}))
        return

    revocations = load_revocations(Path(args.revocations_file))
    if revocations is None:
        print(
            json.dumps(
                {
                    "valid": False,
                    "tier": "free",
                    "reason": "revocation_load_error",
                },
                separators=(",", ":"),
            )
        )
        return

    public_key = load_public_key(Path(args.public_key_file))

    if public_key is not None:
        result = validate_signed_token(key, public_key, revocations)
    else:
        result = {
            "valid": False,
            "tier": "free",
            "reason": "missing_public_key",
        }

    if (
        not result.get("valid", False)
        and result.get("reason") == "invalid_format"
        and args.allow_legacy_prefix == "true"
    ):
        legacy = validate_legacy_prefix(key)
        if legacy.get("valid", False):
            result = legacy

    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
