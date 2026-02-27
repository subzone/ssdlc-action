#!/usr/bin/env python3
"""Generate Ed25519 keypair for license signing/verification."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--private-key-out",
        default="tools/licensing/private_key.pem",
        help="Path to write private key PEM",
    )
    parser.add_argument(
        "--public-key-out",
        default="src/licensing/public_key.pem",
        help="Path to write public key PEM",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing private key file if it exists",
    )
    args = parser.parse_args()

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = Path(args.private_key_out)
    public_path = Path(args.public_key_out)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if args.force else os.O_EXCL)
    try:
        fd = os.open(private_path, flags, 0o600)
    except FileExistsError:
        raise SystemExit(
            f"Private key already exists at {private_path}. "
            "Use --force to overwrite."
        )
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    public_path.write_bytes(public_pem)

    print(f"Private key written to: {private_path}")
    print(f"Public key written to: {public_path}")
    print("Keep private key secret. Commit only the public key.")


if __name__ == "__main__":
    main()
