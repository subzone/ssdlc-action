#!/usr/bin/env python3
"""Generate Ed25519 keypair for license signing/verification."""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
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
    parser.add_argument(
        "--passphrase-env",
        default="PRIVATE_KEY_PASSPHRASE",
        metavar="ENV_VAR",
        help=(
            "Name of the environment variable containing the passphrase "
            "used to encrypt the private key (default: PRIVATE_KEY_PASSPHRASE)"
        ),
    )
    args = parser.parse_args()

    passphrase = os.environ.get(args.passphrase_env)
    if passphrase is None or passphrase == "":
        raise SystemExit(
            f"Environment variable '{args.passphrase_env}' must be set and non-empty "
            "(it is currently unset or empty). "
            "The private key will be encrypted with this passphrase."
        )
    if len(passphrase) < 12:
        raise SystemExit(
            f"Passphrase in '{args.passphrase_env}' is too short. "
            "Use at least 12 characters for adequate encryption strength."
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = Path(args.private_key_out)
    public_path = Path(args.public_key_out)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.force and private_path.exists():
        raise SystemExit(
            f"Private key already exists at {private_path}. "
            "Use --force to overwrite."
        )

    # Reject non-regular files (e.g. symlinks, devices) before writing
    if private_path.exists():
        st = os.lstat(private_path)
        if not stat.S_ISREG(st.st_mode):
            raise SystemExit(
                f"{private_path} exists and is not a regular file. Aborting."
            )

    # Write to a temporary file with 0o600 permissions in the same directory,
    # then atomically replace the destination so:
    #   1. The file is never readable by others at any point.
    #   2. os.replace() does not follow symlinks at the destination.
    tmp_fd, tmp_path = tempfile.mkstemp(dir=private_path.parent)
    try:
        os.fchmod(tmp_fd, 0o600)
        with os.fdopen(tmp_fd, "wb") as fh:
            fh.write(private_pem)
        os.replace(tmp_path, private_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    public_path.write_bytes(public_pem)

    print(f"Private key written to: {private_path} (encrypted with passphrase)")
    print(f"Public key written to: {public_path}")
    print(
        f"Keep private key secret. Store the passphrase securely. "
        "Commit only the public key."
    )


if __name__ == "__main__":
    main()
