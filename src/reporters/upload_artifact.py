#!/usr/bin/env python3
"""
Upload a file as a GitHub Actions artifact using the Actions Runtime API.

Uses the v1 artifact API backed by ACTIONS_RUNTIME_URL / ACTIONS_RUNTIME_TOKEN,
which GitHub injects into every step in a workflow run (including Docker actions).

Called from entrypoint.sh to make findings.json available via the GitHub
Artifacts REST API so the SSDLC platform dashboard can fetch and display
per-run vulnerability details.

Usage:
    python3 upload_artifact.py <findings_path> [artifact_name]
"""
import os
import sys
from urllib.parse import urlencode, urlparse

import requests


def main() -> int:  # noqa: PLR0911
    findings_path = sys.argv[1] if len(sys.argv) > 1 else ".ssdlc-results/findings.json"
    artifact_name = sys.argv[2] if len(sys.argv) > 2 else "ssdlc-findings"

    runtime_url   = os.environ.get("ACTIONS_RUNTIME_URL", "")
    runtime_token = os.environ.get("ACTIONS_RUNTIME_TOKEN", "")
    run_id        = os.environ.get("GITHUB_RUN_ID", "")

    if not all([runtime_url, runtime_token, run_id]):
        print("GitHub Actions runtime vars not available — skipping artifact upload")
        return 0

    if not os.path.exists(findings_path):
        print(f"Findings file not found at {findings_path} — skipping artifact upload")
        return 0

    with open(findings_path, "rb") as fh:
        content = fh.read()

    if not content or content.strip() == b"[]":
        print("No findings to upload — skipping artifact upload")
        return 0

    base_url = runtime_url.rstrip("/")
    json_headers = {
        "Authorization": f"Bearer {runtime_token}",
        "Accept": "application/json;api-version=6.0-preview",
        "Content-Type": "application/json",
    }

    # ── Step 1: Create artifact container ────────────────────────────────────
    create_resp = requests.post(
        f"{base_url}/_apis/pipelines/workflows/{run_id}/artifacts",
        headers=json_headers,
        json={"type": "actions_storage", "name": artifact_name},
        timeout=30,
    )
    if create_resp.status_code not in (200, 201):
        # Log only the HTTP status — response body may contain auth tokens (CWE-532)
        print(f"Failed to create artifact container: HTTP {create_resp.status_code}")
        return 1

    try:
        container_url = create_resp.json().get("fileContainerResourceUrl", "")
    except ValueError:
        print("Invalid JSON response from artifact create API — cannot upload")
        return 1

    if not container_url:
        print("No fileContainerResourceUrl in artifact create response — cannot upload")
        return 1

    # ── Step 2: Upload file content ───────────────────────────────────────────
    # Build the upload URL by appending the item path to the container URL's
    # path segment and setting itemPath as the sole query param.  Using
    # urllib.parse ensures existing query params in the container URL are not
    # duplicated or malformed.
    item_path = "findings.json"
    parsed    = urlparse(container_url)
    new_path  = parsed.path.rstrip("/") + "/" + item_path
    upload_url = parsed._replace(path=new_path, query=urlencode({"itemPath": item_path})).geturl()

    upload_resp = requests.put(
        upload_url,
        headers={
            "Authorization": f"Bearer {runtime_token}",
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(content)),
        },
        data=content,
        timeout=60,
    )
    if upload_resp.status_code not in (200, 201):
        print(f"Failed to upload artifact file: HTTP {upload_resp.status_code}")
        return 1

    # ── Step 3: Finalize (patch size) ─────────────────────────────────────────
    # 400 means the artifact was already finalised — treat as success.
    finalize_resp = requests.patch(
        f"{base_url}/_apis/pipelines/workflows/{run_id}/artifacts",
        headers=json_headers,
        params={"artifactName": artifact_name},
        json={"size": len(content)},
        timeout=30,
    )
    if finalize_resp.status_code not in (200, 201, 400):
        print(f"Warning: artifact finalize returned HTTP {finalize_resp.status_code}")

    print(
        f"Successfully uploaded {len(content):,} bytes "
        f"as GitHub artifact '{artifact_name}'"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
