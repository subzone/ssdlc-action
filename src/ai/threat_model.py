#!/usr/bin/env python3
"""
AI Threat Modelling (STRIDE)
Analyses changed architecture/IaC files and produces a STRIDE threat model.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ARCH_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".bicep",
                   ".template", ".hcl", ".md", ".drawio", ".puml"}
MAX_FILE_SIZE   = 50_000   # chars — don't send huge files to AI
MAX_FILES       = 10       # cap number of files sent to AI

# Directories to skip when walking the repo
_EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "dist", "build", ".cache", "coverage", ".mypy_cache",
                 ".pytest_cache", ".ruff_cache"}

def get_pr_changed_arch_files(workspace: str) -> list[str]:
    """
    Return arch/IaC files changed in this PR or push.
    Tries the full PR range (origin/main...HEAD) first, then falls back to
    the last commit (HEAD~1..HEAD).  Returns an empty list if neither yields
    anything useful.
    """
    for ref in ("origin/main...HEAD", "HEAD~1..HEAD"):
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", ref],
                capture_output=True, text=True, cwd=workspace,
            )
            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
                arch = [f for f in files if Path(f).suffix.lower() in ARCH_EXTENSIONS]
                if arch:
                    return arch
        except Exception:
            pass
    return []

def get_repo_arch_files(workspace: str) -> list[str]:
    """
    Walk the repo and collect architecture/IaC files for a full-repo scan,
    skipping noise directories.  Prioritises Terraform, Helm, Docker, CI files.
    """
    ws = Path(workspace)
    # Priority file names collected first
    priority_names = {"Chart.yaml", "values.yaml", "docker-compose.yml",
                      "docker-compose.yaml", "action.yml", "action.yaml"}
    priority: list[str] = []
    rest: list[str] = []

    for path in ws.rglob("*"):
        if any(part in _EXCLUDE_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in ARCH_EXTENSIONS:
            continue
        rel = str(path.relative_to(ws))
        if path.name in priority_names or path.suffix in {".tf", ".hcl"}:
            priority.append(rel)
        else:
            rest.append(rel)

    return (priority + rest)[:MAX_FILES]

def read_file_content(path: str, workspace: str) -> str:
    full = Path(workspace) / path
    if not full.exists():
        return ""
    content = full.read_text(errors="replace")
    return content[:MAX_FILE_SIZE]

def call_ai(system_prompt: str, user_prompt: str, provider: str, model: str, api_key: str) -> str:
    if provider.lower() == "anthropic":
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=model, max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return msg.content[0].text
    elif provider.lower() == "github":
        import openai
        try:
            client = openai.OpenAI(
                base_url="https://models.inference.ai.azure.com",
                api_key=api_key,
            )
            resp = client.chat.completions.create(
                model=model, max_tokens=4096,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
            )
            return resp.choices[0].message.content
        except openai.AuthenticationError as e:
            raise RuntimeError(
                f"GitHub Models authentication failed. Ensure GITHUB_TOKEN has required permissions: {e}"
            ) from e
    else:
        import openai
        client = openai.OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model, max_tokens=4096,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        )
        return resp.choices[0].message.content

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--provider",  default="anthropic")
    parser.add_argument("--model",     default="claude-sonnet-4-6")
    parser.add_argument("--cloud",     default="aws")
    args = parser.parse_args()

    api_key = os.environ.get("AI_API_KEY", "")
    # For GitHub Models, GITHUB_TOKEN is the credential; AI_API_KEY is a fallback
    if args.provider.lower() == "github":
        effective_key = os.environ.get("GITHUB_TOKEN", "") or api_key
    else:
        effective_key = api_key
    if not effective_key:
        print(json.dumps({"summary": "Threat modeling skipped — no API key."}))
        return

    # Prefer PR-changed arch files; fall back to a full repo scan so threat
    # modeling always produces output even when no IaC/arch files were touched.
    arch_files = get_pr_changed_arch_files(args.workspace)
    if arch_files:
        scan_scope = "PR-changed files"
        arch_files = arch_files[:MAX_FILES]
    else:
        arch_files = get_repo_arch_files(args.workspace)
        scan_scope = "full repository architecture scan (no IaC/arch files changed in this PR)"

    file_contents = {}
    for f in arch_files:
        content = read_file_content(f, args.workspace)
        if content:
            file_contents[f] = content

    if not file_contents:
        print(json.dumps({
            "summary": "No readable architecture or IaC files found in this repository.",
            "overall_risk": "none",
            "stride_analysis": {},
            "recommended_actions": [],
        }))
        return

    system_prompt_path = Path("/action/src/ai/prompts/threat_model_system.txt")
    system_prompt = system_prompt_path.read_text() if system_prompt_path.exists() else ""

    files_text = "\n\n".join(
        f"=== FILE: {name} ===\n{content}"
        for name, content in file_contents.items()
    )

    user_prompt = f"""Please perform a STRIDE threat model analysis on these architecture/IaC files.
Cloud provider: {args.cloud}
Scan scope: {scan_scope}
Files analysed ({len(file_contents)}): {', '.join(file_contents.keys())}

FILE CONTENTS:
{files_text}

Return ONLY valid JSON matching the schema in your instructions. No markdown, no code blocks."""

    try:
        raw = call_ai(system_prompt, user_prompt, args.provider, args.model, effective_key)
        parsed = json.loads(raw)
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(json.dumps({"summary": raw, "overall_risk": "unknown",
                          "stride_analysis": {}, "recommended_actions": []}))
    except Exception as e:
        print(f"Threat modeling error: {e}", file=sys.stderr)
        print(json.dumps({"summary": f"Threat modeling failed: {e}",
                          "overall_risk": "unknown", "stride_analysis": {},
                          "recommended_actions": []}))

if __name__ == "__main__":
    main()
