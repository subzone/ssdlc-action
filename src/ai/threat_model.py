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
MAX_FILES       = 10       # cap number of changed files sent

def get_changed_files(workspace: str) -> list[str]:
    """Get files changed in the current PR/push."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            capture_output=True, text=True, cwd=workspace
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except Exception:
        return []

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
    parser.add_argument("--model",     default="claude-sonnet-4-5-20250929")
    parser.add_argument("--cloud",     default="aws")
    args = parser.parse_args()

    api_key = os.environ.get("AI_API_KEY", "")
    if not api_key:
        print(json.dumps({"summary": "Threat modeling skipped — no API key."}))
        return

    changed = get_changed_files(args.workspace)
    arch_files = [
        f for f in changed
        if Path(f).suffix.lower() in ARCH_EXTENSIONS
    ][:MAX_FILES]

    if not arch_files:
        print(json.dumps({
            "summary": "No architecture or IaC files changed in this PR.",
            "overall_risk": "none",
            "stride_analysis": {},
            "recommended_actions": [],
        }))
        return

    file_contents = {}
    for f in arch_files:
        content = read_file_content(f, args.workspace)
        if content:
            file_contents[f] = content

    system_prompt_path = Path("/action/src/ai/prompts/threat_model_system.txt")
    system_prompt = system_prompt_path.read_text() if system_prompt_path.exists() else ""

    files_text = "\n\n".join(
        f"=== FILE: {name} ===\n{content}"
        for name, content in file_contents.items()
    )

    user_prompt = f"""Please perform a STRIDE threat model analysis on these changed files.
Cloud provider: {args.cloud}
Changed files ({len(arch_files)}): {', '.join(arch_files)}

FILE CONTENTS:
{files_text}

Return ONLY valid JSON matching the schema in your instructions. No markdown, no code blocks."""

    try:
        raw = call_ai(system_prompt, user_prompt, args.provider, args.model, api_key)
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
