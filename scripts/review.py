#!/usr/bin/env python3
"""AI PR Security Reviewer.

Reads Bandit (Python SAST) and Trivy (dependency / vulnerability) findings,
asks Gemini to explain each one in plain English with a concrete fix and a
mapped compliance control (SOX / MiFID II / Basel III), then posts the result
as a comment on the pull request.

Runs inside GitHub Actions. Required env vars:
  GEMINI_API_KEY   - from repo secrets
  GITHUB_TOKEN     - provided automatically by Actions (map it in the workflow)
  GITHUB_REPOSITORY, GITHUB_EVENT_PATH - set automatically by Actions
"""
import json
import os
import sys

import requests
from google import genai

MODEL = "gemini-2.5-flash"   # free-tier model; change this one string if deprecated
MAX_FINDINGS = 25            # keep the prompt small and inside free-tier limits


def load_json(path):
    """Load a JSON file, returning None if missing or unparsable."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def collect_bandit(data):
    findings = []
    if not data:
        return findings
    for r in data.get("results", []):
        findings.append({
            "source": "Bandit (SAST)",
            "severity": r.get("issue_severity", "UNKNOWN"),
            "title": r.get("test_name") or r.get("test_id", "Issue"),
            "detail": r.get("issue_text", ""),
            "location": f'{r.get("filename", "?")}:{r.get("line_number", "?")}',
        })
    return findings


def collect_trivy(data):
    findings = []
    if not data:
        return findings
    for res in data.get("Results", []) or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            detail = (v.get("Title") or v.get("Description") or "")[:300]
            findings.append({
                "source": "Trivy (dependency)",
                "severity": v.get("Severity", "UNKNOWN"),
                "title": f'{v.get("VulnerabilityID", "")} in {v.get("PkgName", "")}',
                "detail": detail,
                "location": target,
            })
    return findings


def build_prompt(findings):
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(
            f'{i}. [{f["severity"]}] {f["title"]} '
            f'({f["source"]}, {f["location"]})\n   {f["detail"]}'
        )
    findings_block = "\n".join(lines)
    return f"""You are a senior application security engineer reviewing a pull
request for a financial-services company. Below are raw findings from automated
scanners.

For EACH finding, write a short, plain-English review entry containing:
- **Severity** (Critical / High / Medium / Low)
- **What & why it matters** (1-2 sentences, no jargon)
- **How to fix** (concrete and specific)
- **Compliance** - map it to the most relevant control among SOX, MiFID II, or
  Basel III and name it. If none genuinely applies, write "General security hygiene."

Begin with a one-line overall summary (counts by severity). Use clean GitHub
Markdown with a short heading per finding. Be concise. Do NOT invent findings
beyond those listed below.

FINDINGS:
{findings_block}
"""


def review_text(findings):
    client = genai.Client()  # reads GEMINI_API_KEY from the environment
    resp = client.models.generate_content(
        model=MODEL,
        contents=build_prompt(findings),
    )
    return resp.text


def post_comment(body):
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event = load_json(os.environ.get("GITHUB_EVENT_PATH", "")) or {}
    pr = event.get("pull_request", {}).get("number")

    if not (token and repo and pr):
        print("Missing GitHub context (token/repo/PR number); printing instead:\n")
        print(body)
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    r = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    r.raise_for_status()
    print(f"Posted review comment to PR #{pr}.")


def main():
    findings = collect_bandit(load_json("bandit-results.json"))
    findings += collect_trivy(load_json("trivy-results.json"))

    if not findings:
        post_comment("## AI Security Review\n\nNo issues found by Bandit or Trivy "
                     "on this PR. \u2705")
        return

    findings = findings[:MAX_FINDINGS]
    try:
        review = review_text(findings)
    except Exception as e:  # noqa: BLE001 - surface any API/SDK error clearly
        print(f"Gemini call failed: {e}", file=sys.stderr)
        sys.exit(1)

    header = ("## AI Security Review\n"
              "_Automated review of SAST + dependency findings, with compliance "
              "mapping (SOX / MiFID II / Basel III)._\n\n")
    post_comment(header + review)


if __name__ == "__main__":
    main()