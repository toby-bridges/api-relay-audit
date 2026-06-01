---
name: api-relay-audit
description: Use when auditing third-party AI API relays, proxy APIs, or API-key resale services for hidden prompt injection, prompt leakage, instruction override, context truncation, tool-call substitution, error leakage, SSE stream anomalies, Web3 wallet-safety prompt injection, infrastructure fingerprints, latency variance, and upstream channel mismatches.
version: 2.3.0
author: Toby Bridges
license: AGPL-3.0-only
platforms: [linux, macos]
metadata:
  hermes:
    tags: [security, red-teaming, ai-safety, api-relay, web3]
    related_skills: []
required_environment_variables:
  - name: API_RELAY_AUDIT_KEY
    prompt: API relay key
    help: Use a temporary or low-scope key for the relay being tested.
    required_for: Running relay audits without pasting secrets into chat
---

# API Relay Audit for Hermes Agent

## Overview

This skill runs `api-relay-audit`, a zero-dependency security audit for third-party AI API relays and proxy services. It checks whether the relay tampers with prompts, truncates context, rewrites package-install instructions, leaks upstream credentials or internal headers, corrupts Anthropic SSE streams, changes the upstream channel, or injects unsafe Web3 wallet behavior.

Use the standalone `audit.py` path by default. It only needs Python 3 and `curl`, which makes it suitable for local Hermes terminal sessions and sandboxed execution.

## When to Use

- The user asks whether an AI API relay, proxy API, resale key, or "API relay" is safe.
- The user provides a relay base URL and wants an evidence-based risk report.
- The user suspects hidden prompts, identity substitution, response tampering, context truncation, tool-call/package substitution, or stream anomalies.
- The user wants to audit Web3/wallet safety behavior with `--profile web3` or `--profile full`.

Do not use this skill for general model benchmarking, provider price comparison, or legal/security certification. The output is a technical audit report, not a guarantee that a service is safe.

## Install or Share

After this file is merged to the public repository, Hermes users can install it as a tap skill:

```bash
hermes skills tap add toby-bridges/api-relay-audit
hermes skills install toby-bridges/api-relay-audit/api-relay-audit
```

For direct testing without adding the whole tap:

```bash
hermes skills install toby-bridges/api-relay-audit/skills/api-relay-audit
```

## Required Inputs

| Input | How to provide it | Notes |
|---|---|---|
| Relay API key | Prefer `$API_RELAY_AUDIT_KEY` via Hermes secure env setup | Use a temporary or low-scope key when possible. |
| Base URL | Ask the user or use `$API_RELAY_AUDIT_URL` if already set | Example: `https://relay.example.com/v1`. |
| Model | Optional; default is `claude-opus-4-6` | Use the model the user plans to rely on. |
| Profile | Optional; default is `general` | Use `web3` for wallet users, `full` for complete coverage. |

Never print the raw API key in summaries, filenames, reports, shell traces, or GitHub comments. If the user pasted a key into chat, avoid repeating it and recommend rotating it after the audit if exposure matters.

## Standard Workflow

1. Confirm the target base URL, model, and profile.
2. Ensure the key is available as `$API_RELAY_AUDIT_KEY`. If it is missing, ask the user to configure it through Hermes secure setup or local `.env`, not by committing it.
3. Download the standalone script into a temporary directory unless the current repo already contains `audit.py`.
4. Run the audit and write a Markdown report.
5. Summarize only evidence from the generated report. Do not overstate safety or make policy promises.

## One-Shot Audit Recipe

Use this when the user provides a base URL and wants a normal audit:

```bash
set -euo pipefail

: "${API_RELAY_AUDIT_KEY:?Set API_RELAY_AUDIT_KEY through Hermes secure env setup first}"
: "${API_RELAY_AUDIT_URL:?Set API_RELAY_AUDIT_URL to the relay base URL}"

MODEL="${API_RELAY_AUDIT_MODEL:-claude-opus-4-6}"
PROFILE="${API_RELAY_AUDIT_PROFILE:-general}"
WORKDIR="$(mktemp -d)"
REPORT="$PWD/api-relay-audit-report.md"

curl -fsSL \
  https://raw.githubusercontent.com/toby-bridges/api-relay-audit/master/audit.py \
  -o "$WORKDIR/audit.py"

python3 "$WORKDIR/audit.py" \
  --key "$API_RELAY_AUDIT_KEY" \
  --url "$API_RELAY_AUDIT_URL" \
  --model "$MODEL" \
  --profile "$PROFILE" \
  --output "$REPORT"

printf 'Report written to %s\n' "$REPORT"
```

If the current working tree is the `api-relay-audit` repository and `audit.py` exists, prefer the local file:

```bash
python3 audit.py \
  --key "$API_RELAY_AUDIT_KEY" \
  --url "$API_RELAY_AUDIT_URL" \
  --model "${API_RELAY_AUDIT_MODEL:-claude-opus-4-6}" \
  --profile "${API_RELAY_AUDIT_PROFILE:-general}" \
  --output api-relay-audit-report.md
```

## Profiles and Cost Controls

| Scenario | Recommended flags |
|---|---|
| Fast first pass | `--skip-infra --skip-context --skip-latency-variance` |
| Normal relay audit | `--profile general` |
| Web3 or wallet relay | `--profile web3` |
| Complete audit | `--profile full` |
| Suspicious relay with request-count gating | `--warmup 5` to `--warmup 20` |
| Avoid intentionally broken requests | `--skip-error-leakage` |
| Avoid streaming checks | `--skip-stream-integrity` |
| Avoid upstream channel classification | `--skip-channel-classifier` |

Warn the user before enabling `--aggressive-error-probes` because oversized probes can create metered usage on pay-as-you-go relays.

## What the 14 Steps Cover

| Step | Area | Purpose |
|---|---|---|
| 1 | Infrastructure recon | DNS, WHOIS, SSL, HTTP headers, and panel hints. |
| 2 | Model list | Available models, model count, and ownership fields. |
| 3 | Token injection | Hidden system-prompt size via token delta. |
| 4 | Prompt extraction | Direct attempts to extract hidden prompts. |
| 5 | Instruction conflict and identity | Whether user instructions and identity settings are overridden. |
| 6 | Jailbreak extraction | Indirect prompt-extraction attempts. |
| 7 | Context length | Canary-based truncation detection. |
| 8 | Tool-call substitution | Package-install command rewriting, AC-1.a. |
| 9 | Error leakage | Credential, header, stack trace, path, and internal-field leakage. |
| 10 | Stream integrity | SSE event whitelist, usage monotonicity, signatures, and stream model identity. |
| 11 | Web3 prompt injection | Wallet-safety refusal probes, profile-gated. |
| 12 | Infrastructure fingerprint | Known relay framework signatures, informational only. |
| 13 | Latency variance | Bimodal or unstable routing hints, informational only. |
| 14 | Upstream channel classifier | Bedrock, Vertex, OpenRouter, Cloudflare AI Gateway, or transparent Anthropic relay hints from headers, message IDs, and body signals. |

## Report Summary Template

After running the audit, summarize in this format:

```markdown
## Audit Result: <relay host>

Overall risk: LOW / MEDIUM / HIGH

- Token injection: <delta or unavailable>
- Prompt extraction: <count or summary>
- User control: <instruction/identity result>
- Context length: <full/truncated/inconclusive>
- Tool-call substitution: <clean/substituted/inconclusive>
- Error leakage: <none/medium/high/critical/inconclusive>
- Stream integrity: <clean/anomaly/inconclusive>
- Upstream channel: <direct/known channel/transparent/inconclusive>
- Web3 profile: <not run/clean/injected/inconclusive>
- Informational: <infra fingerprint and latency variance highlights>

Recommendation: <use / use with caution / do not use>, based only on the report evidence.
```

## Common Pitfalls

1. Do not treat "no finding" as proof of safety. It only means these probes did not catch tampering.
2. Do not paste or repeat API keys in chat. Prefer `API_RELAY_AUDIT_KEY`.
3. Do not skip dual-distribution context when editing the project itself: changes to modular audit logic usually need root `audit.py` parity.
4. Do not promise product timelines, vendor cooperation, or risk-policy changes from an audit result.
5. If a relay is non-Anthropic or does not support thinking streams, Step 10 may be inconclusive rather than clean.

## Verification Checklist

- [ ] `SKILL.md` frontmatter has `name`, `description`, `version`, `author`, `license`, and `metadata.hermes.tags`.
- [ ] Description is under 1024 characters and starts with "Use when".
- [ ] The audit command uses `$API_RELAY_AUDIT_KEY`, not a literal key.
- [ ] The report was generated as Markdown and the key was not echoed.
- [ ] Any public reply or GitHub comment is grounded only in the report, README, ROADMAP, FOR_JOHN, or current code.
