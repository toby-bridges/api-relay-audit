# OpenClaw and Hermes Skill Distribution

This document tracks the publish path for API Relay Audit as an agent skill.
It is operational release documentation, not a user-facing safety claim.

## Current Skill Files

| Target | File | Role |
| --- | --- | --- |
| OpenClaw / ClawHub | `SKILL.md` | Root skill file used for ClawHub publish. `.clawhubignore` keeps the published bundle to this file. |
| Hermes Agent | `skills/api-relay-audit/SKILL.md` | Hermes skill folder for GitHub tap, direct install, and Skills Hub publish. |

Both files must stay aligned with the current audit surface:

- version `2.3.0`
- audit script ref `fa12ae8513ef77c13c4cd8227a47e9121a257504`
- 14 audit steps
- local-first execution
- API key not repeated in chat, logs, filenames, or public comments
- no claim that a relay is certified safe

The skill files are versioned distribution artifacts, so their `audit.py`
download commands must use an immutable tag or commit SHA. Do not publish a
versioned skill that downloads mutable `master/audit.py`.

## OpenClaw / ClawHub

ClawHub publishes a skill folder centered on `SKILL.md`. The registry extracts
frontmatter metadata, uses `description` for search, and expects runtime
requirements under `metadata.openclaw`.

Publish after the README / Pages PR has merged:

```bash
npm i -g clawhub
clawhub --version
clawhub login
clawhub whoami

clawhub skill publish . \
  --slug api-relay-audit \
  --name "API Relay Audit" \
  --version 2.3.0 \
  --changelog "Local 14-step AI API relay and LLM proxy security audit skill."
```

Notes:

- Publishing a skill to ClawHub releases the skill bundle under ClawHub's skill
  license terms. Because `.clawhubignore` publishes only `SKILL.md`, the main
  repository code remains governed by `AGPL-3.0-only`.
- Confirm the ClawHub bundle contains only `SKILL.md` before publishing.
- Do not include API keys, test reports, private relay URLs, or generated audit
  output in the skill bundle.
- Confirm the runtime script URL in `SKILL.md` is pinned to an immutable tag or
  commit SHA.
- If ClawHub offers a dry-run or review preview in the installed CLI, run it
  before the final publish command.

Post-publish verification:

```bash
openclaw skills search "api relay audit"
openclaw skills info api-relay-audit
openclaw skills install api-relay-audit
openclaw skills check
```

## Hermes Agent

Hermes supports direct install, GitHub taps, Skills Hub publishing, and
well-known discovery endpoints. The repo currently supports GitHub tap install
from `skills/api-relay-audit/SKILL.md`.

Direct install:

```bash
hermes skills install toby-bridges/api-relay-audit/skills/api-relay-audit
```

Tap install:

```bash
hermes skills tap add toby-bridges/api-relay-audit
hermes skills install toby-bridges/api-relay-audit/api-relay-audit
```

Skills Hub publish after merge:

```bash
hermes --version
hermes auth status
hermes skills publish skills/api-relay-audit \
  --to github \
  --repo toby-bridges/api-relay-audit
```

Post-publish verification:

```bash
hermes skills list | grep api-relay-audit
hermes chat --toolsets skills -q "Use the api-relay-audit skill to explain how to audit a relay without exposing my API key."
```

## Search Positioning

Primary concepts stay unchanged:

- API Relay Audit
- AI API relay security audit
- LLM proxy security

Skill-specific long-tail phrases:

- OpenClaw skill for AI API relay audit
- OpenClaw prompt injection relay audit
- Hermes skill for LLM proxy security
- Hermes Agent API key relay audit

Use these phrases naturally in README and Pages. Do not rename the project or
make OpenClaw / Hermes the primary concept.
