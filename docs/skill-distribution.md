# DSH, OpenClaw, and Hermes Distribution

This document tracks the distribution paths for API Relay Audit integrations.
It is operational release documentation, not a user-facing safety claim.

## Current Distribution Files

| Target | File | Role |
| --- | --- | --- |
| DeepSeek Harness | `package.json`, `dsh/` | GitHub-installable bundle that registers `/relay-audit` on DSH command-compatible clients and carries the generated standalone `audit.py`. |
| OpenClaw / ClawHub | `SKILL.md` | Root skill file used for ClawHub publish. `.clawhubignore` keeps the published bundle to this file. |
| Hermes Agent | `skills/api-relay-audit/SKILL.md` | Hermes skill folder for GitHub tap, direct install, and Skills Hub publish. |

Both files must stay aligned with the current audit surface:

- version `2.4.0`
- audit script ref `v2.4.0`
- 14 audit steps
- local-first execution
- API key not repeated in chat, logs, filenames, or public comments
- no claim that a relay is certified safe
- Hermes platform support includes Linux, macOS, and Windows. The Windows
  contract is Python 3 + `curl` with Git Bash or an equivalent POSIX shell for
  the one-shot recipe; direct local `python audit.py ...` commands can also run
  from PowerShell.

The skill files and DSH package are versioned distribution artifacts, so their `audit.py`
download commands must use an immutable tag or commit SHA. Do not publish a
versioned skill that downloads mutable `master/audit.py`.

## DeepSeek Harness

The DSH bundle is deliberately prebuilt JavaScript with no `prepare` or build
hook. A Git install therefore does not require pnpm's install-time build
allowlist. Install an immutable repository revision into each intended
profile:

```bash
DSH_PLUGIN_REF=<commit-sha-or-release-tag>
dsh plugin --profile web add "github:toby-bridges/api-relay-audit#${DSH_PLUGIN_REF}"
dsh plugin --profile cc-tui add "github:toby-bridges/api-relay-audit#${DSH_PLUGIN_REF}"
```

Compatibility contract:

- tested with DSH `0.1.0-rc.6` and `dsh-cc-tui` `0.4.1`;
- requires the DSH profile/bundle loader and `@deepseek-ai/dsh-commands`;
- resolves `baseURL`, model, and `apiKeyEnv` from the current configurable
  provider, with explicit command overrides for missing facts;
- resolves the credential per invocation and never puts the value in argv or
  the recorded command input;
- accepts Claude routes over either Anthropic-compatible or OpenAI-compatible
  APIs, but refuses non-Claude model families because the current identity and
  stream-integrity baselines are Claude-specific;
- writes reports under the current session workspace by default.

Post-install verification:

```bash
dsh --profile web --dump-config
dsh --profile cc-tui --dump-config
```

Both dumps must contain the `api-relay-audit` row. In a configured session,
`/relay-audit --connectivity` should create a local Markdown report without
placing the API key in the command input, result, process argv, or logs.

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
  --version 2.4.0 \
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

The supported Hermes distribution entrypoint is this repository's GitHub tap.
It installs `skills/api-relay-audit/SKILL.md` without opening a pull request
against the source repository:

```bash
hermes skills tap add toby-bridges/api-relay-audit
hermes skills install toby-bridges/api-relay-audit/api-relay-audit
```

Post-install verification:

```bash
hermes skills list | grep api-relay-audit
hermes skills audit api-relay-audit
hermes chat --toolsets skills -q "Use the api-relay-audit skill to explain how to audit a relay without exposing my API key."
```

Windows dogfood must also verify that Hermes can load the installed skill, not
just install it. A successful direct install followed by a platform-gated
`skill_view` failure is a distribution bug.

## Search Positioning

Primary concepts stay unchanged:

- API Relay Audit
- AI API relay security audit
- LLM proxy security

Do not merge these project-level query families into one marketplace slogan:

- API relay audit
- prompt injection audit
- model substitution signals
- Web3 relay audit

Skill-specific long-tail phrases:

- DSH plugin for AI API relay audit
- DeepSeek Harness Claude relay security audit
- OpenClaw skill for AI API relay audit
- OpenClaw prompt injection relay audit
- Hermes skill for LLM proxy security
- Hermes Agent API key relay audit

Use these phrases naturally in README and Pages. Do not rename the project or
make DSH / OpenClaw / Hermes the primary concept.
