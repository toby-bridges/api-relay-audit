# DeepSeek Harness Plugin Distribution

DeepSeek Harness is the primary integration distribution target for API Relay
Audit. This document is operational release documentation, not a user-facing
safety claim.

## Current Distribution Files

| Target | File | Role |
| --- | --- | --- |
| DeepSeek Harness | `package.json`, `dsh/` | Active GitHub-installable bundle that registers `/relay-audit` on DSH command-compatible clients and carries the generated standalone `audit.py`. |
| OpenClaw | `SKILL.md` | Retained direct integration file for existing users; no ClawHub registry publication is planned. |
| Hermes Agent | `skills/api-relay-audit/SKILL.md` | Retained direct integration file; not part of the current distribution or release gate. |

All retained integration files must stay aligned with the current audit surface:

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
DSH_PLUGIN_REF=v2.4.0
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

The release-specific evidence is in
[`distribution-verification-v2.4.0.md`](./distribution-verification-v2.4.0.md).

## Non-Primary Integrations

The root OpenClaw `SKILL.md` and Hermes
`skills/api-relay-audit/SKILL.md` remain available to existing direct users.
They are maintained for compatibility, but neither is an active registry
publication target or a release blocker. In particular, API Relay Audit does
not publish to ClawHub.

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

DSH-specific long-tail phrases:

- DSH plugin for AI API relay audit
- DeepSeek Harness Claude relay security audit

Use these phrases naturally in README and Pages. Do not rename the project or
make DeepSeek Harness the primary project concept.
