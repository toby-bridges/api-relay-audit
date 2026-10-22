# skills.sh — proposed installation material

Status: **draft; do not treat these as already-published candidate bytes**.

## Directory copy

Name: API Relay Audit

Description:

Run local, evidence-based audits of AI API relays and LLM proxies before
trusting sensitive traffic. Preserve the tool's reported risk, incomplete
coverage, and model-specific limitations. API keys and raw evidence stay local.

Source repository: https://github.com/toby-bridges/api-relay-audit

Skill path: `skills/api-relay-audit/SKILL.md`

License: AGPL-3.0-only

## Proposed install command

Use this only after the approved candidate reaches the public default branch:

```bash
npx skills@1.7.4 add \
  https://github.com/toby-bridges/api-relay-audit/tree/master/skills/api-relay-audit \
  --skill api-relay-audit --agent cursor --copy
```

The exact final public commit should replace `master` when publishing a
reproducible installation example. The Skill itself pins the audit engine's
release and SHA-256 independently.

For a review install that must not send installation telemetry:

```bash
DISABLE_TELEMETRY=1 DO_NOT_TRACK=1 npx skills@1.7.4 add \
  https://github.com/toby-bridges/api-relay-audit/tree/master/skills/api-relay-audit \
  --skill api-relay-audit --agent cursor --copy
```

The preparation verifier uses the candidate's local subdirectory, without
npx or network, and asserts that only SKILL.md is installed. Using only the
repository URL would select the root Skill and may copy unrelated files.

## Discovery and approval

[skills.sh FAQ](https://www.skills.sh/docs/faq) says listing and ranking follow
anonymous installation telemetry. There is no ordinary submission form in
that documented route. Publishing the GitHub files and validating installation
does not prove leaderboard inclusion or acquisition.

No indexing request or installation telemetry has been sent by this task.
Let real consenting users install the published Skill; do not simulate users,
repeat installs to boost ranking, or label this candidate as already listed.

[CLI installation and source formats](https://github.com/vercel-labs/skills/blob/a80e4c9d12d607631249d4d7d059f835d4b2f13a/docs/commands.md)
and [telemetry opt-out](https://github.com/vercel-labs/skills/blob/a80e4c9d12d607631249d4d7d059f835d4b2f13a/src/telemetry.ts)
were checked during preparation.
