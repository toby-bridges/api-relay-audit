# Implementation Notes

> Task: DSH plugin hardening and first-use clarity on remote master cfb8da4
> Spec: User's three-stage optimization schedule (2026-10-01)
> Started: 2026-10-01
> Completed: 2026-10-03 16:55 CST

---

## Design Decisions

| # | Decision | Context | Alternative considered |
|---|----------|---------|----------------------|
| 1 | Keep the existing DSH route gate unchanged during the first security slice. | The released DSH adapter and its tests currently use a Claude-specific baseline. This does not define the broader project goal, which includes Claude and Codex audit workflows. | Expand the adapter's model acceptance without a separate baseline. |
| 2 | Expose the shared curl header-config helper through the standalone transport facade. | The generated client calls `_transport.curl_header_config`; the builder constructs that facade explicitly. | Duplicate header formatting in the client. |
| 3 | State the Claude-only and metered-run boundaries in `/relay-audit --help` and the DSH guide. | README already documented both, but users can reach the command or guide without reading README. | Repeat the whole compatibility document in the command help. |
| 4 | Distinguish the pinned v2.4.0 artifact from the unreleased curl fix in public copy. | The installed tag is immutable and still has the process-argument exposure. | Describe the local fix as though it were already in v2.4.0. |
| 5 | Treat DeepSeek Harness as a distribution host, not a target model family. | The user reiterated that this project audits Claude and Codex rather than DeepSeek models. | Add a DeepSeek-specific audit track because the host is named DeepSeek. |
| 6 | Keep the newer-host peer guard intact. | DSH `0.1.7-rc.2` rejects this package's exact `0.1.0-rc.6` peers and rolls back the attempted profile install. | Grant an `allow-version` exemption without testing the API contract. |
| 7 | Admit only exact newer hosts after testing their published packages. | The DSH installer enforces peer compatibility, while prerelease APIs can change between tags. | Use a broad semver range that would silently admit untested prereleases. |
| 8 | Read redacted form descriptors on newer hosts. | `dsh-settings` rc.17 and rc.20 expose `describe({ redactSecrets: true })` but no `get()`; the provider directory still names the settings namespace and path. | Drop default-route resolution or read the full unredacted form. |

## Deviations

| # | What changed | Spec said | I did instead | Why |
|---|-------------|-----------|---------------|-----|
| 1 | Treat the newer DSH matrix as a compatibility investigation before promising support. | D3–D5 listed rc.8, 0.1.7-rc.2, and 0.2.0-rc.2 for validation. | Keep the exact rc.6 support claim until each new host has an install and runtime result. | Current peer dependencies are pinned to rc.6; newer hosts enforce peer compatibility, and the 0.2 npm CLI changes plugin management. |
| 2 | Use an installed-package command harness for the runtime proof. | Verify install, load, command, and removal in an isolated DSH profile. | Installed the current worktree tarball in an isolated rc.6 `web` profile, then invoked its registered command through a minimal service harness and a real Python child. | The unmodified rc.6 Web host exits at its own missing Cordis HMR service even with an empty profile; rc.8 has the same control failure. This does not establish interactive Web UI compatibility. |

## Tradeoffs

| # | Topic | Option A | Option B | Chose | Reasoning |
|---|-------|----------|----------|-------|-----------|
| 1 | curl credentials | Put headers in a temporary config file. | Feed headers through curl config stdin and put request body in a temporary file. | B | The secret stays out of argv and persistent files; the project already uses this pattern for ordinary requests. |

## Open Questions

| # | Question | Impact | My assumption | Blocking? |
|---|----------|--------|---------------|-----------|
| 1 | When should the established Codex audit goal receive a distinct model baseline? | `scripts/audit.py` currently fixes the identity probe to Claude, `stream_integrity.py` treats non-Claude stream models as anomalous, and the DSH adapter refuses non-Claude routes. These paths cannot support a Codex model verdict by changing only a label or gate. | Complete the current DSH security slice; do not claim a Codex model verdict until baseline work is scoped and verified. | Yes, before expanding the model gate. |

## Newer DSH Adaptation (2026-10-03)

- Current source peer declarations admit exactly `0.1.0-rc.6`, `0.1.7-rc.2`, and `0.2.0-rc.2` for the five injected DSH services. The existing rc.6 `settings.get()` path remains; rc.17 and rc.20 use `settings.describe({ redactSecrets: true })` filtered by the configurable provider's `settingsNs`.
- rc.8 was not added to the peer declaration because its empty Web profile failed the HMR boot control in the prior isolated test. Do not infer compatibility from nearby prerelease numbers.
- Published package declarations for rc.20 retain `commands.register`, `credentials.resolve`, `llm.listConfigurableProviders` and `resolveModelInfo`, `subprocess.resolveExecutable` and `spawn`, and agent `options` / session `header.cwd`. The settings read was the required source adaptation.
- An isolated worktree tarball installed without a version exemption into rc.17 and rc.20 Web profiles; both config dumps contained `api-relay-audit`, and both Web hosts started a loopback listener without startup errors. The same tarball installed into rc.6 and appeared in its config dump; full rc.6 Web boot remains blocked by the previously reproduced empty-profile HMR issue.
- The tested worktree tarball SHA-256 was `e591d6c29260d52f900d1ae1130506d2b92717584e0bef5d7a41a80b37b8366d`; its package version remains `2.4.0` locally, so it must not be confused with the immutable published `v2.4.0` tag.
- The exact installed rc.17 and rc.20 bundles registered `/relay-audit`; a minimal service harness supplied the newer descriptor shape and ran the real standalone Python child against a loopback fake relay. Both received HTTP 200 on Anthropic Messages and OpenAI Chat, produced `Connectivity Verdict: OK`, requested redacted settings, and kept the fake key out of child/curl argv, command result, and report.
- Both newer Web profiles then removed the test bundle through `dsh plugin --profile web remove dsh-api-relay-audit` with exit code 0.
- This proof covers installation, composition, Web boot, command adapter, and real child connectivity. It does not cover an interactive Web command submission, Desktop, or non-Claude model audit. The immutable `v2.4.0` release still carries rc.6-only peers and does not include these source changes.
- Local gates: `python3 -m pytest tests/ -q` (811 passed), `node --test dsh/test/*.test.js` (19 passed), standalone build and version sync checks (passed), `npm pack --dry-run --ignore-scripts` (passed), and `git diff --check` (passed).
- The newer-host test's temporary profiles, runtimes, caches, fixture scripts, reports, and fake credential were removed after the results were recorded.
- The PR metrics gate initially found stale public test counts. `python3 scripts/collect-metrics.py` regenerated the metrics document, and the Web landing page was updated from 808 to 811 tests; the check then passed.

## Isolated DSH Verification (2026-10-03)

- Remote `master` remained `cfb8da4e009b11f9eadd61895d25b4e5bff2db18`. npm dist-tags reported `latest` and `next` as `0.2.0-rc.2`, `alpha` as `0.2.1-alpha.1`.
- Test directories used a temporary HOME, DSH_HOME, pnpm store, and npm cache; no dependency install scripts or real relay credentials. The plugin tarball was made from this uncommitted worktree and installed into an rc.6 `web` profile. `dsh --profile web --dump-config` included `api-relay-audit`.
- rc.6 Web boot exited 1: `user patch-layer watching requires the Cordis HMR service`. An empty rc.6 profile exited identically. Empty rc.8 Web boot also exited identically. The rc.6 install resolved some transitive DSH modules at rc.8 through caret dependency ranges, so the failure is currently classified as a host/dependency composition issue, not a plugin failure.
- The exact plugin installed in the rc.6 profile registered `/relay-audit`. Its real standalone Python child ran `--connectivity` against a loopback fixture and received HTTP 200 on both `/v1/messages` and `/v1/chat/completions`. The report had `Connectivity Verdict: OK`; the fake key was absent from child argv, curl argv, command result, and report.
- The rc.6 profile then removed `dsh-api-relay-audit` successfully; the profile manifest returned to its two built-in bundles and a fresh config dump no longer contained `api-relay-audit`. The first removal attempt passed an unsupported `--ignore-scripts` flag and exited 1; retrying without the flag while keeping `npm_config_ignore_scripts=true` succeeded.
- `dsh 0.1.7-rc.2 plugin --profile web add` exited 1 because the package's peers require rc.6. Its plugin manager restored the profile manifest, lockfile, and modules. No version exemption was granted.
- npm-current `dsh 0.2.0-rc.2 plugin --profile web add` reached the same exact-peer compatibility guard, exited 1, and restored the temporary profile. This verifies the npm CLI's **web** profile management path only; it says nothing about Desktop profile management or runtime behavior.
- Full UI boot, interactive command rendering, and Desktop `0.2.0-rc.2` remain unverified. Do not extend the published compatibility claim from these results.
- Final local gates after the isolated test: `python3 -m pytest tests/ -q` (811 passed), `node --test dsh/test/*.test.js` (18 passed), `python3 scripts/build-standalone.py --check` (passed), and `git diff --check` (passed).
- The generated temporary HOME, DSH_HOME profiles, package caches, fixture server script, and fake credential were removed after recording the results. The original checkout was not modified by this test.

---

*This file is maintained automatically during implementation.*
