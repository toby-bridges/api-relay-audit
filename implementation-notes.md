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

## skills.sh and Cursor Directory preparation (2026-10-22)

- Task: prepare local installation evidence and English submission materials; publication remains subject to user approval.
- Baseline: remote master `390de58b83f8e3a7b6c54944c78eae286238dbf5`, with the released v2.5.0 audit engine unchanged.
- Decision: keep the root OpenClaw and nested Hermes metadata for compatibility, but share one host-neutral instruction body. The two channels select different files.
- Decision: recommend the explicit `skills/api-relay-audit` source path. The skills CLI's default root discovery otherwise copies the repository as a skill bundle.
- Decision: run installation in disposable project directories with telemetry disabled and network denied during the CLI checks; do not change user-level skill installations.
- Evidence boundary: a Cursor Directory source-parser replay and filesystem installation do not prove a hosted listing or a model-selected Cursor run.
- Approval gate: no push, PR, directory submission, listing-triggering telemetry, or account authorization in this preparation task.
- Validation repair: the first focused run found one legacy frontmatter-format assertion; retained the nested plain YAML description and reran all 21 focused cases successfully.
- Environment repair: the sandbox denied loopback binding with PermissionError 1; reran with local-listening permission, synthetic credentials, a loopback-only curl wrapper, and telemetry disabled.
- Independent review found no blocking defect; clarified Windows command selection and the application-level network-guard evidence boundary.
- Final local proof: 28 integration checks, 21 focused pytest cases, standalone artifact parity, submission-payload consistency/privacy checks, and diff whitespace check passed. Runtime evidence and draft fields are under docs/distribution/skills-cursor/.
- State: uncommitted local candidate on codex/skills-cursor-preparation; no external write. Next gate is user review before any push, PR, merge, authorization, or channel submission.

*This file is maintained automatically during implementation.*

---

## npm Distribution and Windows Acceptance (2026-10-24)

> Task: Prepare npm distribution, Windows acceptance, and upstream root-cause evidence for DSH issues #99, #101, and #103.
> Spec: User approval in this chat; deliver through a PR. Publication and upstream communication require separate approval.
> Started: 2026-10-24
> Baseline: bd405e8eaa2234118f942fec353324c718ab46d6 (master)
> Completed: 2026-10-24 (npm preparation, hosted Windows/Linux acceptance, evidence package, and PR delivery; publication excluded)

## Design Decisions

| # | Decision | Context | Alternative considered |
|---|----------|---------|------------------------|
| 1 | Use a new managed worktree and codex/dsh-npm-windows branch. | The original checkout contains unrelated user changes. | Reusing the original checkout. |
| 2 | Prepare a prebuilt npm tarball without install/build lifecycle hooks. | The adapter already ships its runtime; Git and source builds are unnecessary consumer requirements. | Installing the source repository. |
| 3 | Keep publication manual and unperformed. | Approval covers preparation, tests, push, and PR creation, not npm publication or upstream outreach. | An automatic publishing workflow. |
| 4 | Validate real Windows behavior in GitHub-hosted Windows CI and retain structured evidence. | This workstation is macOS; platform mocks cannot establish Windows acceptance. | Treating adapter unit tests as Windows host acceptance. |
| 5 | Build one candidate on Ubuntu and consume identical bytes through a loopback npm registry on Windows and Ubuntu. | Public npm publication remains unapproved; local-directory installation does not exercise registry resolution and integrity. | Publishing a test package or independently packing on each OS. |
| 6 | Use the already declared DSH 0.1.7-rc.2 host with a real headless Loader and commands service. | Earlier rc.6 empty-Web controls exposed an unrelated HMR composition failure. Browser interaction and historical issue #101 are separate evidence gates. | Calling the adapter directly or claiming browser UI acceptance. |
| 7 | Preserve the known classifier outputs as fixed-source observations. | Green reproducibility checks must not imply that upstream misclassifications are repaired. | Making known upstream defects silently pass the desired-behavior gate. |
| 8 | Cancel at an observed real metadata request and verify the owned process tree independently. | Synthetic process tests alone do not prove that the DSH/pnpm writer stopped or the prior profile survived. | Treating a taskkill attempt or files on disk as cleanup proof. |

## Deviations

| # | What changed | Spec said | I did instead | Why |
|---|--------------|-----------|---------------|-----|

## Tradeoffs

| # | Topic | Option A | Option B | Chose | Reasoning |
|---|-------|----------|----------|-------|-----------|
| 1 | Upstream scope | Modify or fork Hub/DSH now | Prepare reproducible, pinned evidence and proposed fixes | B | User requested an evidence package; upstream communication remains gated. |

## Open Questions

| # | Question | Impact | My assumption | Blocking? |
|---|----------|--------|---------------|-----------|
| 1 | npm package ownership and final release version | Required before publication | Do not claim registry availability or ownership; retain VERSION until release preparation. | Publication only |
| 2 | Exact cause of issue #101 on the reporter's Windows environment | Required before claiming its root cause fixed | Preserve separate exit, stream-close, configuration, and load observations. | Root-cause conclusion only |

### Local verification

- Python regression: `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/ -q -p no:cacheprovider` — 885 passed; loopback fixtures require permission to bind localhost in this workstation's sandbox.
- Adapter/package behavior: `npm run test:dsh` — 27 passed.
- Candidate: `npm run verify:package` — exact eight-file archive, source bytes, extracted adapter and Python help checks passed. This is preparation, not publication.
- Source consistency: standalone generation, version synchronization, metrics drift and whitespace checks passed.
- Evidence: eight pinned upstream source hashes and six baseline classifier observations reproduced; only one of six matches the desired classification. The explicit correctness gate remains red by design.
- Synthetic lifecycle/acceptance-tool checks: six passed on macOS. Windows acceptance remains pending until the hosted runner completes.
- Final acceptance fixture checks: seven passed under Node 22.19.0; the independent synthetic pipe test is a separate check.
- Real macOS DSH 0.1.7-rc.2 / pnpm 11.7.0 run: all 19 stages matched their expected outcomes, including a missing-version failure and metadata-phase cancellation. Twelve loopback API requests succeeded. Both observed cancellation PIDs exited; original manifest/lock bytes and old command behavior survived before retry.
- Independent review found and closed a Windows path-redaction defect: raw, JSON-escaped, slash-normalized, file-URL and encoded-space path forms now have behavior tests. No production credentials or raw private evidence are included.
- Hosted Windows and Ubuntu results belong to the exact PR commit and workflow artifacts. Local macOS success is not a substitute for either hosted result; original issue #101 and interruption during profile commit remain separate upstream gates.
- First hosted run: Ubuntu's 19 real host stages passed. Windows exposed a defect in the independent synthetic pipe fixture before reaching the host stages. Node 22.19's Windows implementation puts non-detached children in a parent-owned kill-on-close Job; `unref()` did not keep the fixture holder alive. The fixture now uses explicit detachment, an IPC readiness handshake and observer-controlled release without increasing the 2.5-second watchdog. New test against the old fixture failed; the corrected fixture passed locally and awaits hosted Windows confirmation.
- Keep the independent mechanism probe after the real consumer in CI, with both failures still failing the job. This preserves host observations when a probe has a defect.
- The owner separately approved the required `release:minor` PR label after automatic approval rejected it. The label was applied; no release workflow or publication was triggered.
- Hosted acceptance at PR head `6346378` passed on Windows and Ubuntu: 19 expected stages and 12 synthetic API requests per platform. Downloaded summaries confirmed cancelled process-tree exit, profile-byte preservation, old-command behavior before retry and successful cleanup. All 12 current CI checks passed. Permanent sanitized receipt: `docs/distribution/dsh-npm-acceptance-2026-10-24.json`. The receipt records the tested head/integration commit explicitly; later documentation commits do not replace that source identity.


## Standalone website migration — 2026-10-28

- Tool and community evidence remain public in this repository; authored website source moves to `toby-bridges/apirelayaudit-site`.
- Canonical reviewed registry moves from `web/data/evidence.json` to `evidence/registry.json` without changing evidence semantics or the draft-PR review gate.
- Legacy Pages publishes generated redirects and copied public assets from a fixed website commit. Static hosting provides client redirects, not HTTP 301; query strings and fragments are preserved by the redirect script. The workflow refuses deployment while the original repository still owns a custom domain, and the script redirects only on the legacy GitHub hostname.
- Website tests and claims belong to the website repository; tool README, fixture, skill and metrics checks remain here.
- Private operations and raw reports are excluded from both public migration payloads.
- External cutover and exact website commit pin are owned and verified by the parent migration task.
