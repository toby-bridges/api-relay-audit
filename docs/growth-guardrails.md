# Growth Guardrails

This document records the one-time growth checklist audit for API Relay Audit.
It uses the Gingiris skills catalog as an external checklist source, not as an
authority that overrides the project's current positioning.

The current SEO/GEO baseline is considered valid. Future growth work should
deepen evidence, improve release/contributor/user-feedback loops, or support a
new product surface. It should not repeat the same README, metadata, or generic
SEO audit work without a concrete trigger.

## Source

- Primary checklist source: <https://gingiris.tools/skills/>
- Checked categories: SEO & GEO, Open Source, GitHub star growth, Developer
  Marketing, User Research, launch/community/mobile playbooks.
- Scope decision: use the catalog once as a gap checklist for this repository.
  Do not install Gingiris skills in this PR.

Audit run:

- Observed at: 2026-06-06T10:43:45Z
- Local branch: `codex/growth-guardrails`
- Remote checked: `toby-bridges/api-relay-audit`
- Methods: `gh repo view`, `gh issue list`, `gh search repos`, `gh release
  list`, remote tag checks, live Pages `curl -I` checks, web search spot checks,
  local `rg` over README, Pages, docs, issue templates, skill files, and release
  docs.

Decision confidence below means confidence that the classification is correct
from the checked evidence. It is not a promise of traffic, citations, stars, or
conversion lift.

Reference commands, if a future maintainer explicitly wants to inspect a
specific playbook locally:

```sh
npx skills add Gingiris-1031/gingiris-seo-geo-agent
npx skills add Gingiris-1031/i18n-seo-geo
npx skills add Gingiris-1031/gingiris-opensource
npx skills add Gingiris-1031/gingiris-github-star-growth
npx skills add Gingiris-1031/developer-marketing-playbook
npx skills add Gingiris-1031/gingiris-user-interview
```

These commands are references only. Installing a playbook should require a
separate decision and a concrete task.

## Audit Result

Result: the current search/GEO foundation is complete enough to freeze. The
Gingiris checklist does not justify another README, Pages, metadata, topic, or
social-preview rewrite.

Remaining growth work is not another SEO pass. It is release execution,
indexing verification, user feedback, evidence-backed docs, contributor
maintenance, and future submission-page work.

## Evidence Snapshot

The GitHub-side search entry points were verified with `gh repo view`:

- Description: local security audit for AI API relays and LLM proxies, covering
  prompt injection, model substitution, tool-call rewriting, SSE anomalies,
  error leakage, and Web3 wallet risks.
- Homepage: <https://toby-bridges.github.io/api-relay-audit/>
- Topics: 20 high-intent topics, including `llm-proxy`, `llm-security`,
  `prompt-injection`, `model-substitution`, `tool-call-rewriting`,
  `web3-wallet`, and `ai-audit`.
- Custom GitHub social preview: enabled.

The repo-side evidence includes:

- README first screen, Quick Start, FAQ, Chinese details section, citation,
  contribution entry points, and OpenClaw/Hermes links.
- GitHub Pages metadata, canonical links, Open Graph/Twitter cards,
  `FAQPage`/`SoftwareApplication` structured data, sitemap, robots.txt, and
  English/Chinese hreflang.
- Guide pages for AI API relays, Claude relay audits, prompt injection, Web3
  wallet risks, tool comparison, and OpenClaw/Hermes skill usage.
- Public landing issues #31-#35 and contributor issue #37 remain open.
- Issue #36 and #38 are closed because the sanitized report fixture and
  tool-call rewriting fixture path have been implemented.
- `audit-report.yml`, `detector-gap.yml`, and `agent-skill-feedback.yml` provide
  issue-template intake for submissions, detector gaps, and OpenClaw/Hermes
  feedback.
- `docs/report-artifact-schema.md` and the sanitized fixture provide a safe
  base for future submission-page work.

## Checklist Findings

| Area | Evidence | Decision | Next action | Decision confidence |
| --- | --- | --- | --- | --- |
| SEO/GEO basics | README and Pages already include the core definition, natural search terms, FAQ, canonical URL, OG/Twitter cards, structured data, sitemap, and visible explanatory copy. | Covered. Do not rewrite positioning. | Only update if the product surface changes. | 98% |
| AI summary readiness | README and Pages directly answer what the tool is, when to use it, and what it does not claim. | Covered. Do not add another generic summary block. | Add evidence only when new real examples exist. | 98% |
| GitHub organic entry points | Description, homepage, 20 topics, custom social preview, long-tail landing issues, and good-first/help-wanted surfaces are in place. | Covered. No metadata/topic churn. | Re-run the benchmark only around releases or real metadata changes. | 98% |
| Chinese/i18n surface | `/zh/`, README Chinese details, and hreflang are present. | Covered for current scope. | Improve only from real Chinese user feedback or guide-quality issues. | 98% |
| OpenClaw/Hermes discovery | README, Pages, guide page, `SKILL.md`, `skills/api-relay-audit/SKILL.md`, and `docs/skill-distribution.md` exist. | Covered as distribution support, not primary positioning. | Verify publication/install behavior when OpenClaw, ClawHub, or Hermes changes. | 98% |
| Developer marketing | Contribution docs, issue templates, non-code entry points, citation, and example report exist. | Mostly covered. | Improve maintainer response and onboarding after real contributor friction appears. | 98% |
| User research | No dedicated interview script or user-feedback synthesis artifact is present. | Real gap. | Create interview scripts or feedback summaries only for high-signal relay, OpenClaw, or Hermes users. | 98% |
| Release growth | Release notes exist, but launch cadence and indexing verification are outside this docs-only PR. | Real gap. | Execute release, verify install paths, and submit/inspect indexing. | 98% |
| Submission-page workflow | Issue intake, processing workflow, report schema, and sanitized fixture exist; a public submission page/dashboard is not in this PR. | Real future capability. | Build on the existing report artifact schema; do not create a parallel format. | 98% |
| Product Hunt / launch playbooks | The project lacks a fresh release story, screenshots, and user proof for broad launch channels. | Not doing now. | Revisit after release and real usage evidence. | 98% |
| Reddit / KOL / UGC / ambassador playbooks | These require case studies, reputation risk controls, and active community maintenance. | Not doing now. | Revisit only after real case studies and maintainer capacity exist. | 98% |
| ASO / mobile / B2B SaaS playbooks | The project is an open-source local audit tool, not a mobile app or sales-led SaaS. | Out of scope. | Revisit only if the product model changes. | 98% |

## Owner/Maintainer Audit Findings

These are the actual audit findings from running the checklist, split by who can
act on them.

| Finding | Evidence | Owner action | Repo action | Priority |
| --- | --- | --- | --- | --- |
| No formal release anchor yet | `gh release list`, remote tags, and local tags returned no releases or tags. | Approve and publish the first release when the current branch stack is ready. | Keep release notes aligned with the real audit surface before tagging. | P0 |
| Search engines can find the project, but snippets are stale | Web search spot checks found the GitHub repo and Pages, but snippets still referenced older surfaces such as 13-step/11-step copy, old README links, and older license/star snapshots. | Submit sitemap and request URL inspection/indexing in Google Search Console and Bing Webmaster Tools. | Do not rewrite README/Pages just to fight stale snippets; wait for indexing after submission. | P0 |
| Live Pages are healthy | Homepage, `/zh/`, sitemap, robots.txt, and the OpenClaw/Hermes guide returned HTTP 200 from GitHub Pages. | Use these URLs for indexing submission. | Keep static-site checks as the guardrail. | P0 |
| GitHub repo search is strong for current high-intent terms | `api relay audit`, `AI API relay`, `model substitution`, `tool-call rewriting`, and `SSE anomalies` rank #1 in GitHub repository search. | None. | Do not retune metadata or topics. | P0 |
| GitHub repo search still has long-tail gaps | `LLM proxy security`, `prompt injection relay`, and `web3 wallet prompt injection` returned no top-10 repository results. | Treat this as benchmark drift, not a positioning failure. | Keep landing issues and guides; improve with real examples only. | P1 |
| Contributor discovery is thin after completed tasks | Only #37 remains open with `good first issue`; #32 and #33 remain open with `help wanted`. | Decide whether the project wants more newcomer capacity before release. | Add only small, real good-first tasks when there is a concrete maintenance need. | P1 |
| OpenClaw is locally available, but Hermes/ClawHub are not installed here | `openclaw --version` worked; `hermes` and `clawhub` were not found in this environment. | Verify Hermes/ClawHub publication from an environment where the owner has those tools and accounts. | Keep skill docs pinned and avoid claiming publication until verified. | P1 |
| Submission intake exists, but the public submission surface is not launched | `audit-report.yml`, `process-submission.yml`, report schema, and sanitized fixture exist. | Decide when user submissions should become a public growth surface. | Build future UI/dashboard work on the existing report artifact schema. | P1 |

Owner actions above are intentionally outside this docs-only PR. They require
account access, release approval, or a separate product decision.

## Completed Baseline

The following surfaces are already part of the current baseline and should not
be reworked merely because another checklist mentions them:

- GitHub repository metadata: description, homepage, social preview, and topics.
- README positioning: English-first API Relay Audit definition, concise value
  points, Quick Start, FAQ, Chinese details section, and non-code contribution
  entry points.
- GitHub Pages SEO/GEO: title, meta description, canonical URL, Open Graph,
  Twitter card, sitemap, robots.txt, hreflang, visible definition section, FAQ,
  and structured data.
- Search-supporting guide pages, including the OpenClaw and Hermes skill guide.
- OpenClaw and Hermes skill distribution docs and skill files.
- Sanitized report fixture and report artifact schema.
- Contributor-facing issue templates for detector gaps and agent skill feedback.
- Discoverability benchmark in `docs/discoverability.md`.
- Release-readiness copy in `docs/releases/`.

## Relationship To Discoverability Benchmark

`docs/discoverability.md` remains the repeatable GitHub search benchmark. It may
be re-run before releases, after metadata changes, or when real search data
shows underperformance.

That benchmark is not the same as a full SEO/GEO strategy audit. Re-running
repository search queries is allowed; reopening the entire README/Pages/topics
strategy is not allowed unless a re-audit trigger is met.

## Do Not Repeat

Future work should avoid these loops unless a re-audit trigger is met:

- No README repositioning pass.
- No repo metadata retuning or topic churn.
- No repeated generic SEO/GEO checklist audit.
- No duplicated guide-page creation for the same intent cluster.
- No social preview or README banner redo.
- No keyword stuffing in README, Pages, issues, or docs.
- No broad Product Hunt, KOL, ASO, ambassador, or community playbook execution
  before the project has a release/story that justifies that channel.

## Allowed Future Growth Work

The next growth work should fit one of these bounded categories:

- Release execution: publish a version, confirm release notes, and point users to
  stable install/test instructions.
- Search Console and Bing Webmaster submission: submit sitemap, verify indexing,
  and record actual search data when available.
- Evidence-backed guide thickening: improve an existing guide with real test
  output, user feedback, screenshots, or reproducible examples.
- User feedback loops: interview high-signal users, capture detector gaps, and
  convert repeated confusion into docs or tests.
- Contributor funnel: improve issue templates, labels, good-first issues,
  contribution docs, and maintainer response patterns.
- Submission-page or report-artifact work: build the future user submission
  surface around the existing schema-backed report fixture.
- Real case studies: add only sanitized, permission-safe examples tied to actual
  use or deterministic fixture data.
- OpenClaw or Hermes distribution updates: act only when installation,
  publication, or platform behavior changes.

## Future Growth PR Gate

Every future growth PR must state which category it belongs to:

1. Is this a new capability?
2. Does this deepen existing content with real evidence?
3. Does this support release, contributors, user feedback, or submission-page
   work?
4. Is this merely repeating an SEO/GEO checklist?

If the answer to the fourth question is "yes" and none of the first three are
true, the PR should not proceed.

## Re-Audit Triggers

Run another growth checklist audit only when one of these happens:

- Major positioning change, such as moving away from API Relay Audit as the
  primary concept.
- Launch of a user submission page, hosted report gallery, dashboard, or similar
  new product surface.
- Major release that changes the audit surface, install flow, or supported
  agent distribution model.
- Real Search Console, Bing, GitHub search, or analytics data shows a material
  underperformance pattern.
- OpenClaw, Hermes, ClawHub, or the relevant skill distribution mechanism
  changes in a way that affects installability or discovery.

## Gingiris Checklist Audit

| Gingiris area | Decision | Allowed use |
| --- | --- | --- |
| `gingiris-opensource` | Use selectively. | Release planning, backlog shaping, contributor funnel, and maintainer response quality. |
| `gingiris-seo-geo-agent` | One-time gap check only. | Validate that the current README/Pages/search surfaces have no obvious missing basics. No recurring full audit. |
| `i18n-seo-geo` | Use narrowly. | `/zh/`, hreflang, guide quality, citation density, and bilingual clarity checks. |
| `gingiris-github-star-growth` | Use after release. | Cadence planning, benchmark review, and post-release follow-up. Not README rewrites. |
| `developer-marketing-playbook` | Use for developer-facing loops. | Docs, contributor entry points, user feedback funnel, and practical onboarding. |
| `gingiris-user-interview` | Use for high-signal discovery. | Interview scripts for relay users, agent users, and security-minded early adopters. |
| Product Hunt playbooks | Not doing now. | Revisit only after a release with a clear story, screenshots, and credible user proof. |
| ASO/mobile playbooks | Not doing now. | Out of scope unless the project ships a mobile distribution surface. |
| B2B SaaS playbooks | Not doing now. | Out of scope unless the project becomes a hosted SaaS or sales-led product. |
| KOL/UGC/ambassador playbooks | Not doing now. | Out of scope until there are real case studies and a maintained community surface. |
| Broad community playbooks | Not doing now. | Revisit only after release, issue hygiene, and user feedback loops are stable. |

## Bounded Backlog

The checklist leaves only these real growth gaps:

- Submit and verify sitemap/indexing in Google Search Console and Bing
  Webmaster Tools.
- Publish the next release and keep release notes aligned with the real audit
  surface.
- Collect real user feedback from relay users, OpenClaw users, and Hermes users.
- Add evidence to existing guides when new reproducible examples or sanitized
  reports exist.
- Build the future submission-page workflow on top of the report artifact schema
  instead of inventing a parallel artifact format.
- Re-run `docs/discoverability.md` only as a benchmark, not as a new strategy
  audit.

Anything outside this backlog needs a new trigger or explicit maintainer
approval.
