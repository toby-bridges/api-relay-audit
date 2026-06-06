# GitHub Discoverability Benchmark

This document defines a repeatable benchmark for GitHub organic discovery:
repository metadata, topics, public landing issues, contributor labels, and
repository search queries.

This benchmark is not a relay ranking, safety claim, or submitted-report
registry. It only checks whether users can find this local, transparent, and
repeatable audit tool from GitHub search surfaces. Do not use stale observations
as public launch claims without re-running the protocol below.

## Benchmark Protocol

Record every run with an `observed_at` UTC timestamp. Use an authenticated `gh`
session and GitHub repository search with the default ranking mode.

```bash
gh repo view toby-bridges/api-relay-audit \
  --json description,homepageUrl,repositoryTopics,usesCustomOpenGraphImage

gh issue list --repo toby-bridges/api-relay-audit --state open \
  --json number,title,labels --limit 100

gh search repos "$QUERY" --limit 10 --json fullName,description
```

For each search query, record the target repository's 1-based rank in the top 10
results. Use `not_top_10` when the command succeeds but the target repository is
absent. Use `inconclusive` for rate limits, network failures, auth failures, or
other command errors. Search drift alone should not block a release, but stale
results must not support launch copy.

Stars and forks are intentionally omitted from the benchmark because they drift
too quickly to be useful in a long-lived documentation snapshot.

## Latest Observation

Observed at: 2026-06-01T06:27:04Z

- Repository: `toby-bridges/api-relay-audit`
- Description: Local security audit for AI API relays and LLM proxies: detects prompt injection, model substitution, tool-call rewriting, SSE anomalies, error leakage, and Web3 wallet risks.
- Homepage: <https://toby-bridges.github.io/api-relay-audit/>
- Topics: `ai-agents`, `ai-security`, `anthropic`, `api-gateway`, `claude`, `cli`, `llm-proxy`, `llm-security`, `openai-api`, `prompt-injection`, `python`, `security-audit`, `security-scanner`, `supply-chain-security`, `web3-security`, `ai-audit`, `llm-audit`, `model-substitution`, `web3-wallet`, `tool-call-rewriting`
- Custom GitHub social preview: enabled (`usesCustomOpenGraphImage:true`)

## Search Observation

| Query | Target rank | Top results observed | Target surface | Next action |
| --- | --- | --- | --- | --- |
| `api relay audit` | 1 | `toby-bridges/api-relay-audit`; `sk1935/api-relay-audit`; `Cheriimmunogenic168/api-relay-audit` | Name, description | Maintain brand wording and avoid renaming churn. |
| `AI API relay` | 1 | `toby-bridges/api-relay-audit`; `7a6163/1min-relay-worker`; `howardpen9/awesome-ai-api-proxy` | Description, README, topics | Keep `AI API relay` in description and README first screen. |
| `LLM proxy security` | not_top_10 | No results returned by `gh search repos --limit 10`. | Description, `llm-proxy`, `llm-security` | Recheck after metadata indexing; use issue #34 as the long-tail landing surface. |
| `prompt injection relay` | not_top_10 | No results returned by `gh search repos --limit 10`. | `prompt-injection`, description, issues | Recheck after issue #31 is indexed. |
| `model substitution` | 1 | `toby-bridges/api-relay-audit`; `bkwiatkowski/ResourcesSubstitutable`; `ystex/Federated-Learning-with-Friend-Discovery-and-Model-Substitution-` | Description, `model-substitution` | Keep the topic and FAQ wording aligned. |
| `tool-call rewriting` | 1 | `toby-bridges/api-relay-audit` | Description, `tool-call-rewriting`, issue #32 | Keep the hyphenated phrase in metadata and docs. |
| `SSE anomalies` | 1 | `toby-bridges/api-relay-audit`; `ViloForge/vfobs` | Description, issue #35 | Keep `SSE anomalies` in metadata and stream-integrity docs. |
| `web3 wallet prompt injection` | not_top_10 | No results returned by `gh search repos --limit 10`. | `web3-wallet`, `web3-security`, issue #33 | Recheck after the Web3 issue and topic are indexed. |

## Public Landing Issues

| Issue | Labels | Discovery role |
| --- | --- | --- |
| [#31 Track relay prompt injection examples and detection gaps](https://github.com/toby-bridges/api-relay-audit/issues/31) | `documentation`, `enhancement` | Long-tail prompt injection landing surface. |
| [#32 Improve tool-call rewriting detection for structured tool payloads](https://github.com/toby-bridges/api-relay-audit/issues/32) | `enhancement`, `help wanted` | Tool-call rewriting contributor task. |
| [#33 Document Web3 wallet prompt injection threat model](https://github.com/toby-bridges/api-relay-audit/issues/33) | `documentation`, `help wanted` | Web3 wallet prompt injection landing surface. |
| [#34 Track LLM proxy security test cases](https://github.com/toby-bridges/api-relay-audit/issues/34) | `documentation`, `enhancement` | LLM proxy security landing surface. |
| [#35 SSE stream integrity: known relay anomaly patterns](https://github.com/toby-bridges/api-relay-audit/issues/35) | `documentation`, `enhancement` | SSE anomaly landing surface. |
| [#36 docs: add an anonymized example audit report](https://github.com/toby-bridges/api-relay-audit/issues/36) | `documentation`, `help wanted`, `good first issue` | Concrete documentation contribution. |
| [#37 docs: add quick examples for general, web3, and full profiles](https://github.com/toby-bridges/api-relay-audit/issues/37) | `documentation`, `good first issue` | Concrete documentation contribution. |
| [#38 tests: add a fixture for tool-call rewriting edge cases](https://github.com/toby-bridges/api-relay-audit/issues/38) | `help wanted`, `good first issue` | Concrete test contribution. |

## Maintenance Checklist

- Re-run the benchmark before public launch posts or releases.
- Re-run 24-48 hours after repository description, topic, issue, README, Pages,
  or social-preview changes so GitHub indexing can settle.
- Re-run monthly while launch/discoverability work is active.
- Owner: maintainer or docs owner.
- Record rate limits, network failures, auth failures, and GitHub API errors as
  `inconclusive`; do not silently reuse the previous observation.
- Keep repository topics at the 20-topic limit with the highest-intent terms.
- Keep issue titles natural; do not create keyword-only issues.
- Keep `good first issue` and `help wanted` on genuinely scoped contributor
  tasks.
- Verify that the GitHub custom social preview still renders after asset changes.
