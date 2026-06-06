# Query Family Contract

This document keeps the public discovery surface for API Relay Audit clean.
Treat each family below as a distinct user intent. Do not collapse them into
one headline, directory name, or skill description.

## 1. API relay audit

- Primary intent: audit a third-party AI API relay, mirror, gateway, LLM proxy,
  or resale API before trusting traffic.
- Canonical title language: `API Relay Audit`, `AI API relay security audit`,
  `LLM proxy security audit`.
- Runtime profile: `general` by default; `full` when the user explicitly wants
  every available probe.
- Public surfaces: README H1 and intro, GitHub Pages title, repository topics,
  skill names, quick start, local execution model.

## 2. Prompt injection audit

- Primary intent: detect hidden prompt injection, prompt leakage, instruction
  override, jailbreak leakage, and prompt-extraction behavior in a relay path.
- Canonical title language: `prompt injection audit`,
  `detect prompt injection in LLM API proxies`, `hidden prompt leakage`.
- Runtime profile: `general`; covered mainly by Steps 3, 4, 5, and 6.
- Public surfaces: coverage tables, prompt-injection guide, FAQ, detector-gap
  issues.

## 3. Model substitution signals

- Primary intent: collect evidence signals when a relay may expose a different
  model identity, route, or upstream channel than the user expected.
- Canonical title language: `model substitution signals`,
  `model identity consistency`, `upstream channel evidence`.
- Runtime profile: `general`; supported by Step 5 identity consistency, Step 10
  stream model identity, Step 13 latency variance, and Step 14 channel
  classifier.
- Evidence boundary: natural-language self-ID, channel fingerprints, and
  latency patterns are signals. They are not standalone provider-level proof
  that a provider or platform substituted the upstream model. Stronger claims
  require raw response JSON, request IDs, provider/model metadata, stream
  signatures, transparent logs, and reproducible runs.
- Public surfaces: evidence model, FAQ, issue template provider/profile fields,
  operator response path.

## 4. Web3 relay audit

- Primary intent: check wallet-sensitive relay behavior before agent workflows
  touch signing, transaction guidance, or private-key-adjacent content.
- Canonical title language: `Web3 relay audit`,
  `Web3 wallet prompt injection`, `wallet signature-isolation probes`.
- Runtime profile: `web3` or `full`; Step 11 is profile-gated.
- Public surfaces: Web3 section, Web3 guide, profile table, issue template
  profile field.

## Cross-Surface Rules

- Keep `API Relay Audit` as the project name and primary title.
- Keep query families in separate sections, cards, FAQ entries, and guides.
- Keep English and Chinese surfaces in sync for the same claims.
- Never claim that a `LOW` result certifies safety.
- Never treat `inconclusive` as `clean`.
- Never publish API keys, raw headers, full response bodies, wallet material,
  private relay traffic, or user data in public issues.
