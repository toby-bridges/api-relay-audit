# LLMprobe-engine Absorption Plan

This document records how api-relay-audit will absorb useful work from
BazaarLink LLMprobe-engine without changing the default audit contract.

## Priority

1. **External evidence source and measurement method**: handled separately from
   PR #24. Register source-level evidence only: repository, commit, license,
   paper hashes, measurement window, aggregate source-reported claims, and
   limitations. Do not publish unmasked endpoint mappings as api-relay-audit
   findings.
2. **Model-substitution detection**: start as v2.0 spike work. Use capability
   deltas and sub-model baselines as evidence, but keep outputs informational
   until honest baselines and confidence intervals are strong enough.
3. **Multimodal dilution detector**: start with self-generated tiny fixtures
   and request-shape validation for Anthropic and OpenAI formats. Format or
   transport failures are inconclusive, not safety verdicts.
4. **AC-1.b long-running watch mode**: treat as companion mode. Analyze local
   neutral/sensitive NDJSON observations; do not wire it into the default
   one-shot audit or claim complete conditional-delivery coverage.

## Guardrails

- No 0-100 scoring, leaderboard, safe-relay list, or trusted-relay language.
- No knowledge-cutoff verdicts.
- No direct per-relay public allegations without independently reviewable
  report hashes and maintainer review.
- No risk-matrix expansion from these spikes. They remain
  `riskMatrixImpact=none` until a later owner-approved design changes that.

## Current Spike Entry Points

- `scripts/experiments/model_substitution_spike.py`
- `scripts/experiments/multimodal_dilution_spike.py`
- `scripts/experiments/ac1b_watch_spike.py`
