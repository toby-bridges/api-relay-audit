# Benchmark Spike Reference: AiApiTest

Reference repository: <https://github.com/huyang218/AiApiTest>

Inspection date: 2026-05-19

Reference commit inspected: `15e8ce90cb29626d537ae41f48caa0fc8abcc4a1`

## Why This Exists

`AiApiTest` is useful as a reference for a future benchmark spike, but it is
not a direct fit for the core `api-relay-audit` pipeline.

Our project scope is narrower: a local, evidence-oriented security audit for
third-party AI API relays, with a zero-dependency standalone distribution and a
modular tested distribution. `AiApiTest` is broader: it is a Flask-based API
testing platform for model authenticity, provider comparison, benchmark
metrics, token cost estimation, multimodal checks, and history UI.

This document captures the ideas worth reusing without importing code.

## Relevant Core Design in AiApiTest

The central implementation is `api_tester.py` / `testers/text_tester.py`.

Key pieces:

- `ApiFormat` supports Anthropic, OpenAI-compatible, Azure OpenAI, Gemini, and
  several domestic-provider labels that mostly route through OpenAI-compatible
  calls.
- `ApiTester.call_api()` normalizes request construction and response parsing
  across providers.
- `verify_model()` asks identity, cutoff, reasoning, math, code-analysis, and
  consistency questions, then produces a coarse authenticity verdict.
- `run_benchmark()` fires concurrent requests and reports success rate, latency
  statistics, QPS, token counts, tokens/second, and estimated cost.
- Flask routes in `routes/test_text.py` compare a tested relay against an
  official provider configured in local settings.
- The UI stores official-provider keys locally in `settings.json`, keeps tested
  relay keys out of the database, and stores history in SQLite.

## What Is Useful for Us

### 1. Official-provider response comparison

AiApiTest sends the same question set to both the tested relay and an official
provider, then compares response similarity.

Possible value for us:

- A future experiment can test whether an advertised model is behaviorally close
  to an official baseline.
- This could complement, not replace, our existing security probes.
- It can help investigate suspected silent substitution where Steps 5, 10, 12,
  and 13 are inconclusive.

Why it should stay experimental first:

- It requires official provider keys, which violates the current "one key plus
  base URL" simplicity of the main audit.
- Similarity scores are noisy across temperature, routing, region, safety
  policy, model snapshots, and prompt wording.
- A low similarity score is not automatically a security finding.

### 2. Benchmark metric reporting

AiApiTest reports success rate, latency percentiles, QPS, total tokens,
tokens/second, and estimated cost.

Possible value for us:

- Reuse the reporting vocabulary for a future `benchmark` spike.
- Compare it with our Step 13 latency variance output.
- Add cost and reliability context to reports without making it part of the
  security risk matrix.

Boundary:

- Performance benchmarking is not the same as relay security auditing.
- These metrics should remain informational unless tied to a documented
  security threat model.

### 3. Model-authenticity question sets

AiApiTest uses reasoning, math, code, identity, and consistency questions to
infer whether the tested endpoint behaves like the claimed model.

Possible value for us:

- Use as inspiration for a small clean-room benchmark corpus.
- The corpus should be deterministic, short, low-cost, and versioned.
- Scoring must be transparent and testable.

Risks:

- Many "intelligence" questions are easy to overfit and can create false
  confidence.
- Self-identification questions overlap with our Step 5 and are already known
  to be noisy.
- Capability deltas require honest baselines and periodic recalibration.

### 4. Multimodal/version checks

AiApiTest includes UI surfaces for image and video generation/version testing.

Possible value for us:

- This overlaps with ROADMAP §2.6.2, the multimodal dilution spike.
- A tiny self-generated image fixture plus a deterministic judge could detect
  substitution to a pure-text model.

Boundary:

- Do not add a hosted UI or external judge model.
- Do not make multimodal probes default until cost and false-negative behavior
  are measured.

## What We Should Not Import

- Do not import Flask, Bootstrap, SQLite history, or settings management into
  the core audit.
- Do not require official provider keys for the default audit path.
- Do not add response-similarity scores to the LOW/MEDIUM/HIGH risk matrix.
- Do not copy question text or code directly unless licensing is clarified.
  The inspected repository does not expose a license through GitHub metadata in
  the current checkout, so treat it as inspiration only.
- Do not store API keys in repo-managed config files.

## Proposed Future Spike

Working title: `Capability benchmark delta`

Suggested location:

- `scripts/experiments/model_authenticity_benchmark_spike.py`
- Optional supporting notes in `docs/model-authenticity-benchmark.md`

Inputs:

- Tested relay key and URL.
- Tested model name.
- Optional official-provider key and base URL.
- Optional official model mapping.

Outputs:

- Markdown or JSON report with per-question results.
- No LOW/MEDIUM/HIGH risk change.
- Verdicts should be `close`, `different`, or `inconclusive`, not
  `safe`/`unsafe`.

Minimum viable probe set:

- One model-field check.
- Two deterministic reasoning questions.
- One code-analysis question.
- One short safety/identity consistency question.
- Optional official-baseline comparison if an official key is configured.

Acceptance criteria before shipping beyond `experiments/`:

- Clean-room question set and scoring rules.
- At least three honest baseline runs for the same advertised model.
- Clear false-positive guidance in the report.
- No dependency added to standalone `audit.py`.
- No risk-matrix promotion until baseline variance is understood.

## Relationship to Current Roadmap

This reference maps most closely to ROADMAP item "Capability benchmark delta
(direct model-substitution detection)" and to the multimodal dilution spike.

Recommended next step:

Keep this as a design reference. If we implement anything, start with a
standalone experiment under `scripts/experiments/`, not a new default audit
step.
