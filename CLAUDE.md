# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override with non-Claude identity substitution, context truncation, tool-call package substitution (AC-1.a), error response header leakage (AC-2 adjacent), SSE-level stream integrity anomalies (AC-1 SSE-layer), Web3 prompt injection (SlowMist signature isolation, profile-gated), relay-framework fingerprinting, and latency-variance fingerprinting.

Threat taxonomy follows Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 — AC-1 (payload injection), AC-1.a (dependency-targeted injection), AC-1.b (conditional delivery), AC-2 (secret exfiltration). Infrastructure fingerprint (Step 12) and latency variance (Step 13) are sourced from Zhang et al., *Real Money, Fake Models*, arXiv:2603.01919. AC-1 full tool_call support and AC-1.b beyond warm-up mitigation remain on the backlog (see FOR_JOHN.md).

## Scope / Constraints

**Editable without asking**: `scripts/`, `api_relay_audit/`, `tests/`, `audit.py` (root standalone), `ROADMAP.md`, `CLAUDE.md`, `FOR_JOHN.md`.

**Ask before touching**: `web/`, `.github/workflows/`, `.github/voice-samples/`, `docs/`, `deploy/`, any root-level config files.

**Why**: `web/` is under a frontend colleague handoff (post-2026-04-20). `.github/workflows/` contains Claude Code action configuration — changes there have external side effects.

## Contribution Philosophy

**User-feedback-driven, not speculative.** Do not add features because they might be useful — add them when a real user need has been reported. This applies to code changes, new detection steps, and incoming PRs.

**Permanently out of scope** (evaluated and deliberately dropped — do not re-open without new information):
- **Claude Code CLI header impersonation** (ROADMAP §14): brittle version-pinning, and impersonating CC headers removes audit differentiation value
- **Hosted web dashboard** (ROADMAP "Explicitly NOT doing"): requires API backend + auth, which changes the product from a one-curl-download tool to a hosted service

**PR evaluation heuristics**: Does the change address a reported user problem? Does it preserve the dual-distribution invariant? Does it add complexity for a use case with zero user reports?

## Commands

```bash
# Install dependencies
pip install httpx pytest

# Run full audit
python scripts/audit.py --key <KEY> --url <BASE_URL> --model claude-opus-4-6

# Context length test only
python scripts/context-test.py --key <KEY> --url <BASE_URL>

# Extract report data to JSON (for dashboard)
python scripts/extract-data.py --reports-dir ./reports --output data.json

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_client.py -v

# Run a single test case
python -m pytest tests/test_client.py::TestAutoDetection::test_format_cached -v
```

## Architecture

### Dual Distribution Model
There are **two parallel versions**:
- `audit.py` (root) — standalone, zero-dependency version (~2500 lines, curl-only). Users can `curl` this file and run it without installing anything.
- `api_relay_audit/` + `scripts/` — modular version with `httpx`, used for development and testing.

When making changes to audit logic, `audit.py` (root) must be updated to stay in sync. `tests/test_dual_distribution_parity.py::test_risk_matrix_character_identical` enforces byte-level parity on the risk-matrix block; `tests/test_web3_injection.py::TestWeb3MarkerParity` enforces it on Web3 markers; `tests/test_refusal_detector.py::TestRefusalMarkerParity` enforces it on the Step 4/6 refusal vocabulary.

### Module Responsibilities

- `api_relay_audit/client.py` — All API calls go through `APIClient`. Auto-detects Anthropic vs OpenAI format (tries Anthropic first, caches on success). On SSL errors switches httpx → subprocess curl (`-sk`).
- `api_relay_audit/context.py` — Canary-marker + binary search context truncation. Coarse scan → binary → fine, ~12 requests vs ~75 naive.
- `api_relay_audit/reporter.py` — Builder-pattern Markdown report. `flag(level, msg)` appends to both body and risk summary.
- `api_relay_audit/tool_substitution.py` — AC-1.a via text-echo of pinned package commands (`pip install requests==2.31.0`, etc.). Text surrogate only: does NOT catch rewrites targeting structured `tool_call` payloads.
- `api_relay_audit/error_leakage.py` — AC-2 adjacent. 7-8 deterministic broken requests (malformed JSON, invalid model, wrong content-type, missing fields, unknown endpoint, `max_tokens=99999999` force-upstream, fake Bearer auth probe). Three scan paths: literal key match, LiteLLM-ported regex, LiteLLM issue-sourced markers (#5762, #8075, #12152, #13705, #15799, #20419).
- `api_relay_audit/identity_patterns.py` — 26 non-Claude keywords. ASCII uses word-bounded regex (`Qwen2.5` matches, `laws` doesn't); CJK uses substring.
- `api_relay_audit/stream_integrity.py` — SSE whitelist + usage monotonicity + thinking signature + stream model identity check. Tri-state verdict (`clean`/`anomaly`/`inconclusive`). Clean-room reimplementation of hvoy.ai concept, not a port.
- `api_relay_audit/transparent_log.py` — Append-only JSONL forensic log. Hash-only (no body), entries ≤1.5 KB. Hooks into all 4 `APIClient` public methods (`call`, `get_models`, `raw_request`, `stream_call`).
- `api_relay_audit/web3/injection_probes.py` — 3 SlowMist-derived probes; safe-priority aggregation with `HARD_INJECTED_MARKERS` override for contradictory responses. Profile-gated (`--profile web3|full`).
- `api_relay_audit/infra_fingerprint.py` — 3 unauthenticated GET probes; signature DB covers 7 frameworks; majority vote → `confirmed`/`tentative`/`unknown`. Informational only, does not feed the risk matrix.
- `api_relay_audit/latency_variance.py` — N identical `max_tokens=8` requests timed with `time.perf_counter` (not `time.time` — monotonicity, v1.8.1 fix). `ensure_format()` is called before the timing loop to prevent the first sample silently including a failed Anthropic probe. Bimodality is the strong signal for silent A/B model substitution. Informational only.
- `scripts/audit.py` — 13-step orchestration. **6D risk matrix**: D1=token injection, D2=instruction override, D3=tool-call substitution, D4=error leakage, D5=stream anomaly, D6=Web3 injection (profile-gated). Steps 12/13 informational only. `--profile` gates step set at runtime — rejected branch-forking to preserve the dual-distribution invariant.

### APIClient Return Format
```python
{"text": str, "input_tokens": int, "output_tokens": int, "raw": dict, "time": float}
# or on error:
{"error": str}
```

## CLI Flags for `scripts/audit.py`
`--key`, `--url`, `--model`, `--output`, `--profile {general,web3,full}`, `--skip-infra`, `--skip-context`, `--skip-tool-substitution`, `--skip-error-leakage`, `--aggressive-error-probes`, `--skip-stream-integrity`, `--skip-web3-injection`, `--skip-infra-fingerprint`, `--skip-latency-variance`, `--latency-probe-count N`, `--warmup N`, `--timeout`

## Dual-distribution invariant
Whenever `scripts/audit.py` or any `api_relay_audit/*.py` module changes, the standalone `audit.py` at the repo root must be updated to match. The standalone version is a character-copy of the modular code with curl subprocess replacing httpx. New helper modules (e.g. `tool_substitution.py`) get inlined as a new `Section` block in `audit.py`.

## Reference Documents

- `FOR_JOHN.md` — architecture decisions, design pitfalls, and "why we didn't do X" reasoning. Read before making structural changes.
- `ROADMAP.md` — near-term candidates (§2), deferred (§2.4/2.45), and permanently out-of-scope (§2.6 "Explicitly NOT doing"). Check before implementing any new feature.
- `.github/voice-samples/` — tone and structure for issue replies (`pr-reply-sample.md`) and PR reviews (`pr-review-sample.md`). The automated `claude-issue-triage.yml` and `claude-pr-review.yml` workflows read these files.
