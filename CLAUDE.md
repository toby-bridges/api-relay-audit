# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, context truncation, tool-call package substitution (AC-1.a), and error response header leakage (AC-2 adjacent).

Threat taxonomy follows Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 — AC-1 (payload injection), AC-1.a (dependency-targeted injection), AC-1.b (conditional delivery), AC-2 (secret exfiltration). AC-1.a is actively detected via Step 8 (tool-call substitution) and AC-2 is covered by Step 9 (error response leakage: scans for echoed credentials, upstream URLs, env var names, FS paths, stack traces). AC-1 full tool_call support and AC-1.b beyond warm-up mitigation remain on the backlog (see FOR_JOHN.md).

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
- `audit.py` (root) — standalone, zero-dependency version (~1K lines, curl-only). Users can `curl` this file and run it without installing anything.
- `api_relay_audit/` + `scripts/` — modular version with `httpx`, used for development and testing.

When making changes to audit logic, consider whether `audit.py` also needs to be updated to stay in sync.

### Module Responsibilities
- `api_relay_audit/client.py` — All API calls go through `APIClient`. Implements a **state-machine auto-detection**: tries Anthropic format first (`POST /v1/messages`, `x-api-key` header), falls back to OpenAI format (`POST /v1/chat/completions`, `Authorization: Bearer`). On SSL errors, switches from httpx to subprocess curl (`-sk`). Format is cached after detection.
- `api_relay_audit/context.py` — Context truncation detection via **canary markers + binary search**. Embeds 5 unique `CANARY_N_<hex>` strings at equal intervals, asks the model to list them. Uses coarse scan → binary search → fine scan, reducing requests from ~75 to ~12.
- `api_relay_audit/reporter.py` — Builder-pattern Markdown report generator. `flag(level, msg)` records findings to both the body and an auto-generated risk summary.
- `api_relay_audit/tool_substitution.py` — AC-1.a detection. Asks the model to echo pinned package-install commands (`pip install requests==2.31.0`, etc.), compares received text char-by-char, classifies as `exact` / `whitespace` / `substituted`. Text-echo surrogate: does NOT catch AC-1 rewrites that target only structured tool_call payloads.
- `api_relay_audit/error_leakage.py` — AC-2 adjacent detection (Step 9, v1.5.1). Fires 7-8 deterministic broken requests (malformed JSON, invalid model, wrong content-type, missing fields, unknown endpoint, **force_upstream_error** via `max_tokens=99999999`, **auth_probe** via fake Bearer header, optional 256 KB oversized body), captures the full error body and headers via `APIClient.raw_request`, and scans for leaks via three complementary paths: (1) literal substring match for the caller's own api_key + first-8 prefix + upstream provider hosts + env var names + filesystem paths + stack-trace markers + LiteLLM internal field names (`user_api_key`, `model_list`, `UserAPIKeyAuth`, ...) + PII echo markers (`piiEntities`, `sensitiveInformationPolicy`), (2) LiteLLM-ported regex patterns (`sk-`, Bearer, AWS AKIA, Google AIza, Gemini URL `?key=`, GCP ya29, JWT, PEM, DB connstring) with span-based dedup to prevent double-counting when the api_key matches both a literal and a regex, and (3) v1.5.1 LiteLLM issue tracker sourcing: every marker is cross-referenced against a real verified bug report (issues #5762, #8075, #12152, #13705, #15799, #20419). Tri-state return: `(results, severity, inconclusive)` where `severity ∈ {"none","medium","high","critical"}`.
- `scripts/audit.py` — 9-step audit orchestration (expanding to 11 in v3): Infrastructure → Models → Token Injection → Prompt Extraction → Instruction Conflict → Jailbreak → Context Length → Tool-Call Substitution → Error Response Leakage. Overall rating uses a **4D risk matrix**: D1 = injection > 100, D2 = instruction overridden, D3 = any tool-call substitution, D4 = error response critical/high leakage. HIGH if D3 or D4 OR (D1 AND D2); MEDIUM if D1, D2, D3i (inconclusive), D4i (inconclusive), or D4m (medium-only leakage); LOW otherwise.

### APIClient Return Format
```python
{"text": str, "input_tokens": int, "output_tokens": int, "raw": dict, "time": float}
# or on error:
{"error": str}
```

## CLI Flags for `scripts/audit.py`
`--key`, `--url`, `--model`, `--output`, `--skip-infra`, `--skip-context`, `--skip-tool-substitution`, `--skip-error-leakage`, `--aggressive-error-probes`, `--warmup N`, `--timeout`

## Dual-distribution invariant
Whenever `scripts/audit.py` or any `api_relay_audit/*.py` module changes, the standalone `audit.py` at the repo root must be updated to match. The standalone version is character-copy of the modular code with curl subprocess replacing httpx. New helper modules (e.g. `tool_substitution.py`) get inlined as a new `Section` block in `audit.py`.
