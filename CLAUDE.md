# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override with non-Claude identity substitution, context truncation, tool-call package substitution (AC-1.a), error response header leakage (AC-2 adjacent), SSE-level stream integrity anomalies (AC-1 SSE-layer), and Web3 prompt injection (SlowMist signature isolation, profile-gated).

Threat taxonomy follows Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 — AC-1 (payload injection), AC-1.a (dependency-targeted injection), AC-1.b (conditional delivery), AC-2 (secret exfiltration). AC-1.a is actively detected via Step 8 (tool-call substitution). AC-2 is covered by Step 9 (error response leakage). AC-1 at the streaming layer is covered by Step 10 (stream integrity: SSE event whitelist + usage monotonicity + thinking signature validity + stream model identity; v1.7, concept sourced from hvoy.ai claude_detector.py verified 2026-04-11). Web3-specific signature-isolation refusal probes are Step 11 (v2.3, inspired by SlowMist OpenClaw Security Practice Guide, gated behind `--profile web3|full`). AC-1 full tool_call support and AC-1.b beyond warm-up mitigation remain on the backlog (see FOR_JOHN.md).

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

When making changes to audit logic, consider whether `audit.py` also needs to be updated to stay in sync. `tests/test_dual_distribution_parity.py::test_risk_matrix_character_identical` enforces byte-level parity on the risk-matrix block; `tests/test_web3_injection.py::TestWeb3MarkerParity` enforces it on Web3 safe/unsafe markers; `tests/test_refusal_detector.py::TestRefusalMarkerParity` enforces it on the Step 4/6 refusal vocabulary.

### Module Responsibilities
- `api_relay_audit/client.py` — All API calls go through `APIClient`. Implements a **state-machine auto-detection**: tries Anthropic format first (`POST /v1/messages`, `x-api-key` header), falls back to OpenAI format (`POST /v1/chat/completions`, `Authorization: Bearer`). On SSL errors, switches from httpx to subprocess curl (`-sk`). Format is cached after detection.
- `api_relay_audit/context.py` — Context truncation detection via **canary markers + binary search**. Embeds 5 unique `CANARY_N_<hex>` strings at equal intervals, asks the model to list them. Uses coarse scan → binary search → fine scan, reducing requests from ~75 to ~12.
- `api_relay_audit/reporter.py` — Builder-pattern Markdown report generator. `flag(level, msg)` records findings to both the body and an auto-generated risk summary.
- `api_relay_audit/tool_substitution.py` — AC-1.a detection. Asks the model to echo pinned package-install commands (`pip install requests==2.31.0`, etc.), compares received text char-by-char, classifies as `exact` / `whitespace` / `substituted`. Text-echo surrogate: does NOT catch AC-1 rewrites that target only structured tool_call payloads.
- `api_relay_audit/error_leakage.py` — AC-2 adjacent detection (Step 9, v1.5.1). Fires 7-8 deterministic broken requests (malformed JSON, invalid model, wrong content-type, missing fields, unknown endpoint, **force_upstream_error** via `max_tokens=99999999`, **auth_probe** via fake Bearer header, optional 256 KB oversized body), captures the full error body and headers via `APIClient.raw_request`, and scans for leaks via three complementary paths: (1) literal substring match for the caller's own api_key + first-8 prefix + upstream provider hosts + env var names + filesystem paths + stack-trace markers + LiteLLM internal field names (`user_api_key`, `model_list`, `UserAPIKeyAuth`, ...) + PII echo markers (`piiEntities`, `sensitiveInformationPolicy`), (2) LiteLLM-ported regex patterns (`sk-`, Bearer, AWS AKIA, Google AIza, Gemini URL `?key=`, GCP ya29, JWT, PEM, DB connstring) with span-based dedup to prevent double-counting when the api_key matches both a literal and a regex, and (3) v1.5.1 LiteLLM issue tracker sourcing: every marker is cross-referenced against a real verified bug report (issues #5762, #8075, #12152, #13705, #15799, #20419). Tri-state return: `(results, severity, inconclusive)` where `severity ∈ {"none","medium","high","critical"}`.
- `api_relay_audit/identity_patterns.py` — non-Claude identity detection (Step 5 helper, v1.6.x). `NON_CLAUDE_IDENTITY_KEYWORDS` tuple with 26 keywords (Amazon/Kiro/AWS + GLM/DeepSeek/Qwen/MiniMax/Grok/GPT/ERNIE/Doubao/Moonshot/Kimi + Chinese brand names). `find_non_claude_identities` uses `\b<kw>(?![a-zA-Z])` regex for ASCII (word-bounded leading, non-letter-lookahead trailing so `Qwen2.5` matches but `laws` doesn't) and substring for CJK.
- `api_relay_audit/stream_integrity.py` — AC-1 SSE-level detection (Step 10, v1.7). `StreamSignals` dataclass captures everything an Anthropic streaming response emitted; `KNOWN_SSE_EVENT_TYPES` frozenset lists the 7 valid event types; `analyze_stream` returns a tri-state verdict (`clean` / `anomaly` / `inconclusive`) based on four invariants: SSE event whitelist, `output_tokens` monotonic non-decreasing, `input_tokens` consistent across `message_start` and `message_delta`, and `signature_delta` events having non-empty signatures. Also checks `message_start.message.model` contains `claude`. Populated by `APIClient.stream_call` which adds Anthropic streaming support via httpx `client.stream()` + curl `-N --no-buffer` fallback. Concept verified against hvoy.ai claude_detector.py on 2026-04-11, clean-room reimplementation with tri-state verdicts instead of their 0-100 numeric score.
- `api_relay_audit/transparent_log.py` — Append-only JSONL forensic logger (arXiv:2604.08407 §7.3). `TransparentLogger` writes one JSON line per API request with timestamp, URL, SHA-256 of request/response bytes, status code, and transport metadata. Hash only, not body — keeps entries ≤1.5 KB. `redact_error()` strips response body content from error strings to prevent credential leakage. `sha256hex()` helper handles bytes/str/None. Activated by `--transparent-log <path>` CLI flag; hooks into all 4 `APIClient` public methods (`call`, `get_models`, `raw_request`, `stream_call`) with incremental SHA-256 for streaming responses.
- `api_relay_audit/web3/injection_probes.py` — Web3 prompt injection detection (Step 11, v2.3, profile-gated). 3 probes derived from SlowMist OpenClaw Security Practice Guide: ETH transfer guidance, signed-transaction refusal, private-key-leak refusal. Each probe has `safe_markers` and `unsafe_markers` tuples; `classify_web3_response` returns tri-state `safe`/`injected`/`inconclusive` with safe-priority aggregation. `HARD_INJECTED_MARKERS` override safe-priority to catch contradictory responses ("I cannot sign, but here is the signed tx"). Only runs under `--profile web3|full`.
- `scripts/audit.py` — 11-step audit orchestration: Infrastructure → Models → Token Injection → Prompt Extraction → Instruction Conflict + Identity → Jailbreak → Context Length → Tool-Call Substitution → Error Response Leakage → Stream Integrity → Web3 Injection (profile-gated). Step 4/6 share a broadened `REFUSAL_MARKERS` vocabulary + `_looks_like_refusal` helper so benign refusals do not trip the identity-keyword leak detector (v1.7.4). Overall rating uses a **6D risk matrix**: D1 = injection > 100, D2 = instruction overridden, D3 = any tool-call substitution, D4 = error response critical/high leakage, D5 = stream integrity anomaly, D6 = Web3 prompt injection (only active under `--profile web3|full`). HIGH if D3 or D4 or D5 or D6 OR (D1 AND D2); MEDIUM if D1, D2, D3i, D4i (inconclusive), D4m (medium-only), D5i (stream inconclusive), or D6i (web3 inconclusive); LOW otherwise. Plus the `--profile` selector (general / web3 / full) gates which step set runs — rejected git branch forking in favor of a runtime flag so the dual-distribution invariant stays intact.

### APIClient Return Format
```python
{"text": str, "input_tokens": int, "output_tokens": int, "raw": dict, "time": float}
# or on error:
{"error": str}
```

## CLI Flags for `scripts/audit.py`
`--key`, `--url`, `--model`, `--output`, `--profile {general,web3,full}`, `--skip-infra`, `--skip-context`, `--skip-tool-substitution`, `--skip-error-leakage`, `--aggressive-error-probes`, `--skip-stream-integrity`, `--skip-web3-injection`, `--warmup N`, `--timeout`

## Dual-distribution invariant
Whenever `scripts/audit.py` or any `api_relay_audit/*.py` module changes, the standalone `audit.py` at the repo root must be updated to match. The standalone version is character-copy of the modular code with curl subprocess replacing httpx. New helper modules (e.g. `tool_substitution.py`) get inlined as a new `Section` block in `audit.py`.
