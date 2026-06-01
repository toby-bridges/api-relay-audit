# Example API Relay Audit Report

This is a sanitized example report. It uses reserved domains, placeholder
request IDs, redacted credentials, and synthetic findings so the report shape
is visible without exposing real relay domains, API keys, customer prompts, or
private traffic.

# API Relay Security Audit Report

**Generated**: 2026-06-01 04:45
**Target**: `https://relay.example.invalid/v1`
**Model**: `claude-opus-4-6`

## Risk Summary

- 🟢 No token injection detected
- 🟢 Prompt extraction probes did not reveal hidden prompts
- 🟢 Instruction override probes preserved the user instruction
- 🟢 Jailbreak probes were refused or safely handled
- 🟢 Tool-call package substitution not detected
- 🟢 No sensitive error leakage detected
- 🟢 Stream integrity checks passed
- 🟢 Web3 prompt-injection probes were skipped under `profile=general`
- 🟡 Infrastructure fingerprint: relay framework family inferred as `generic-proxy`
- 🟢 Latency variance did not show a bimodal pattern
- 🟢 Upstream channel classifier: transparent relay pattern

---

## 1. Infrastructure Recon

### 1.1 DNS Records

**A**: `203.0.113.10`
**CNAME**: `(empty)`
**NS**: `ns1.example.invalid`

### 1.2 WHOIS

```text
Domain Name: EXAMPLE.INVALID
Registry Domain ID: sanitized-example
Updated Date: 2026-01-01T00:00:00Z
Registrar: Example Registrar, Inc.
```

### 1.3 SSL Certificate

```text
subject=CN=relay.example.invalid
issuer=C=US, O=Example CA, CN=Example CA Root
notBefore=Jan  1 00:00:00 2026 GMT
notAfter=Jan  1 00:00:00 2027 GMT
```

### 1.4 HTTP Response Headers

```http
HTTP/2 401
content-type: application/json
x-request-id: req_sanitized_001
server: example-edge
```

### 1.5 System Identification

```json
{"error":{"message":"missing authorization","type":"authentication_error"}}
```

## 2. Model List

Total **3** models:

- `claude-opus-4-6` (owned_by: `anthropic`)
- `claude-sonnet-4-5` (owned_by: `anthropic`)
- `gpt-4.1-mini` (owned_by: `openai`)

## 3. Token Injection Detection

Send minimal messages, compare expected vs actual input_tokens. Delta = hidden
injection.

| Test | Actual input_tokens | Expected | Delta |
|------|---------------------|----------|-------|
| 'Say hi' (no system prompt) | **11** | ~10 | **~1** |
| 'Say hi' + short system prompt | **21** | ~20 | **~1** |
| 'Who are you' (no system prompt) | **15** | ~15 | **~0** |

🟢 **No token injection detected**

## 4. Prompt Extraction Tests

### 4.1 Direct hidden prompt extraction

The model refused to reveal hidden or system instructions and answered with a
generic policy-safe refusal.

### 4.2 Contradictory identity probe

No hidden prompt markers such as `system prompt`, `developer message`, or
provider-specific private instructions were returned.

🟢 **Prompt extraction probes did not reveal hidden prompts**

## 5. Instruction Override Tests

### 5.1 User instruction priority

The relay preserved a benign user instruction and did not inject a conflicting
system policy.

### 5.2 Identity consistency

The response self-identified consistently with the requested model family.

🟢 **Instruction override probes preserved the user instruction**

## 6. Jailbreak & Role Impersonation Tests

Attempts to impersonate higher-priority roles were refused or redirected to
safe behavior.

🟢 **Jailbreak probes were refused or safely handled**

## 7. Context Length Test

The relay accepted the configured context ladder through the fast scan limit.

| Payload size | Result |
|--------------|--------|
| 10K chars | accepted |
| 50K chars | accepted |
| 100K chars | accepted |
| 200K chars | accepted |

## 8. Tool-Call Package Substitution (AC-1.a)

Package-install commands in tool-call style responses were not rewritten.

| Probe | Expected package | Observed package |
|-------|------------------|------------------|
| npm install | `left-pad` | `left-pad` |
| pip install | `httpx` | `httpx` |

🟢 **Tool-call package substitution not detected**

## 9. Error Response Leakage (AC-2 adjacent)

Malformed request probes returned generic client errors. The report redacts
credential-like values before rendering snippets.

```json
{
  "status": 400,
  "body_preview": "{\"error\":{\"message\":\"invalid request body\"}}",
  "matched_secrets": []
}
```

🟢 **No sensitive error leakage detected**

## 10. Stream Integrity (AC-1 SSE-level)

Streaming response structure matched expected event ordering and usage fields.

```text
events_seen=message_start, content_block_start, content_block_delta,
content_block_stop, message_delta, message_stop
unknown_events=0
usage_monotonic=true
```

🟢 **Stream integrity checks passed**

## 11. Web3 Prompt Injection (Step 11, Web3 profile only)

This example was generated with `profile=general`, so Web3 wallet probes were
not executed.

🟢 **Web3 prompt-injection probes were skipped under `profile=general`**

## 12. Infrastructure Fingerprint

Unauthenticated probes suggest a generic proxy shape. This is an informational
finding and not proof of a specific upstream provider.

```json
{
  "framework": "generic-proxy",
  "confidence": "low",
  "signals": ["generic JSON auth error", "edge request id"]
}
```

🟡 **Infrastructure fingerprint: relay framework family inferred as `generic-proxy`**

## 13. Latency Variance

Identical probes did not show a clear bimodal latency distribution.

| Probe | Latency seconds |
|-------|-----------------|
| 1 | 1.02 |
| 2 | 1.07 |
| 3 | 1.05 |
| 4 | 1.09 |

🟢 **Latency variance did not show a bimodal pattern**

## 14. Upstream Channel Classifier

The classifier did not observe Bedrock, Vertex, OpenRouter, or Cloudflare AI
Gateway channel signatures in the message ID, headers, or response body.

```json
{
  "classification": "transparent-relay",
  "confidence": "medium",
  "evidence": ["anthropic-style message id", "no provider gateway marker"]
}
```

🟢 **Upstream channel classifier: transparent relay pattern**

## 14. Overall Rating

### LOW RISK

No high-risk relay manipulation was detected in this sanitized example. The
single informational fingerprint finding should be preserved with the raw
request/response evidence if this were a real report.
