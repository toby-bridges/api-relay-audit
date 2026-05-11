"""Upstream channel classifier (Step 14, v1.9).

Classifies the upstream serving channel of an authenticated /v1/messages
response: AWS Bedrock, Google Vertex, AWS API Gateway, Anthropic Official,
OpenRouter, Cloudflare AI Gateway, or transparent Anthropic relay (inferred
from native msg_01... id with no other signals).

This complements Step 12 (infrastructure fingerprint), which uses three
*unauthenticated* GET probes (`/`, `/v1/models`, `/notfound`) to identify the
relay-framework family (LiteLLM, Helicone, Portkey, one-api, etc.). Step 12
cannot see the upstream channel because the markers (msg_bdrk_*, msg_vrtx_*,
anthropic-ratelimit-*) only appear on real authenticated message responses.

To avoid double-counting, Step 14 deliberately omits channels that Step 12
already covers (litellm, helicone, portkey, kong-gateway, alibaba-dashscope,
azure-foundry, new-api, one-api, cloudflare). Run both for the full picture.

Detection algorithm (clean-room reimplementation of the technique used in
LLMprobe-engine `channel-signature.ts`, Bazaarlinkorg/LLMprobe-engine,
AGPL-3.0; algorithm reproduced from observed behavior, not source code):

    Tier 1 — deterministic, single signal returns confidence 1.0 immediately
    Tier 2 — weighted accumulation across 4 competing channels, max wins
    Tier 3 — fallback inference when all Tier 1/2 signals are empty:
             a native Anthropic message id with no other signal implies a
             transparent relay (returns 0.5 confidence)

Informational only: result does NOT feed the 6D risk matrix. Channel labels
like aws-bedrock or anthropic-official are legitimate serving paths; they
become a fraud signal only when combined with Step 5 identity substitution
or Step 13 latency bimodality (multi-step accumulation, ROADMAP §2.6.3.2).
"""

import json
import re


# ----------------------------------------------------------------------
# Tier 1 — deterministic single-signal rules
# ----------------------------------------------------------------------
#
# Each rule is ``(label, signal_type, signal_value)``:
#
#   signal_type = "id_prefix"      -> message id startswith signal_value
#   signal_type = "header"         -> header named signal_value present
#   signal_type = "header_prefix"  -> any header name startswith signal_value
#   signal_type = "header_value_prefix" -> header named signal_value[0]
#                                      has value startswith signal_value[1]
#
# First match wins; classifier returns immediately at confidence 1.0.
TIER1_RULES = [
    # OpenRouter: openrouter.ai relay. Mints its own ids (`gen-...`) and
    # echoes them in the `x-generation-id` response header.
    ("openrouter", "id_prefix", "gen-"),
    ("openrouter", "header_value_prefix", ("x-generation-id", "gen-")),
    # Cloudflare AI Gateway: ai-gateway.cloudflare.com adds `cf-aig-*` to
    # every response (DISTINCT from `cf-ray` which is plain CDN edge).
    ("cloudflare-ai-gateway", "header_prefix", "cf-aig-"),
]


# ----------------------------------------------------------------------
# Tier 2 — weighted scoring across 4 competing channels
# ----------------------------------------------------------------------
#
# Each entry is ``label -> list of (signal_type, signal_value, weight)``.
# Same signal_type vocabulary as Tier 1, plus:
#
#   signal_type = "body"                -> body contains signal_value
#                                          (case-sensitive substring)
#   signal_type = "header_value_contains" -> header named signal_value[0]
#                                            has value containing
#                                            signal_value[1] (case-insens.)
#
# Weights accumulate independently. Final confidence = max channel score,
# clamped to [0.0, 1.0], rounded to 2 decimal places.
TIER2_WEIGHTS = {
    "aws-bedrock": [
        ("header_prefix", "x-amzn-bedrock-", 1.0),
        ("id_prefix", "msg_bdrk_", 1.0),
        ("body", "bedrock-2023-05-31", 0.9),
    ],
    "google-vertex": [
        ("id_prefix", "msg_vrtx_", 1.0),
        ("header_prefix", "x-goog-", 1.0),
        ("body", "vertex-2023-10-16", 0.9),
        ("header_value_contains", ("server", "google"), 0.5),
        ("header_value_contains", ("via", "google"), 0.5),
    ],
    "aws-apigateway": [
        ("header", "x-amz-apigw-id", 0.8),
        ("header", "apigw-requestid", 0.8),
    ],
    "anthropic-official": [
        ("header_prefix", "anthropic-ratelimit-", 0.95),
        ("header_prefix", "anthropic-priority-", 0.95),
        ("header_prefix", "anthropic-fast-", 0.95),
        ("header_value_prefix", ("request-id", "req_"), 0.6),
    ],
}


# Tie-break order when multiple channels share the same max score.
# Bedrock wins over Vertex over AWS-API-Gateway over Anthropic-Official.
TIER2_PRIORITY = ("aws-bedrock", "google-vertex", "aws-apigateway", "anthropic-official")


# ----------------------------------------------------------------------
# Tier 3 — relay-proxy inference
# ----------------------------------------------------------------------
#
# Native Anthropic ids start with `msg_01` followed by 22+ Crockford-base32-ish
# characters. If we see such an id but ZERO other signals fired, the operator
# is most likely a transparent reverse proxy in front of Anthropic's API
# (id is forwarded verbatim because the relay didn't generate its own).
TIER3_RELAY_ID_PATTERN = re.compile(r"^msg_01[A-Za-z0-9]{22,}$")
TIER3_RELAY_CONFIDENCE = 0.5


# Body scan cap. Anthropic message responses are typically <2 KB but tool-use
# or large outputs can balloon; we only need enough to catch the
# `anthropic_version` field which is always near the top of the JSON.
_BODY_SCAN_LIMIT = 8192


def _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
    """Return True if the (type, value) signal fires against the inputs.

    All inputs are pre-normalized: headers_lower is a lowercased name->value
    dict, message_id is a string (possibly empty), body_truncated is a
    string truncated to _BODY_SCAN_LIMIT.
    """
    if signal_type == "id_prefix":
        return bool(message_id) and message_id.startswith(signal_value)
    if signal_type == "header":
        return signal_value.lower() in headers_lower
    if signal_type == "header_prefix":
        return any(k.startswith(signal_value.lower()) for k in headers_lower)
    if signal_type == "header_value_prefix":
        name, prefix = signal_value
        value = headers_lower.get(name.lower(), "")
        return value.startswith(prefix)
    if signal_type == "header_value_contains":
        name, needle = signal_value
        value = headers_lower.get(name.lower(), "")
        return needle.lower() in value.lower()
    if signal_type == "body":
        return signal_value in body_truncated
    return False


def _evidence_string(signal_type, signal_value):
    """Render a (type, value) signal into a human-readable evidence string."""
    if signal_type == "id_prefix":
        return f"id_prefix:{signal_value}"
    if signal_type == "header":
        return f"header:{signal_value}"
    if signal_type == "header_prefix":
        return f"header_prefix:{signal_value}"
    if signal_type == "header_value_prefix":
        return f"header:{signal_value[0]}={signal_value[1]}*"
    if signal_type == "header_value_contains":
        return f"header:{signal_value[0]}~{signal_value[1]}"
    if signal_type == "body":
        return f"body:{signal_value}"
    return f"{signal_type}:{signal_value}"


def classify_channel(headers, message_id, raw_body):
    """Classify a single response into upstream channel + confidence + evidence.

    Args:
        headers: dict of response headers (case-insensitive matching is done
                 internally; pass whatever casing is convenient).
        message_id: the response's `id` field (or None / empty).
        raw_body: the full response body as a string (or empty).

    Returns:
        dict with keys:
          channel    -- one of: openrouter, cloudflare-ai-gateway, aws-bedrock,
                        google-vertex, aws-apigateway, anthropic-official,
                        anthropic-relay, unknown
          confidence -- float in [0.0, 1.0], rounded to 2 decimal places
          evidence   -- list of strings, each describing a fired signal
    """
    if headers is None:
        headers = {}
    headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
    message_id = message_id or ""
    body_truncated = (raw_body or "")[:_BODY_SCAN_LIMIT]

    # Tier 1: first match returns immediately.
    for label, signal_type, signal_value in TIER1_RULES:
        if _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
            return {
                "channel": label,
                "confidence": 1.0,
                "evidence": [_evidence_string(signal_type, signal_value)],
            }

    # Tier 2: accumulate scores per channel.
    scores = {label: 0.0 for label in TIER2_WEIGHTS}
    fired_signals = {label: [] for label in TIER2_WEIGHTS}
    for label, signals in TIER2_WEIGHTS.items():
        for signal_type, signal_value, weight in signals:
            if _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
                scores[label] += weight
                fired_signals[label].append(_evidence_string(signal_type, signal_value))

    max_score = max(scores.values())
    if max_score > 0:
        # Pick the highest scorer; on ties, earliest in TIER2_PRIORITY wins.
        winner = None
        for label in TIER2_PRIORITY:
            if scores[label] == max_score:
                winner = label
                break
        confidence = round(min(max_score, 1.0), 2)
        return {
            "channel": winner,
            "confidence": confidence,
            "evidence": fired_signals[winner],
        }

    # Tier 3: native Anthropic id with no other signal -> transparent relay.
    if TIER3_RELAY_ID_PATTERN.match(message_id):
        return {
            "channel": "anthropic-relay",
            "confidence": TIER3_RELAY_CONFIDENCE,
            "evidence": [f"id_pattern:{TIER3_RELAY_ID_PATTERN.pattern}"],
        }

    return {"channel": "unknown", "confidence": 0.0, "evidence": []}


# ----------------------------------------------------------------------
# Probe runner
# ----------------------------------------------------------------------
#
# Step 14 fires a single minimal /v1/messages probe (max_tokens=4) instead
# of piggybacking on Step 3-10's responses. Rationale: clean separation,
# no client-surface changes, and the cost is ~$0.001 per audit.

def _extract_message_id(body):
    """Pull the top-level `id` field from a JSON response body, returning
    None on parse failure or absence."""
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    msg_id = parsed.get("id")
    if isinstance(msg_id, str):
        return msg_id
    return None


def _build_auth_headers(client):
    """Build the auth headers needed for an authenticated /v1/messages call.

    Mirrors APIClient._call_anthropic / _call_openai. We send BOTH styles
    so the probe works regardless of which format the relay accepts; relays
    that strictly enforce one style will simply ignore the other header.
    """
    api_key = getattr(client, "api_key", "") or ""
    return {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Authorization": f"Bearer {api_key}",
    }


def run_channel_classifier(client):
    """Fire a minimal authenticated /v1/messages probe and classify the
    upstream channel.

    Returns dict with keys:
        channel    -- channel label (see classify_channel)
        confidence -- float in [0.0, 1.0]
        evidence   -- list of evidence strings
        raw_status -- HTTP status (0 on transport error)
        message_id -- the response id (or None)
        error      -- transport error string or None
        verdict    -- "classified" (status 200, classification trusted),
                      "inconclusive" (probe failed: transport error or
                      non-200 status), or "no-signal" (200 OK but no
                      Tier 1/2/3 signals fired)
    """
    model = getattr(client, "model", None) or "claude-haiku-4-5-20251001"
    payload = json.dumps({
        "model": model,
        "max_tokens": 4,
        "messages": [{"role": "user", "content": "ping"}],
    }).encode("utf-8")

    try:
        r = client.raw_request(
            method="POST",
            path="/v1/messages",
            headers=_build_auth_headers(client),
            body=payload,
            content_type="application/json",
            timeout=30,
        )
    except Exception as exc:  # pragma: no cover -- defensive
        return {
            "channel": "unknown",
            "confidence": 0.0,
            "evidence": [],
            "raw_status": 0,
            "message_id": None,
            "error": f"probe-exception: {exc}",
            "verdict": "inconclusive",
        }

    status = r.get("status", 0)
    headers = r.get("headers", {}) or {}
    body = r.get("body", "") or ""
    error = r.get("error")

    # Codex review HIGH fix: only trust the classification on a successful
    # message response. Non-200 (incl. 401/403/404 from auth issues, 5xx
    # from upstream errors) means we're looking at an error envelope, not
    # an authenticated message; classifying it would risk false-positive
    # upstream attribution from error-page server headers.
    if error or status != 200:
        return {
            "channel": "unknown",
            "confidence": 0.0,
            "evidence": [],
            "raw_status": status,
            "message_id": None,
            "error": error,
            "verdict": "inconclusive",
        }

    message_id = _extract_message_id(body)
    classification = classify_channel(headers, message_id, body)
    classification["raw_status"] = status
    classification["message_id"] = message_id
    classification["error"] = error
    classification["verdict"] = (
        "no-signal" if classification["channel"] == "unknown" else "classified"
    )
    return classification
