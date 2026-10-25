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

OpenAI-format usage fingerprint (v2.6): when the client already detected
OpenAI-compatible format, Step 14 also sends one minimal chat-completions
call and checks the key names of its `usage` object for foreign-upstream
residue (``classify_openai_usage``, Tier 1, labels ``anthropic-translated``
and ``foreign-usage-source``).

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
        # Deliberately require Vertex-specific id/body markers. Generic
        # Google edge headers (server: Google Frontend, x-goog-*, via:
        # google) are hosting-surface evidence, not upstream-channel proof.
        ("id_prefix", "msg_vrtx_", 1.0),
        ("body", "vertex-2023-10-16", 0.9),
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
_CHANNEL_BODY_SCAN_LIMIT = 8192


def _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
    """Return True if the (type, value) signal fires against the inputs.

    All inputs are pre-normalized: headers_lower is a lowercased name->value
    dict, message_id is a string (possibly empty), body_truncated is a
    string truncated to _CHANNEL_BODY_SCAN_LIMIT.
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
    body_truncated = (raw_body or "")[:_CHANNEL_BODY_SCAN_LIMIT]

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
# OpenAI-format usage fingerprint (Tier 1, informational, v2.6)
# ----------------------------------------------------------------------
#
# Official Chat Completions usage is {prompt_tokens, completion_tokens,
# total_tokens} plus optional *_details objects. Anthropic-shaped keys in
# that object are residue left by a relay that translates an Anthropic
# upstream response into OpenAI format. A declared non-openai
# ``usage_source`` is a self-reported marker, surfaced only sanitized.
OPENAI_USAGE_TRANSLATED_LABEL = "anthropic-translated"
OPENAI_USAGE_FOREIGN_SOURCE_LABEL = "foreign-usage-source"
OPENAI_USAGE_CLAUDE_CACHE_PREFIX = "claude_cache_creation"
OPENAI_USAGE_ANTHROPIC_PAIR = ("input_tokens", "output_tokens")
OPENAI_USAGE_OPENAI_PAIR = ("prompt_tokens", "completion_tokens")
OPENAI_USAGE_ANTHROPIC_ONLY_KEYS = (
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "cache_creation",
)
OPENAI_USAGE_WEAK_PAIR_EVIDENCE = "usage_keys:input_output_pair"
# usage_source is the only usage value ever surfaced. It and every key name
# shown in a report are reduced to this character set and length first.
OPENAI_USAGE_SOURCE_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")
OPENAI_USAGE_SOURCE_MAX_LEN = 32
OPENAI_USAGE_REPORT_KEY_LIMIT = 8


def _sanitize_usage_text(value):
    """Reduce a usage key name or ``usage_source`` value to a safe token."""
    return OPENAI_USAGE_SOURCE_UNSAFE.sub("", str(value))[:OPENAI_USAGE_SOURCE_MAX_LEN]


def format_usage_key_list(keys):
    """Render usage key names for a report cell or flag message.

    Each name is reduced to ``[A-Za-z0-9_.-]`` and cut to 32 characters
    (``?`` if nothing is left); at most 8 names are listed and the rest
    are summarized as ``+N more``.
    """
    names = [_sanitize_usage_text(k) or "?" for k in keys]
    text = ", ".join(f"`{k}`" for k in names[:OPENAI_USAGE_REPORT_KEY_LIMIT])
    if len(names) > OPENAI_USAGE_REPORT_KEY_LIMIT:
        text += f" +{len(names) - OPENAI_USAGE_REPORT_KEY_LIMIT} more"
    return text


def classify_openai_usage(usage):
    """Flag foreign-upstream residue in an OpenAI-format ``usage`` object.

    Concept inspired by canarybyte/veridrop protocol_templates.py (AGPL-3.0); reimplemented independently.

    Tier 1, deterministic, confidence 1.0 when any rule fires:

      1. Any key starts with ``claude_cache_creation``
         -> ``anthropic-translated``.
      2. ``input_tokens`` and ``output_tokens`` are both present, no
         ``*_details`` key is present, and either ``prompt_tokens`` /
         ``completion_tokens`` are absent or an Anthropic-only cache key
         (``cache_creation_input_tokens``, ``cache_read_input_tokens``,
         ``cache_creation``) is present -> ``anthropic-translated``.
         A pair that misses these conditions (zero-padded next to the
         OpenAI names, or the Responses shape with ``*_details``) only adds
         the weak evidence ``usage_keys:input_output_pair`` and leaves
         the channel ``unknown``.
      3. ``usage_source`` is a string whose sanitized form is not empty and,
         after strip + lowercase, is not ``openai`` (so ``open ai`` and
         `` OpenAI `` do not fire) -> ``foreign-usage-source``. The value
         compared is the value displayed. Non-string values never fire.

    When rule 3 fires together with rule 1 or 2, ``anthropic-translated``
    is the channel and rule 3 stays in ``evidence``.

    No usage value is returned except ``usage_source_value``: the declared
    ``usage_source`` reduced to ``[A-Za-z0-9_.-]`` and cut to 32 characters
    (``None`` when rule 3 did not fire). Key names are returned raw; report
    code renders them through ``format_usage_key_list``. Non-dict input
    returns the no-match result instead of raising.

    Returns:
        dict with keys ``channel`` (``anthropic-translated``,
        ``foreign-usage-source`` or ``unknown``), ``confidence`` (1.0 or
        0.0), ``tier`` (1 or None), ``matched_keys`` (key names of fired
        Tier 1 rules, rule order), ``evidence`` (fixed strings, one per
        fired rule or weak hint, never values) and ``usage_source_value``.
    """
    matched_keys = []
    evidence = []
    source_value = None
    translated = False
    if isinstance(usage, dict):
        cache_keys = sorted(
            k for k in usage
            if isinstance(k, str) and k.startswith(OPENAI_USAGE_CLAUDE_CACHE_PREFIX)
        )
        if cache_keys:
            translated = True
            matched_keys.extend(cache_keys)
            evidence.append(f"usage_key_prefix:{OPENAI_USAGE_CLAUDE_CACHE_PREFIX}")
        if all(k in usage for k in OPENAI_USAGE_ANTHROPIC_PAIR):
            has_details = any(
                isinstance(k, str) and k.endswith("_details") for k in usage
            )
            openai_named = any(k in usage for k in OPENAI_USAGE_OPENAI_PAIR)
            anthropic_only = any(k in usage for k in OPENAI_USAGE_ANTHROPIC_ONLY_KEYS)
            if not has_details and (not openai_named or anthropic_only):
                translated = True
                matched_keys.extend(OPENAI_USAGE_ANTHROPIC_PAIR)
                evidence.append("usage_keys:input_tokens+output_tokens")
            else:
                evidence.append(OPENAI_USAGE_WEAK_PAIR_EVIDENCE)
        source = usage.get("usage_source")
        if isinstance(source, str):
            sanitized = _sanitize_usage_text(source)
            if sanitized and sanitized.strip().lower() != "openai":
                matched_keys.append("usage_source")
                evidence.append("usage_source:non-openai")
                source_value = sanitized
    if translated:
        channel = OPENAI_USAGE_TRANSLATED_LABEL
    elif source_value is not None:
        channel = OPENAI_USAGE_FOREIGN_SOURCE_LABEL
    else:
        return {
            "channel": "unknown",
            "confidence": 0.0,
            "tier": None,
            "matched_keys": [],
            "evidence": evidence,
            "usage_source_value": None,
        }
    return {
        "channel": channel,
        "confidence": 1.0,
        "tier": 1,
        "matched_keys": matched_keys,
        "evidence": evidence,
        "usage_source_value": source_value,
    }

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


def _coarse_probe_error(error):
    """Reduce a ``call()`` error to ``HTTP <status>`` or ``transport error``.

    ``call()`` errors embed up to 200 characters of the response body
    (``HTTP 401: {...}``); nothing of the body may reach the report.
    """
    match = re.match(r"\s*HTTP\s+(\d{3})\b", str(error))
    if match:
        return f"HTTP {match.group(1)}"
    return "transport error"


def run_openai_usage_probe(client):
    """Fingerprint the ``usage`` object of one minimal OpenAI-format call.

    Uses the client's normal ``call()`` path with ``max_tokens=4``; Step 14
    only invokes this when the client already detected OpenAI format, so the
    request goes to ``/v1/chat/completions``. Never raises.

    Returns the ``classify_openai_usage`` dict plus:
        usage_keys -- sorted top-level key names of ``usage`` (raw, no values;
                      render through ``format_usage_key_list``)
        error      -- ``HTTP <status>`` / ``transport error`` (response body
                      dropped), or None
        verdict    -- "classified" (a Tier 1 rule fired), "no-signal" (usage
                      present, no Tier 1 rule fired) or "inconclusive" (call
                      failed or the response had no usage object)
    """
    try:
        res = client.call([{"role": "user", "content": "ping"}], max_tokens=4)
    except Exception:  # call() catches internally; stay defensive
        res = {"error": "probe-exception"}
    if not isinstance(res, dict):
        res = {"error": "probe returned no result"}
    error = res.get("error")
    raw = res.get("raw")
    usage = raw.get("usage") if isinstance(raw, dict) and not error else None
    result = classify_openai_usage(usage)
    result["usage_keys"] = sorted(str(k) for k in usage) if isinstance(usage, dict) else []
    result["error"] = _coarse_probe_error(error) if error else None
    if error or not isinstance(usage, dict):
        result["verdict"] = "inconclusive"
    elif result["matched_keys"]:
        result["verdict"] = "classified"
    else:
        result["verdict"] = "no-signal"
    return result
