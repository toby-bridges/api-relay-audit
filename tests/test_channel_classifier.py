"""Tests for Step 14 upstream channel classifier."""

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from api_relay_audit.channel_classifier import (
    TIER1_RULES,
    TIER2_PRIORITY,
    TIER2_WEIGHTS,
    TIER3_RELAY_CONFIDENCE,
    TIER3_RELAY_ID_PATTERN,
    classify_channel,
    classify_openai_usage,
    format_usage_key_list,
    run_channel_classifier,
    run_openai_usage_probe,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Tier 1 — deterministic single-signal rules
# ---------------------------------------------------------------------------

class TestTier1Deterministic:
    def test_openrouter_via_id_prefix(self):
        result = classify_channel({}, "gen-abc12345xyz", "")
        assert result["channel"] == "openrouter"
        assert result["confidence"] == 1.0
        assert result["evidence"] == ["id_prefix:gen-"]

    def test_openrouter_via_generation_id_header(self):
        result = classify_channel(
            {"x-generation-id": "gen-abc12345xyz"}, None, ""
        )
        assert result["channel"] == "openrouter"
        assert result["confidence"] == 1.0
        # First-match rule order: id_prefix wins if id present, but here id
        # is None so the header rule fires.
        assert result["evidence"] == ["header:x-generation-id=gen-*"]

    def test_cloudflare_ai_gateway_via_cf_aig_prefix(self):
        result = classify_channel({"cf-aig-cache-status": "hit"}, None, "")
        assert result["channel"] == "cloudflare-ai-gateway"
        assert result["confidence"] == 1.0
        assert result["evidence"] == ["header_prefix:cf-aig-"]

    def test_cf_ray_alone_does_not_trigger_ai_gateway(self):
        # cf-ray is plain Cloudflare CDN edge, NOT AI Gateway. Step 12
        # already classifies that as "cloudflare"; Step 14 must not falsely
        # claim cloudflare-ai-gateway.
        result = classify_channel(
            {"cf-ray": "abc123-DFW", "server": "cloudflare"}, None, ""
        )
        assert result["channel"] == "unknown"

    def test_tier1_returns_immediately_skips_tier2(self):
        # OpenRouter id should win even if a Tier 2 Bedrock signal also
        # fires (deterministic rules return at confidence 1.0 immediately).
        result = classify_channel(
            {"x-amzn-bedrock-invocation-latency": "42"},
            "gen-abc12345xyz",
            "",
        )
        assert result["channel"] == "openrouter"
        assert result["confidence"] == 1.0


# ---------------------------------------------------------------------------
# Tier 2 — weighted scoring
# ---------------------------------------------------------------------------

class TestTier2Weighted:
    def test_aws_bedrock_via_header_prefix(self):
        result = classify_channel(
            {"x-amzn-bedrock-invocation-latency": "120"}, None, ""
        )
        assert result["channel"] == "aws-bedrock"
        assert result["confidence"] == 1.0
        assert "header_prefix:x-amzn-bedrock-" in result["evidence"]

    def test_aws_bedrock_via_id_prefix(self):
        result = classify_channel({}, "msg_bdrk_abc12345xyz", "")
        assert result["channel"] == "aws-bedrock"
        assert result["confidence"] == 1.0

    def test_aws_bedrock_via_body_anthropic_version(self):
        body = '{"id": "msg_xyz", "anthropic_version": "bedrock-2023-05-31"}'
        result = classify_channel({}, "msg_xyz", body)
        assert result["channel"] == "aws-bedrock"
        # 0.9 weight only -> capped at 1.0 but we expect 0.9 here
        assert result["confidence"] == 0.9

    def test_aws_bedrock_multiple_signals_capped_at_1_0(self):
        # 1.0 + 1.0 + 0.9 = 2.9, clamped to 1.0
        body = '{"anthropic_version": "bedrock-2023-05-31"}'
        result = classify_channel(
            {"x-amzn-bedrock-invocation-latency": "120"},
            "msg_bdrk_xyz",
            body,
        )
        assert result["channel"] == "aws-bedrock"
        assert result["confidence"] == 1.0
        # All three signals appear in evidence
        assert len(result["evidence"]) == 3

    def test_google_vertex_via_id_prefix(self):
        result = classify_channel({}, "msg_vrtx_abc12345xyz", "")
        assert result["channel"] == "google-vertex"
        assert result["confidence"] == 1.0

    def test_x_goog_header_alone_does_not_over_attribute_vertex(self):
        result = classify_channel({"x-goog-trace": "abc"}, None, "")
        assert result["channel"] == "unknown"
        assert result["confidence"] == 0.0

    def test_google_edge_headers_do_not_over_attribute_vertex(self):
        # Generic Google Frontend / via headers identify an edge or hosting
        # surface, not the actual upstream model-serving channel.
        result = classify_channel(
            {"server": "Google Frontend", "via": "1.1 google"}, None, ""
        )
        assert result["channel"] == "unknown"
        assert result["confidence"] == 0.0

    def test_google_frontend_server_only_does_not_classify(self):
        result = classify_channel({"server": "Google Frontend"}, None, "")
        assert result["channel"] == "unknown"
        assert result["confidence"] == 0.0

    def test_aws_apigateway_via_amz_apigw_id(self):
        result = classify_channel({"x-amz-apigw-id": "abc"}, None, "")
        assert result["channel"] == "aws-apigateway"
        assert result["confidence"] == 0.8

    def test_aws_apigateway_via_apigw_requestid(self):
        result = classify_channel({"apigw-requestid": "xyz"}, None, "")
        assert result["channel"] == "aws-apigateway"
        assert result["confidence"] == 0.8

    def test_anthropic_official_via_ratelimit_header(self):
        result = classify_channel(
            {"anthropic-ratelimit-tokens-remaining": "9999"}, None, ""
        )
        assert result["channel"] == "anthropic-official"
        assert result["confidence"] == 0.95

    def test_anthropic_official_via_request_id_prefix(self):
        result = classify_channel({"request-id": "req_011AbC"}, None, "")
        assert result["channel"] == "anthropic-official"
        assert result["confidence"] == 0.6

    def test_anthropic_official_combined(self):
        # ratelimit (0.95) + request-id req_ (0.6) = 1.55 -> 1.0 cap
        result = classify_channel(
            {
                "anthropic-ratelimit-tokens-remaining": "9999",
                "request-id": "req_011",
            },
            None,
            "",
        )
        assert result["channel"] == "anthropic-official"
        assert result["confidence"] == 1.0


# ---------------------------------------------------------------------------
# Tier 2 — tie-breaking via TIER2_PRIORITY
# ---------------------------------------------------------------------------

class TestTier2TieBreaking:
    def test_bedrock_beats_vertex_on_tie(self):
        # Both score 1.0; Bedrock listed first in TIER2_PRIORITY.
        result = classify_channel(
            {"x-amzn-bedrock-x": "y", "x-goog-z": "w"}, None, ""
        )
        assert result["channel"] == "aws-bedrock"

    def test_vertex_body_marker_beats_apigateway(self):
        # Vertex-specific body marker (0.9) beats API Gateway's generic gateway
        # header (0.8), while x-goog-* alone is intentionally not enough.
        result = classify_channel(
            {"x-amz-apigw-id": "z"},
            None,
            '{"anthropic_version":"vertex-2023-10-16"}',
        )
        assert result["channel"] == "google-vertex"

    def test_apigateway_beats_anthropic_on_tie(self):
        # APIGW 0.8, Anthropic-Official 0.6 (request-id only) -> APIGW
        result = classify_channel(
            {"x-amz-apigw-id": "abc", "request-id": "req_xx"}, None, ""
        )
        assert result["channel"] == "aws-apigateway"


# ---------------------------------------------------------------------------
# Tier 3 — relay-proxy inference
# ---------------------------------------------------------------------------

class TestTier3RelayInference:
    def test_native_anthropic_id_with_no_other_signals(self):
        result = classify_channel({}, "msg_01ABcDeFgHiJkLmNoPqRsTuV", "")
        assert result["channel"] == "anthropic-relay"
        assert result["confidence"] == TIER3_RELAY_CONFIDENCE
        assert result["confidence"] == 0.5

    def test_anthropic_official_signal_overrides_relay_inference(self):
        # Same id, but ratelimit header is present -> Tier 2 fires first.
        result = classify_channel(
            {"anthropic-ratelimit-tokens-remaining": "9999"},
            "msg_01ABcDeFgHiJkLmNoPqRsTuV",
            "",
        )
        assert result["channel"] == "anthropic-official"

    def test_msg_02_id_does_not_match_relay_pattern(self):
        # Pattern is anchored to msg_01 specifically.
        result = classify_channel({}, "msg_02ABcDeFgHiJkLmNoPqRsTuV", "")
        assert result["channel"] == "unknown"

    def test_short_msg_01_id_does_not_match(self):
        # Need >= 22 characters after msg_01.
        result = classify_channel({}, "msg_01short", "")
        assert result["channel"] == "unknown"

    def test_21_char_suffix_just_below_threshold(self):
        # Codex MEDIUM fix: regex says {22,} but old {21,} accepted 21-char
        # suffixes. This test locks the boundary so a future loosening is
        # caught. 21 chars after msg_01 must NOT match.
        suffix_21 = "A" * 21
        assert TIER3_RELAY_ID_PATTERN.match(f"msg_01{suffix_21}") is None
        result = classify_channel({}, f"msg_01{suffix_21}", "")
        assert result["channel"] == "unknown"

    def test_22_char_suffix_at_threshold(self):
        # 22 chars after msg_01 is the minimum match.
        suffix_22 = "A" * 22
        assert TIER3_RELAY_ID_PATTERN.match(f"msg_01{suffix_22}") is not None
        result = classify_channel({}, f"msg_01{suffix_22}", "")
        assert result["channel"] == "anthropic-relay"


# ---------------------------------------------------------------------------
# Unknown fallback + edge cases
# ---------------------------------------------------------------------------

class TestUnknownFallback:
    def test_no_signals_yields_unknown(self):
        result = classify_channel({"random-header": "x"}, "anonymous", "")
        assert result["channel"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["evidence"] == []

    def test_null_headers_handled(self):
        result = classify_channel(None, None, None)
        assert result["channel"] == "unknown"

    def test_empty_inputs(self):
        result = classify_channel({}, "", "")
        assert result["channel"] == "unknown"

    def test_case_insensitive_header_matching(self):
        # Header name case must not affect detection.
        result = classify_channel(
            {"X-Amzn-Bedrock-Invocation-Latency": "120"}, None, ""
        )
        assert result["channel"] == "aws-bedrock"


# ---------------------------------------------------------------------------
# run_channel_classifier — probe runner
# ---------------------------------------------------------------------------

class TestRunChannelClassifier:
    def _make_client(self, response, model="claude-haiku-4-5-20251001",
                     api_key="sk-test-key-123"):
        client = MagicMock()
        client.model = model
        client.api_key = api_key
        client.raw_request = MagicMock(return_value=response)
        return client

    def test_anthropic_official_response_classified(self):
        body = json.dumps({
            "id": "msg_01ABcDeFgHiJkLmNoPqRsTuV",
            "model": "claude-haiku-4-5-20251001",
            "content": [{"type": "text", "text": "pong"}],
        })
        client = self._make_client({
            "status": 200,
            "headers": {
                "anthropic-ratelimit-tokens-remaining": "9999",
                "request-id": "req_011AbC",
            },
            "body": body,
            "error": None,
        })
        result = run_channel_classifier(client)
        assert result["channel"] == "anthropic-official"
        assert result["confidence"] == 1.0
        assert result["raw_status"] == 200
        assert result["message_id"] == "msg_01ABcDeFgHiJkLmNoPqRsTuV"
        assert result["error"] is None
        assert result["verdict"] == "classified"

    def test_bedrock_response_with_anthropic_version_in_body(self):
        body = json.dumps({
            "id": "msg_bdrk_xyz",
            "anthropic_version": "bedrock-2023-05-31",
            "content": [{"type": "text", "text": "pong"}],
        })
        client = self._make_client({
            "status": 200,
            "headers": {"x-amzn-bedrock-invocation-latency": "120"},
            "body": body,
            "error": None,
        })
        result = run_channel_classifier(client)
        assert result["channel"] == "aws-bedrock"
        assert result["message_id"] == "msg_bdrk_xyz"
        assert result["verdict"] == "classified"

    def test_transport_error_yields_inconclusive(self):
        client = self._make_client({
            "status": 0,
            "headers": {},
            "body": "",
            "error": "Connection refused",
        })
        result = run_channel_classifier(client)
        assert result["channel"] == "unknown"
        assert result["verdict"] == "inconclusive"
        assert result["confidence"] == 0.0
        assert result["raw_status"] == 0
        assert result["error"] == "Connection refused"
        assert result["message_id"] is None

    def test_401_response_yields_inconclusive_not_classified(self):
        # Codex CRITICAL/HIGH fix: a 401 from auth rejection must NOT be
        # classified -- the response body is an error envelope, not a
        # message. Server headers from a 401 page would falsely attribute
        # an upstream channel.
        client = self._make_client({
            "status": 401,
            "headers": {"server": "Google Frontend"},  # would have falsely
                                                      # matched google-vertex
            "body": '{"error": "invalid api key"}',
            "error": None,
        })
        result = run_channel_classifier(client)
        assert result["channel"] == "unknown"
        assert result["verdict"] == "inconclusive"
        assert result["raw_status"] == 401
        # No false-positive vertex classification from error-page server header
        assert result["evidence"] == []

    def test_502_bad_gateway_yields_inconclusive(self):
        client = self._make_client({
            "status": 502,
            "headers": {"server": "nginx"},
            "body": "<html>502 Bad Gateway</html>",
            "error": None,
        })
        result = run_channel_classifier(client)
        assert result["channel"] == "unknown"
        assert result["verdict"] == "inconclusive"
        assert result["raw_status"] == 502

    def test_200_ok_with_no_signals_is_no_signal_not_inconclusive(self):
        # 200 OK with a valid body but zero upstream signals -- the relay
        # successfully proxied the request but stripped all upstream
        # identifiers. This is "classified as nothing", distinct from
        # "couldn't classify" (inconclusive).
        body = json.dumps({"id": "anonymous", "content": []})
        client = self._make_client({
            "status": 200,
            "headers": {"x-relay-version": "1.0"},
            "body": body,
            "error": None,
        })
        result = run_channel_classifier(client)
        assert result["channel"] == "unknown"
        assert result["verdict"] == "no-signal"
        assert result["raw_status"] == 200

    def test_probe_includes_auth_headers(self):
        # Codex CRITICAL fix: probe must include auth or it's just an
        # unauthenticated 401 dance (cannot ever classify a real upstream).
        client = self._make_client({
            "status": 200, "headers": {}, "body": "", "error": None,
        }, api_key="sk-my-secret-key")
        run_channel_classifier(client)
        _, kwargs = client.raw_request.call_args
        sent_headers = kwargs.get("headers") or {}
        # Both auth styles are sent so the probe works on either format.
        assert sent_headers.get("x-api-key") == "sk-my-secret-key"
        assert sent_headers.get("Authorization") == "Bearer sk-my-secret-key"
        assert sent_headers.get("anthropic-version") == "2023-06-01"

    def test_probe_uses_max_tokens_4(self):
        client = self._make_client({
            "status": 200, "headers": {}, "body": "", "error": None,
        })
        run_channel_classifier(client)
        _, kwargs = client.raw_request.call_args
        body = kwargs.get("body")
        assert body is not None
        parsed = json.loads(body)
        assert parsed["max_tokens"] == 4
        assert parsed["model"] == "claude-haiku-4-5-20251001"

    def test_probe_uses_client_model_when_present(self):
        client = self._make_client(
            {"status": 200, "headers": {}, "body": "", "error": None},
            model="claude-opus-4-7",
        )
        run_channel_classifier(client)
        _, kwargs = client.raw_request.call_args
        body = kwargs.get("body")
        parsed = json.loads(body)
        assert parsed["model"] == "claude-opus-4-7"

    def test_probe_handles_missing_api_key_gracefully(self):
        # If a test harness gives us a client with no api_key, we still
        # send headers (with empty key) rather than crashing.
        client = self._make_client(
            {"status": 401, "headers": {}, "body": "", "error": None},
            api_key=None,
        )
        result = run_channel_classifier(client)
        # 401 from missing key -> inconclusive (correct behavior)
        assert result["verdict"] == "inconclusive"
        _, kwargs = client.raw_request.call_args
        sent_headers = kwargs.get("headers") or {}
        assert sent_headers.get("x-api-key") == ""


# ---------------------------------------------------------------------------
# Constants exported for parity testing
# ---------------------------------------------------------------------------

class TestConstantsShape:
    """Defensive: the parity test in test_dual_distribution_parity.py asserts
    these constants are character-identical between modular + standalone.
    These tests just confirm the constants exist and are well-formed so
    accidental refactors get caught locally before parity tests run.
    """

    def test_tier1_rules_shape(self):
        assert isinstance(TIER1_RULES, list)
        for rule in TIER1_RULES:
            assert len(rule) == 3
            label, signal_type, signal_value = rule
            assert isinstance(label, str)
            assert isinstance(signal_type, str)

    def test_tier2_weights_shape(self):
        assert isinstance(TIER2_WEIGHTS, dict)
        assert set(TIER2_WEIGHTS.keys()) == set(TIER2_PRIORITY)
        for label, signals in TIER2_WEIGHTS.items():
            for entry in signals:
                assert len(entry) == 3
                _, _, weight = entry
                assert isinstance(weight, float)
                assert 0.0 < weight <= 1.0

    def test_tier2_priority_is_tuple(self):
        assert isinstance(TIER2_PRIORITY, tuple)
        assert len(TIER2_PRIORITY) == 4

    def test_tier3_pattern_compiled(self):
        assert TIER3_RELAY_ID_PATTERN.pattern == r"^msg_01[A-Za-z0-9]{22,}$"


# ---------------------------------------------------------------------------
# OpenAI-format usage fingerprint (v2.6, informational)
# ---------------------------------------------------------------------------

_STANDARD_OPENAI_USAGE = {
    "prompt_tokens": 8,
    "completion_tokens": 4,
    "total_tokens": 12,
    "prompt_tokens_details": {"cached_tokens": 0},
}


class TestClassifyOpenAIUsage:
    def test_usage_source_not_openai_is_foreign_source(self):
        result = classify_openai_usage(
            dict(_STANDARD_OPENAI_USAGE, usage_source="anthropic")
        )
        assert result["channel"] == "foreign-usage-source"
        assert result["confidence"] == 1.0
        assert result["tier"] == 1
        assert result["matched_keys"] == ["usage_source"]
        assert result["evidence"] == ["usage_source:non-openai"]
        assert result["usage_source_value"] == "anthropic"

    def test_anthropic_translated_wins_over_foreign_source(self):
        result = classify_openai_usage(dict(
            _STANDARD_OPENAI_USAGE,
            claude_cache_creation_5_m_tokens=0,
            usage_source="gemini",
        ))
        assert result["channel"] == "anthropic-translated"
        assert result["evidence"] == [
            "usage_key_prefix:claude_cache_creation",
            "usage_source:non-openai",
        ]
        assert result["usage_source_value"] == "gemini"

    @pytest.mark.parametrize(("raw", "expected"), [
        ("Vertex AI/<b>gemini</b>|x`y", "VertexAIbgeminibxy"),
        ("z" * 40, "z" * 32),
    ])
    def test_usage_source_value_is_sanitized_and_truncated(self, raw, expected):
        result = classify_openai_usage({"usage_source": raw})
        assert result["channel"] == "foreign-usage-source"
        assert result["usage_source_value"] == expected

    def test_claude_cache_creation_prefix_matches(self):
        result = classify_openai_usage(dict(
            _STANDARD_OPENAI_USAGE,
            claude_cache_creation_5_m_tokens=0,
            claude_cache_creation_1_h_tokens=0,
        ))
        assert result["channel"] == "anthropic-translated"
        assert result["confidence"] == 1.0
        assert result["tier"] == 1
        assert result["matched_keys"] == [
            "claude_cache_creation_1_h_tokens",
            "claude_cache_creation_5_m_tokens",
        ]

    def test_input_and_output_tokens_pair_matches(self):
        result = classify_openai_usage({"input_tokens": 8, "output_tokens": 4})
        assert result["channel"] == "anthropic-translated"
        assert result["confidence"] == 1.0
        assert result["tier"] == 1
        assert result["matched_keys"] == ["input_tokens", "output_tokens"]

    def test_standard_openai_usage_does_not_match(self):
        result = classify_openai_usage(dict(_STANDARD_OPENAI_USAGE))
        assert result == {
            "channel": "unknown",
            "confidence": 0.0,
            "tier": None,
            "matched_keys": [],
            "evidence": [],
            "usage_source_value": None,
        }

    @pytest.mark.parametrize("value", ["openai", "OpenAI", " openai ", "", None])
    def test_openai_or_empty_usage_source_does_not_match(self, value):
        usage = dict(_STANDARD_OPENAI_USAGE, usage_source=value)
        assert classify_openai_usage(usage)["channel"] == "unknown"

    def test_input_tokens_alone_does_not_match(self):
        usage = dict(_STANDARD_OPENAI_USAGE, input_tokens=8)
        assert classify_openai_usage(usage)["channel"] == "unknown"

    @pytest.mark.parametrize("usage", [
        {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12,
         "input_tokens": 0, "output_tokens": 0},
        dict(_STANDARD_OPENAI_USAGE, input_tokens=0, output_tokens=0),
    ])
    def test_zero_padded_pair_next_to_openai_names_is_weak_only(self, usage):
        result = classify_openai_usage(usage)
        assert result["channel"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["tier"] is None
        assert result["matched_keys"] == []
        assert result["evidence"] == ["usage_keys:anthropic-style-names"]

    def test_responses_shape_is_weak_only(self):
        result = classify_openai_usage({
            "input_tokens": 8,
            "output_tokens": 4,
            "total_tokens": 12,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        })
        assert result["channel"] == "unknown"
        assert result["matched_keys"] == []
        assert result["evidence"] == ["usage_keys:anthropic-style-names"]

    def test_pair_with_anthropic_only_cache_key_is_translated(self):
        result = classify_openai_usage({
            "prompt_tokens": 8,
            "completion_tokens": 4,
            "total_tokens": 12,
            "input_tokens": 8,
            "output_tokens": 4,
            "cache_read_input_tokens": 0,
        })
        assert result["channel"] == "anthropic-translated"
        assert result["matched_keys"] == ["input_tokens", "output_tokens"]
        assert result["evidence"] == ["usage_keys:input_tokens+output_tokens"]

    @pytest.mark.parametrize(
        "value", [False, 0, 42, [], {}, "   ", chr(0x4E2D) + chr(0x6587)]
    )
    def test_non_string_or_unprintable_usage_source_does_not_fire(self, value):
        result = classify_openai_usage(
            dict(_STANDARD_OPENAI_USAGE, usage_source=value)
        )
        assert result["channel"] == "unknown"
        assert result["matched_keys"] == []
        assert result["usage_source_value"] is None

    @pytest.mark.parametrize(
        "value", [None, "usage", 42, [], ["input_tokens", "output_tokens"]]
    )
    def test_non_dict_input_returns_no_match_without_raising(self, value):
        result = classify_openai_usage(value)
        assert result["channel"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["matched_keys"] == []

    def test_only_sanitized_usage_source_value_is_surfaced(self):
        result = classify_openai_usage({
            "usage_source": "upstream-secret-name",
            "input_tokens": 1234567,
            "output_tokens": 7654321,
        })
        assert result["usage_source_value"] == "upstream-secret-name"
        rest = {k: v for k, v in result.items() if k != "usage_source_value"}
        rendered = json.dumps(rest)
        assert "upstream-secret-name" not in rendered
        assert "1234567" not in rendered
        assert result["matched_keys"] == [
            "input_tokens", "output_tokens", "usage_source",
        ]


class TestRunOpenAIUsageProbe:
    def _make_client(self, call_result=None, side_effect=None):
        client = MagicMock()
        client.call = MagicMock(return_value=call_result, side_effect=side_effect)
        return client

    def test_translated_usage_is_classified_with_minimal_probe(self):
        usage = dict(_STANDARD_OPENAI_USAGE, claude_cache_creation_5_m_tokens=0)
        client = self._make_client({"text": "po", "raw": {"usage": usage}})
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "classified"
        assert result["channel"] == "anthropic-translated"
        assert result["error"] is None
        assert result["usage_keys"] == sorted(usage)
        args, kwargs = client.call.call_args
        assert args[0] == [{"role": "user", "content": "ping"}]
        assert kwargs["max_tokens"] == 4

    def test_standard_usage_is_no_signal(self):
        client = self._make_client(
            {"text": "po", "raw": {"usage": dict(_STANDARD_OPENAI_USAGE)}}
        )
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "no-signal"
        assert result["channel"] == "unknown"

    def test_call_error_is_inconclusive(self):
        client = self._make_client({"error": "HTTP 503: upstream busy"})
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "inconclusive"
        assert result["error"] == "HTTP 503"
        assert result["channel"] == "unknown"

    def test_missing_usage_is_inconclusive(self):
        client = self._make_client({"text": "po", "raw": {"id": "chatcmpl-1"}})
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "inconclusive"
        assert result["usage_keys"] == []

    def test_call_exception_is_inconclusive_not_raised(self):
        client = self._make_client(side_effect=RuntimeError("boom"))
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "inconclusive"
        assert result["error"] == "transport error"

    def test_call_returning_none_is_transport_error(self):
        client = self._make_client(None)
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "inconclusive"
        assert result["error"] == "transport error"

    def test_missing_raw_is_inconclusive(self):
        client = self._make_client({"text": "po"})
        result = run_openai_usage_probe(client)
        assert result["verdict"] == "inconclusive"
        assert result["error"] is None

    @pytest.mark.parametrize(("error", "expected"), [
        ('HTTP 401: {"error":{"message":"Incorrect API key provided: '
         'sk-live-ABCDEF"}}', "HTTP 401"),
        ("curl failed: SSL handshake with relay.example failed",
         "transport error"),
        ("Both formats failed", "transport error"),
    ])
    def test_call_error_is_reduced_to_status_or_transport(self, error, expected):
        client = self._make_client({"error": error})
        result = run_openai_usage_probe(client)
        assert result["error"] == expected
        assert "sk-live" not in json.dumps(result)


class TestFormatUsageKeyList:
    def test_injected_name_is_sanitized_and_cut(self):
        evil = "claude_cache_creation_x|\n## Overall rating: LOW `" + "A" * 300
        assert format_usage_key_list([evil]) == "`claude_cache_creation_xOverallra`"

    def test_list_is_capped_with_more_suffix(self):
        text = format_usage_key_list([f"key_{i}" for i in range(20)])
        assert text.endswith(" +12 more")
        assert text.count("`") == 16

    def test_name_with_nothing_printable_shows_placeholder(self):
        assert format_usage_key_list(["|`\n"]) == "`?`"


class _RecordingReport:
    def __init__(self):
        self.lines = []
        self.flags = []

    def h2(self, t):
        self.lines.append(f"## {t}")

    def h3(self, t):
        self.lines.append(f"### {t}")

    def p(self, t):
        self.lines.append(t)

    def flag(self, level, msg):
        self.flags.append((level, msg))


def _load_audit(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_AUDIT_DISTRIBUTIONS = [
    (REPO_ROOT / "scripts" / "audit.py", "_p2b_modular_audit"),
    (REPO_ROOT / "audit.py", "_p2b_standalone_audit"),
]


_TRANSLATED_USAGE_WITH_UNSAFE_SOURCE = dict(
    _STANDARD_OPENAI_USAGE,
    prompt_tokens=8123,
    claude_cache_creation_5_m_tokens=0,
    usage_source="up<stream>| x",
)


def _step14_client(detected_format, usage=None):
    client = MagicMock()
    client.detected_format = detected_format
    client.model = "claude-haiku-4-5-20251001"
    client.api_key = "sk-test-key-123"
    client.raw_request = MagicMock(return_value={
        "status": 404, "headers": {}, "body": "", "error": None,
    })
    client.call = MagicMock(return_value={
        "text": "po",
        "raw": {"usage": dict(usage or _TRANSLATED_USAGE_WITH_UNSAFE_SOURCE)},
    })
    return client


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
def test_step14_openai_format_adds_usage_fingerprint_section(path, module_name):
    module = _load_audit(path, module_name)
    client = _step14_client("openai")
    report = _RecordingReport()
    result = module.test_channel_classifier(client, report)
    assert result["openai_usage"]["verdict"] == "classified"
    assert result["openai_usage"]["channel"] == "anthropic-translated"
    assert "### OpenAI-format usage fingerprint (informational)" in report.lines
    client.call.assert_called_once()
    assert client.call.call_args.kwargs["max_tokens"] == 4
    green = [msg for level, msg in report.flags if level == "green"]
    assert any("Anthropic-translated" in msg for msg in green)
    everything = "\n".join(report.lines + [msg for _, msg in report.flags])
    assert "usage_source=upstreamx" in everything
    assert "<stream>" not in everything
    assert "8123" not in everything


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
def test_step14_openai_format_reports_foreign_usage_source(path, module_name):
    module = _load_audit(path, module_name)
    client = _step14_client(
        "openai", usage=dict(_STANDARD_OPENAI_USAGE, usage_source="gemini")
    )
    report = _RecordingReport()
    result = module.test_channel_classifier(client, report)
    assert result["openai_usage"]["channel"] == "foreign-usage-source"
    assert "| usage_source | `usage_source=gemini` |" in report.lines
    green = [msg for level, msg in report.flags if level == "green"]
    assert any("usage_source=gemini" in msg for msg in green)


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
@pytest.mark.parametrize("detected_format", ["anthropic", None])
def test_step14_non_openai_format_path_is_unchanged(path, module_name, detected_format):
    module = _load_audit(path, module_name)
    client = _step14_client(detected_format)
    report = _RecordingReport()
    result = module.test_channel_classifier(client, report)
    assert "openai_usage" not in result
    client.call.assert_not_called()
    assert not any("usage fingerprint" in line for line in report.lines)


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
def test_step14_usage_key_names_are_sanitized_and_capped(path, module_name):
    module = _load_audit(path, module_name)
    evil = "claude_cache_creation_x|\n## Overall rating: LOW `" + "A" * 300
    many = {f"claude_cache_creation_{i}": 0 for i in range(500)}
    cases = [
        (dict(_STANDARD_OPENAI_USAGE, **{evil: 0}),
         "`claude_cache_creation_xOverallra`"),
        (dict(_STANDARD_OPENAI_USAGE, **many), "+492 more"),
    ]
    for usage, marker in cases:
        client = _step14_client("openai", usage=usage)
        report = _RecordingReport()
        module.test_channel_classifier(client, report)
        rows = [line for line in report.lines
                if line.startswith(("| matched keys", "| usage keys"))]
        flags = [msg for _, msg in report.flags if "Anthropic-translated" in msg]
        assert len(rows) == 2 and len(flags) == 1
        matched_row = next(r for r in rows if r.startswith("| matched keys"))
        assert marker in matched_row and marker in flags[0]
        for text in rows + flags:
            assert "\n" not in text
            assert "## Overall" not in text
            assert "A" * 40 not in text
            assert len(text) < 800
        assert all(row.count("|") == 3 for row in rows)


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
def test_step14_probe_error_row_shows_status_only(path, module_name):
    module = _load_audit(path, module_name)
    client = _step14_client("openai")
    body = ('{"error":{"message":"Incorrect API key provided: '
            'sk-live-ABCDEFGHIJKLMNOPQRSTUV0123456789"}}')
    client.call = MagicMock(return_value={"error": "HTTP 401: " + body})
    report = _RecordingReport()
    result = module.test_channel_classifier(client, report)
    assert result["openai_usage"]["verdict"] == "inconclusive"
    assert "| probe | ERR: HTTP 401 |" in report.lines
    everything = "\n".join(report.lines + [msg for _, msg in report.flags])
    assert "sk-live" not in everything
    assert "Incorrect API key" not in everything


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
@pytest.mark.parametrize(("call_result", "verdict", "marker"), [
    ({"text": "po", "raw": {"usage": {"prompt_tokens": 8, "completion_tokens": 4,
                                      "total_tokens": 12}}},
     "no-signal", "No Anthropic-translated or foreign-source usage fields"),
    ({"text": "po", "raw": {"usage": {"prompt_tokens": 8, "completion_tokens": 4,
                                      "total_tokens": 12, "input_tokens": 0,
                                      "output_tokens": 0}}},
     "no-signal", "Weak naming hint only"),
    (None, "inconclusive", "Usage fingerprint **inconclusive**"),
    ({"text": "po"}, "inconclusive", "Usage fingerprint **inconclusive**"),
])
def test_step14_report_no_signal_and_inconclusive_branches(
        path, module_name, call_result, verdict, marker):
    module = _load_audit(path, module_name)
    client = _step14_client("openai")
    client.call = MagicMock(return_value=call_result)
    report = _RecordingReport()
    result = module.test_channel_classifier(client, report)
    assert result["openai_usage"]["verdict"] == verdict
    marker_lines = [line for line in report.lines if marker in line]
    assert marker_lines
    assert not [msg for level, msg in report.flags if level == "green"]
    if marker.startswith("Weak"):
        assert all("Anthropic" not in line for line in marker_lines)


@pytest.mark.parametrize(("path", "module_name"), _AUDIT_DISTRIBUTIONS)
def test_step14_add_on_exception_is_inconclusive_not_crash(
        path, module_name, monkeypatch):
    module = _load_audit(path, module_name)

    def explode(client, report):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(module, "_report_openai_usage_fingerprint", explode)
    client = _step14_client("openai")
    report = _RecordingReport()
    result = module.test_channel_classifier(client, report)
    assert result["openai_usage"] == {"verdict": "inconclusive",
                                      "error": "RuntimeError"}
    assert any("internal error (RuntimeError)" in line for line in report.lines)
    assert not any("secret detail" in line for line in report.lines)
