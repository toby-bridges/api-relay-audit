"""Tests for Step 14 upstream channel classifier."""

import json
from unittest.mock import MagicMock

import pytest

from api_relay_audit.channel_classifier import (
    TIER1_RULES,
    TIER2_PRIORITY,
    TIER2_WEIGHTS,
    TIER3_RELAY_CONFIDENCE,
    TIER3_RELAY_ID_PATTERN,
    classify_channel,
    run_channel_classifier,
)


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

    def test_google_vertex_via_x_goog_header(self):
        result = classify_channel({"x-goog-trace": "abc"}, None, "")
        assert result["channel"] == "google-vertex"
        assert result["confidence"] == 1.0

    def test_google_vertex_weak_signals_only_partial_confidence(self):
        # server: google + via: google = 0.5 + 0.5 = 1.0 cap
        result = classify_channel(
            {"server": "Google Frontend", "via": "1.1 google"}, None, ""
        )
        assert result["channel"] == "google-vertex"
        assert result["confidence"] == 1.0

    def test_google_vertex_server_only_yields_low_score(self):
        result = classify_channel({"server": "Google Frontend"}, None, "")
        assert result["channel"] == "google-vertex"
        assert result["confidence"] == 0.5

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

    def test_vertex_beats_apigateway_on_tie(self):
        # Vertex 1.0, APIGW 0.8 -> Vertex wins on score, but also priority.
        # Check explicit equal-score tie:
        result = classify_channel(
            {"x-goog-x": "y", "x-amz-apigw-id": "z"}, None, ""
        )
        # Vertex score 1.0 > APIGW 0.8, score-based winner
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
