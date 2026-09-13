"""Tests for api_relay_audit.stream_integrity.analyze_stream (Sub-PR 2).

The analyzer is pure: given a StreamSignals it returns a dict with a
verdict + supporting fields. No I/O, deterministic. These tests
construct StreamSignals directly (not via the client) so they exercise
only the verdict logic.
"""

import pytest

from api_relay_audit.stream_integrity import (
    KNOWN_SSE_EVENT_TYPES,
    MAX_UNKNOWN_EVENTS_REPORTED,
    StreamSignals,
    _check_stream_complete,
    _check_stream_model,
    _check_usage_consistent,
    _check_usage_monotonic,
    analyze_stream,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_clean_signals():
    """Build a StreamSignals that looks like a clean Anthropic text
    response (no thinking). analyze_stream should return 'clean'."""
    s = StreamSignals()
    s.has_message_start = True
    s.has_content_block_start = True
    s.has_content_block_delta = True
    s.has_message_delta = True
    s.has_message_stop = True
    s.has_text_delta = True
    s.event_types = [
        "message_start", "content_block_start", "content_block_delta",
        "content_block_delta", "content_block_delta",
        "message_delta", "message_stop",
    ]
    s.content_block_types = ["text"]
    s.delta_types = ["text_delta", "text_delta", "text_delta"]
    s.message_start_model = "claude-opus-4-6"
    s.input_tokens = 42
    s.message_delta_input_tokens_samples = [42]
    s.output_tokens_samples = [3, 8, 14]
    s.raw_event_count = 7
    return s


def _make_clean_thinking_signals():
    """Build a StreamSignals that looks like a clean thinking response
    (thinking + text blocks, valid non-empty signature)."""
    s = _make_clean_signals()
    s.thinking_start_seen = True
    s.thinking_delta_seen = True
    s.content_block_types = ["thinking", "text"]
    s.delta_types = ["thinking_delta", "signature_delta", "text_delta"]
    # empty_signature_delta_count stays 0 — real signature was non-empty
    return s


# ---------------------------------------------------------------------------
# Clean verdicts
# ---------------------------------------------------------------------------


class TestAnalyzeStreamClean:

    def test_clean_text_only_stream(self):
        result = analyze_stream(_make_clean_signals())
        assert result["verdict"] == "clean"
        assert result["event_shape"] == "pass"
        assert result["unknown_events"] == []
        assert result["usage_monotonic"] is True
        assert result["usage_consistent"] is True
        assert result["signature_valid"] is True
        assert result["stream_model_is_claude"] is True
        assert result["findings"] == []

    def test_clean_thinking_stream(self):
        result = analyze_stream(_make_clean_thinking_signals())
        assert result["verdict"] == "clean"
        assert result["findings"] == []

    def test_clean_stream_with_ping_events(self):
        """``ping`` events are known and must not count as anomalies."""
        s = _make_clean_signals()
        s.event_types = ["ping"] + s.event_types + ["ping"]
        s.raw_event_count += 2
        result = analyze_stream(s)
        assert result["verdict"] == "clean"
        assert result["unknown_events"] == []

    def test_clean_stream_with_content_block_stop(self):
        """``content_block_stop`` is known and must not count as an
        anomaly. Regression guard — the v1 WebFetch summary missed it."""
        s = _make_clean_signals()
        s.event_types.insert(-2, "content_block_stop")
        s.raw_event_count += 1
        result = analyze_stream(s)
        assert result["verdict"] == "clean"

    def test_clean_stream_with_single_output_token_sample(self):
        """One output_tokens sample is vacuously monotonic."""
        s = _make_clean_signals()
        s.output_tokens_samples = [5]
        result = analyze_stream(s)
        assert result["verdict"] == "clean"
        assert result["usage_monotonic"] is True


# ---------------------------------------------------------------------------
# Anomaly verdicts
# ---------------------------------------------------------------------------


class TestAnalyzeStreamAnomaly:

    def test_unknown_event_type_triggers_anomaly(self):
        s = _make_clean_signals()
        s.event_types.append("custom_injected_event")
        s.raw_event_count += 1
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert "custom_injected_event" in result["unknown_events"]
        assert any("unknown SSE event" in f for f in result["findings"])

    def test_many_unknown_events_capped_at_max_reported(self):
        """More than MAX_UNKNOWN_EVENTS_REPORTED distinct unknown events
        must be capped in the output but still report the total count."""
        s = _make_clean_signals()
        extras = [f"unknown_{i}" for i in range(MAX_UNKNOWN_EVENTS_REPORTED + 3)]
        s.event_types.extend(extras)
        s.raw_event_count += len(extras)
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert len(result["unknown_events"]) == MAX_UNKNOWN_EVENTS_REPORTED
        assert any("+more, capped" in f for f in result["findings"])

    def test_usage_non_monotonic_triggers_anomaly(self):
        """output_tokens going backwards means a relay is rewriting."""
        s = _make_clean_signals()
        s.output_tokens_samples = [3, 8, 5, 10]  # 8 -> 5 is a regression
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["usage_monotonic"] is False
        assert any("non-monotonic" in f or "backwards" in f for f in result["findings"])

    def test_usage_input_tokens_inconsistent_triggers_anomaly(self):
        """input_tokens at message_start must equal message_delta samples."""
        s = _make_clean_signals()
        s.input_tokens = 42
        s.message_delta_input_tokens_samples = [42, 100, 42]  # 100 is wrong
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["usage_consistent"] is False
        assert any("disagrees" in f for f in result["findings"])

    def test_empty_signature_delta_triggers_anomaly(self):
        """An empty signature_delta is the thinking-block downgrade
        signal hvoy.ai's claude_detector.py watches for."""
        s = _make_clean_thinking_signals()
        s.empty_signature_delta_count = 2
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["signature_valid"] is False
        assert any("empty signatures" in f for f in result["findings"])

    def test_non_claude_stream_model_triggers_anomaly(self):
        """message_start.message.model = 'gpt-4' means the relay routed
        our claude request to a substitute upstream."""
        s = _make_clean_signals()
        s.message_start_model = "gpt-5.4"
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_model_is_claude"] is False
        assert any("does not contain 'claude'" in f for f in result["findings"])

    def test_multiple_anomalies_all_reported(self):
        """When multiple things are wrong, every finding should appear."""
        s = _make_clean_signals()
        s.event_types.append("custom_event")
        s.raw_event_count += 1
        s.output_tokens_samples = [10, 5]
        s.empty_signature_delta_count = 1
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        # At least 3 distinct findings (unknown event, non-monotonic, empty sig)
        assert len(result["findings"]) >= 3

    def test_qwen_stream_model_triggers_anomaly(self):
        """Chinese-market substitute case: relay routes to Qwen."""
        s = _make_clean_signals()
        s.message_start_model = "qwen2.5-72b-instruct"
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_model_is_claude"] is False

    def test_missing_stream_model_triggers_anomaly(self):
        """A relay can hide a downgrade by stripping the model field
        instead of exposing a non-Claude upstream name."""
        s = _make_clean_signals()
        s.message_start_model = None
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_model_is_claude"] is False
        assert any("omitted message_start.message.model" in f for f in result["findings"])

    def test_missing_message_stop_triggers_anomaly(self):
        s = _make_clean_signals()
        s.event_types.remove("message_stop")
        s.has_message_stop = False
        s.raw_event_count -= 1
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_complete"] is False
        assert result["event_shape"] != "pass"
        assert any("without message_stop" in finding for finding in result["findings"])

    def test_duplicate_message_stop_triggers_anomaly(self):
        s = _make_clean_signals()
        s.event_types.append("message_stop")
        s.raw_event_count += 1
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_complete"] is False
        assert any("exactly once" in finding for finding in result["findings"])

    def test_message_stop_before_start_triggers_anomaly(self):
        s = _make_clean_signals()
        s.event_types.remove("message_stop")
        s.event_types.insert(0, "message_stop")
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_complete"] is False
        assert any("before message_start" in finding for finding in result["findings"])

    def test_non_ping_event_after_message_stop_triggers_anomaly(self):
        s = _make_clean_signals()
        s.event_types.append("message_delta")
        s.raw_event_count += 1
        result = analyze_stream(s)
        assert result["verdict"] == "anomaly"
        assert result["stream_complete"] is False
        assert any("not final" in finding for finding in result["findings"])

    def test_ping_after_message_stop_remains_clean(self):
        s = _make_clean_signals()
        s.event_types.append("ping")
        s.raw_event_count += 1
        result = analyze_stream(s)
        assert result["verdict"] == "clean"
        assert result["stream_complete"] is True


# ---------------------------------------------------------------------------
# Inconclusive verdicts
# ---------------------------------------------------------------------------


class TestAnalyzeStreamInconclusive:

    def test_transport_error_is_inconclusive(self):
        s = StreamSignals()
        s.transport_error = "HTTP 422: unprocessable"
        result = analyze_stream(s)
        assert result["verdict"] == "inconclusive"
        assert result["stream_complete"] is False
        assert any("transport error" in f.lower() for f in result["findings"])

    def test_zero_events_is_inconclusive(self):
        """No events at all (e.g. stream closed immediately)."""
        s = StreamSignals()
        result = analyze_stream(s)
        assert result["verdict"] == "inconclusive"

    def test_only_ping_events_is_inconclusive(self):
        """Stream with only ping keepalives but no message_start is
        effectively a non-Anthropic response — no basis to judge."""
        s = StreamSignals()
        s.event_types = ["ping", "ping", "ping"]
        s.raw_event_count = 3
        result = analyze_stream(s)
        assert result["verdict"] == "inconclusive"

    def test_transport_error_takes_priority_over_other_signals(self):
        """Even if other fields look anomalous, transport error short-
        circuits the verdict to inconclusive."""
        s = _make_clean_signals()
        s.transport_error = "timeout"
        s.event_types.append("malicious_event")
        result = analyze_stream(s)
        assert result["verdict"] == "inconclusive"
        # The anomaly-specific checks should be skipped
        assert result["unknown_events"] == []

    def test_inconclusive_returns_complete_dict_shape(self):
        """Regression: inconclusive branches must return the same keys
        as anomaly/clean branches so downstream reporters don't KeyError."""
        s = StreamSignals()
        s.transport_error = "err"
        result = analyze_stream(s)
        for key in (
            "verdict", "event_shape", "unknown_events",
            "usage_monotonic", "usage_consistent", "signature_valid",
            "stream_complete", "stream_model_name",
            "stream_model_is_claude", "findings",
        ):
            assert key in result, f"Missing key {key} in inconclusive result"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class TestHelperFunctions:

    def test_check_stream_complete_requires_terminal_message_stop(self):
        s = _make_clean_signals()
        assert _check_stream_complete(s) is True
        s.event_types.remove("message_stop")
        assert _check_stream_complete(s) is False

    def test_check_usage_monotonic_empty_list(self):
        s = StreamSignals()
        assert _check_usage_monotonic(s) is True

    def test_check_usage_monotonic_strict_increasing(self):
        s = StreamSignals()
        s.output_tokens_samples = [1, 2, 3, 5, 10]
        assert _check_usage_monotonic(s) is True

    def test_check_usage_monotonic_equal_samples_ok(self):
        """Monotonic NON-decreasing allows equal consecutive samples."""
        s = StreamSignals()
        s.output_tokens_samples = [5, 5, 5]
        assert _check_usage_monotonic(s) is True

    def test_check_usage_monotonic_decrease_detected(self):
        s = StreamSignals()
        s.output_tokens_samples = [1, 2, 1]
        assert _check_usage_monotonic(s) is False

    def test_check_usage_consistent_no_start_value(self):
        s = StreamSignals()
        s.message_delta_input_tokens_samples = [42]
        assert _check_usage_consistent(s) is True  # no anchor to compare

    def test_check_usage_consistent_matching_samples(self):
        s = StreamSignals()
        s.input_tokens = 42
        s.message_delta_input_tokens_samples = [42, 42]
        assert _check_usage_consistent(s) is True

    def test_check_usage_consistent_one_mismatch(self):
        s = StreamSignals()
        s.input_tokens = 42
        s.message_delta_input_tokens_samples = [42, 100]
        assert _check_usage_consistent(s) is False

    def test_check_stream_model_empty(self):
        s = StreamSignals()
        assert _check_stream_model(s) is False

    def test_check_stream_model_claude_opus(self):
        s = StreamSignals()
        s.message_start_model = "claude-opus-4-6"
        assert _check_stream_model(s) is True

    def test_check_stream_model_claude_case_insensitive(self):
        s = StreamSignals()
        s.message_start_model = "CLAUDE-SONNET"
        assert _check_stream_model(s) is True

    def test_check_stream_model_gpt(self):
        s = StreamSignals()
        s.message_start_model = "gpt-5"
        assert _check_stream_model(s) is False

    def test_check_stream_model_qwen(self):
        s = StreamSignals()
        s.message_start_model = "qwen2.5"
        assert _check_stream_model(s) is False
