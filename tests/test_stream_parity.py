"""Tests for the informational Step 10 stream / non-stream parity check.

Three layers:

1. ``compare_stream_nonstream()`` - the pure comparison (no I/O). Only
   input_tokens and the streamed stop_reason decide the verdict; text
   similarity and output_tokens are notes.
2. ``_populate_stream_signals()`` - the ``text`` / ``stop_reason`` capture on
   ``StreamSignals``.
3. ``test_stream_integrity()`` in both distributions - the parity section
   must never change Step 10's return value or summary flags.
"""

import importlib.util
from pathlib import Path

import pytest

from api_relay_audit.client import MAX_STREAM_TEXT_CHARS, _populate_stream_signals
from api_relay_audit.reporter import Reporter
from api_relay_audit.stream_integrity import (
    PARITY_INPUT_TOKEN_TOLERANCE,
    PARITY_OUTPUT_TOKEN_FLOOR,
    PARITY_OUTPUT_TOKEN_FRAC,
    PARITY_SIMILARITY_MIN,
    PARITY_VALID_STOP_REASONS,
    StreamSignals,
    compare_stream_nonstream,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PROBE = [{"role": "user", "content": "Reply with the single word: ok"}]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stream(text="ok", input_tokens=20, output_tokens=5, stop_reason="end_turn"):
    """StreamSignals that analyze_stream judges clean, plus parity fields."""
    s = StreamSignals()
    s.has_message_start = True
    s.has_content_block_start = True
    s.has_content_block_delta = True
    s.has_message_delta = True
    s.has_message_stop = True
    s.has_text_delta = True
    s.event_types = [
        "message_start", "content_block_start", "content_block_delta",
        "content_block_stop", "message_delta", "message_stop",
    ]
    s.content_block_types = ["text"]
    s.delta_types = ["text_delta"]
    s.message_start_model = "claude-opus-4-6"
    s.input_tokens = input_tokens
    s.output_tokens_samples = [output_tokens] if output_tokens else []
    s.raw_event_count = 6
    s.text = text
    s.stop_reason = stop_reason
    return s


def _nonstream(text="ok", input_tokens=20, output_tokens=5):
    return {
        "text": text,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "raw": {},
        "time": 0.1,
    }


# ---------------------------------------------------------------------------
# compare_stream_nonstream
# ---------------------------------------------------------------------------


class TestCompareStreamNonstream:

    def test_identical_text_is_consistent(self):
        result = compare_stream_nonstream(_stream(), _nonstream())
        assert result["verdict"] == "consistent"
        assert result["similarity"] == 1.0
        assert result["input_tokens_delta"] == 0
        assert result["output_tokens_delta"] == 0
        assert result["stop_reason_valid"] is True
        assert result["notes"] == []

    def test_case_and_punctuation_are_normalized(self):
        result = compare_stream_nonstream(_stream(text="ok"), _nonstream(text=" OK. "))
        assert result["similarity"] == 1.0
        assert result["verdict"] == "consistent"

    def test_similar_text_is_consistent(self):
        result = compare_stream_nonstream(
            _stream(text="The quick brown fox jumps over the lazy dog."),
            _nonstream(text="The quick brown fox jumped over the lazy dog."),
        )
        assert PARITY_SIMILARITY_MIN <= result["similarity"] < 1.0
        assert result["verdict"] == "consistent"

    def test_text_difference_is_noted_not_scored(self):
        result = compare_stream_nonstream(
            _stream(text="ok"),
            _nonstream(text="I am a large language model trained by another lab."),
        )
        assert result["similarity"] < PARITY_SIMILARITY_MIN
        assert result["verdict"] == "consistent"
        assert any("similarity" in note for note in result["notes"])

    def test_input_token_gap_beyond_tolerance_is_divergent(self):
        result = compare_stream_nonstream(
            _stream(input_tokens=20),
            _nonstream(input_tokens=20 + PARITY_INPUT_TOKEN_TOLERANCE + 1),
        )
        assert result["input_tokens_delta"] == -(PARITY_INPUT_TOKEN_TOLERANCE + 1)
        assert result["verdict"] == "divergent"
        assert any("input_tokens differ" in note for note in result["notes"])

    def test_input_token_gap_at_tolerance_is_consistent(self):
        result = compare_stream_nonstream(
            _stream(input_tokens=20 + PARITY_INPUT_TOKEN_TOLERANCE),
            _nonstream(input_tokens=20),
        )
        assert result["input_tokens_delta"] == PARITY_INPUT_TOKEN_TOLERANCE
        assert result["verdict"] == "consistent"

    def test_invalid_stop_reason_is_divergent(self):
        result = compare_stream_nonstream(_stream(stop_reason="content_filter"), _nonstream())
        assert result["stop_reason_valid"] is False
        assert result["verdict"] == "divergent"

    def test_missing_stop_reason_is_divergent(self):
        result = compare_stream_nonstream(_stream(stop_reason=None), _nonstream())
        assert result["stop_reason_valid"] is False
        assert result["verdict"] == "divergent"

    @pytest.mark.parametrize("stop_reason", ["refusal", "pause_turn"])
    def test_refusal_and_pause_turn_are_valid(self, stop_reason):
        result = compare_stream_nonstream(_stream(stop_reason=stop_reason), _nonstream())
        assert result["stop_reason_valid"] is True
        assert result["verdict"] == "consistent"

    def test_output_token_gap_is_noted_not_scored(self):
        result = compare_stream_nonstream(
            _stream(output_tokens=5), _nonstream(output_tokens=40),
        )
        assert result["output_tokens_delta"] == -35
        assert result["output_tokens_tolerance"] == int(PARITY_OUTPUT_TOKEN_FRAC * 40)
        assert result["verdict"] == "consistent"
        assert any("output_tokens differ" in note for note in result["notes"])

    def test_small_output_gap_uses_floor(self):
        result = compare_stream_nonstream(
            _stream(output_tokens=2), _nonstream(output_tokens=5),
        )
        assert result["output_tokens_tolerance"] == PARITY_OUTPUT_TOKEN_FLOOR
        assert result["notes"] == []

    def test_output_skipped_without_message_delta(self):
        signals = _stream(output_tokens=1)
        signals.has_message_delta = False
        result = compare_stream_nonstream(signals, _nonstream(output_tokens=40))
        assert result["output_tokens_delta"] is None
        assert result["verdict"] == "consistent"
        assert any("output_tokens not reported" in note for note in result["notes"])

    def test_nonstream_failure_is_inconclusive(self):
        result = compare_stream_nonstream(_stream(), {"error": "HTTP 500", "time": 0.2})
        assert result["verdict"] == "inconclusive"
        assert result["input_tokens_delta"] is None
        assert result["output_tokens_delta"] is None
        assert result["similarity"] is None
        assert result["notes"][0] == "Non-stream request unavailable: HTTP 500"

    def test_empty_text_with_matching_input_is_consistent(self):
        result = compare_stream_nonstream(_stream(text="  "), _nonstream())
        assert result["verdict"] == "consistent"
        assert result["similarity"] is None
        assert result["notes"] == ["text missing on one side; similarity not computed"]

    def test_empty_text_with_input_gap_is_divergent(self):
        result = compare_stream_nonstream(
            _stream(),
            _nonstream(text="", input_tokens=20 + PARITY_INPUT_TOKEN_TOLERANCE + 1),
        )
        assert result["verdict"] == "divergent"
        assert result["similarity"] is None
        assert any("input_tokens differ" in note for note in result["notes"])
        assert "text missing on one side; similarity not computed" in result["notes"]
        assert not any("nothing to compare" in note for note in result["notes"])

    def test_input_tokens_missing_on_both_sides_is_inconclusive(self):
        result = compare_stream_nonstream(
            _stream(input_tokens=None), _nonstream(input_tokens=0),
        )
        assert result["verdict"] == "inconclusive"
        assert result["notes"][0].startswith("input_tokens missing on both sides")

    def test_stream_transport_error_is_inconclusive(self):
        signals = _stream()
        signals.transport_error = "curl failed: reset"
        result = compare_stream_nonstream(signals, _nonstream())
        assert result["verdict"] == "inconclusive"
        assert result["notes"][0].startswith("Stream transport error")

    def test_missing_usage_is_noted_not_divergent(self):
        result = compare_stream_nonstream(_stream(), _nonstream(input_tokens=0))
        assert result["input_tokens_delta"] is None
        assert result["verdict"] == "consistent"
        assert "input_tokens missing on one side; check skipped" in result["notes"]

    def test_malformed_stream_fields_do_not_raise(self):
        signals = _stream()
        signals.text = 123
        signals.stop_reason = ["end_turn"]
        signals.output_tokens_samples = "bad"
        result = compare_stream_nonstream(signals, _nonstream())
        assert result["verdict"] == "divergent"
        assert result["similarity"] is None
        assert result["stop_reason"] is None
        assert result["stop_reason_valid"] is False
        assert result["output_tokens_delta"] is None

    def test_result_keys(self):
        result = compare_stream_nonstream(_stream(), _nonstream())
        assert {
            "verdict", "input_tokens_delta", "output_tokens_delta",
            "similarity", "stop_reason_valid", "notes",
        } <= set(result)

    def test_provisional_threshold_values(self):
        assert PARITY_INPUT_TOKEN_TOLERANCE == 3
        assert PARITY_SIMILARITY_MIN == 0.85
        assert PARITY_OUTPUT_TOKEN_FRAC == 0.5
        assert PARITY_OUTPUT_TOKEN_FLOOR == 3
        assert PARITY_VALID_STOP_REASONS == {
            "end_turn", "max_tokens", "stop_sequence", "tool_use",
            "pause_turn", "refusal",
        }


# ---------------------------------------------------------------------------
# _populate_stream_signals: text and stop_reason capture
# ---------------------------------------------------------------------------


class TestPopulateParitySignals:

    def test_text_deltas_accumulate_in_order(self):
        signals = StreamSignals()
        for chunk in ("Hel", "lo", " world"):
            _populate_stream_signals(
                {"type": "content_block_delta",
                 "delta": {"type": "text_delta", "text": chunk}},
                signals,
            )
        _populate_stream_signals(
            {"type": "content_block_delta",
             "delta": {"type": "thinking_delta", "thinking": "hidden"}},
            signals,
        )
        assert signals.text == "Hello world"

    def test_message_delta_captures_stop_reason(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "message_delta",
             "delta": {"stop_reason": "end_turn", "stop_sequence": None},
             "usage": {"output_tokens": 4}},
            signals,
        )
        assert signals.stop_reason == "end_turn"
        assert signals.output_tokens_samples == [4]

    def test_message_start_usage_is_not_an_output_sample(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "message_start",
             "message": {"model": "claude-opus-4-6",
                         "usage": {"input_tokens": 20, "output_tokens": 1}}},
            signals,
        )
        assert signals.input_tokens == 20
        assert signals.output_tokens_samples == []

    def test_malformed_parity_fields_are_ignored(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": 7}},
            signals,
        )
        _populate_stream_signals({"type": "message_delta", "delta": "bad"}, signals)
        assert signals.text == ""
        assert signals.stop_reason is None

    def test_text_accumulation_is_capped(self):
        signals = StreamSignals()
        chunk = "x" * 1024
        for _ in range(MAX_STREAM_TEXT_CHARS // 1024 + 5):
            _populate_stream_signals(
                {"type": "content_block_delta",
                 "delta": {"type": "text_delta", "text": chunk}},
                signals,
            )
        assert len(signals.text) == MAX_STREAM_TEXT_CHARS


# ---------------------------------------------------------------------------
# Step 10 wiring, modular and standalone
# ---------------------------------------------------------------------------


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module", params=["modular", "standalone"])
def audit_module(request):
    if request.param == "modular":
        return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_stream_parity")
    return _load(REPO_ROOT / "audit.py", "standalone_audit_stream_parity")


class _FakeClient:
    def __init__(self, signals, nonstream=None, call_exc=None,
                 detected_format="anthropic"):
        self._signals = signals
        self._nonstream = nonstream
        self._call_exc = call_exc
        self.detected_format = detected_format
        self.stream_calls = []
        self.calls = []

    def stream_call(self, *args, **kwargs):
        self.stream_calls.append((args, kwargs))
        return self._signals

    def call(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self._call_exc is not None:
            raise self._call_exc
        return self._nonstream


def _run(audit_module, client):
    report = Reporter()
    result = audit_module.test_stream_integrity(client, report)
    return result, report, "".join(report.sections)


class TestStep10ParityWiring:

    def test_requests_mirror_the_unchanged_stream_probe(self, audit_module):
        client = _FakeClient(_stream(), nonstream=_nonstream())
        _run(audit_module, client)
        expected = [((PROBE,), {"max_tokens": 100, "with_thinking": True})]
        assert client.stream_calls == expected
        assert client.calls == expected

    def test_consistent_parity_is_reported(self, audit_module):
        client = _FakeClient(_stream(), nonstream=_nonstream(text="OK."))
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert "### Stream / non-stream parity (informational)" in body
        assert "| Observed parity | consistent | not scored |" in body

    def test_divergent_parity_leaves_verdict_and_flags_unchanged(self, audit_module):
        client = _FakeClient(
            _stream(),
            nonstream=_nonstream(text="A very different answer from elsewhere.",
                                 input_tokens=60),
        )
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert [level for level, _ in report.summary] == ["green"]
        assert "| Observed parity | divergent | not scored |" in body

    def test_nonstream_error_is_inconclusive_and_step_continues(self, audit_module):
        client = _FakeClient(_stream(), nonstream={"error": "HTTP 502", "time": 0.1})
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert "| Observed parity | inconclusive | not scored |" in body
        assert "Non-stream request unavailable: HTTP 502" in body

    def test_nonstream_exception_never_escapes(self, audit_module):
        client = _FakeClient(_stream(), call_exc=RuntimeError("boom"))
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert [level for level, _ in report.summary] == ["green"]
        assert "Parity check failed: RuntimeError: boom" in body

    def test_failed_stream_sends_no_nonstream_request(self, audit_module):
        signals = StreamSignals()
        signals.transport_error = "HTTP 400: thinking not supported"
        client = _FakeClient(signals, nonstream=_nonstream())
        result, report, body = _run(audit_module, client)
        assert result == ("inconclusive", True)
        assert client.calls == []
        assert "| Observed parity | inconclusive | not scored |" in body

    def test_stream_events_without_text_send_no_request(self, audit_module):
        client = _FakeClient(_stream(text=""), nonstream=_nonstream())
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert client.calls == []
        assert "| Observed parity | inconclusive | not scored |" in body

    def test_non_anthropic_client_sends_no_nonstream_request(self, audit_module):
        client = _FakeClient(_stream(), nonstream=_nonstream(), detected_format="openai")
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert client.calls == []
        assert "rather than 'anthropic'" in body

    def test_undetected_format_sends_no_request(self, audit_module):
        client = _FakeClient(_stream(), nonstream=_nonstream(), detected_format=None)
        result, report, body = _run(audit_module, client)
        assert result == ("clean", False)
        assert client.calls == []
        assert "format is None rather than 'anthropic'" in body
