"""Tests for the opt-in Step 10 thinking signature round-trip.

Four layers, all offline with recorded responses:

1. ``analyze_signature_roundtrip()`` - the pure verdict.
2. ``tamper_signature()`` / ``build_replay_assistant_content()`` - the
   replayed assistant turn.
3. ``_populate_stream_signals()`` - the ``thinking_blocks`` capture.
4. ``APIClient.replay_thinking()`` and ``test_stream_integrity()`` in both
   distributions - the replay request bodies, and the section never changing
   Step 10's return value or summary flags.
"""

import importlib.util
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from api_relay_audit import client as client_module
from api_relay_audit import stream_integrity
from api_relay_audit.client import (
    MAX_STREAM_THINKING_BLOCKS,
    MAX_STREAM_THINKING_CHARS,
    _populate_stream_signals,
)
from api_relay_audit.reporter import Reporter
from api_relay_audit.stream_integrity import (
    StreamSignals,
    analyze_signature_roundtrip,
    build_replay_assistant_content,
    has_replayable_signature,
    replay_accepted,
    tamper_signature,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PROBE = [{"role": "user", "content": "Reply with the single word: ok"}]
FOLLOW_UP = "Reply with the single word: done"
SIGNATURE = "EqQBCkYIBxgCKkCm" + "Zx9q" * 40 + "kQ=="
API_KEY = "sk-test-0123456789abcdefghijklmnop"
SIGNED = {"type": "thinking", "thinking": "Short reasoning.", "signature": SIGNATURE}
REDACTED = {"type": "redacted_thinking", "data": "ZW5jcnlwdGVk"}
SIGNATURE_ERROR = "messages.1.content.0: Invalid `signature` in `thinking` block"


def _ok(input_tokens=57):
    return {"status": 200, "error": None, "error_type": None,
            "input_tokens": input_tokens}


def _rejected(status=400, error=SIGNATURE_ERROR, error_type="invalid_request_error"):
    return {"status": status, "error": error, "error_type": error_type,
            "input_tokens": None}


def _diff_positions(a, b):
    assert len(a) == len(b)
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# 1. analyze_signature_roundtrip
# ---------------------------------------------------------------------------


class TestAnalyzeSignatureRoundtrip:

    def test_intact_accepted_and_tampered_400_on_signature_is_upstream_verified(self):
        result = analyze_signature_roundtrip(_ok(), _rejected())
        assert result["verdict"] == "upstream-verified"
        assert result["intact_status"] == 200
        assert result["tampered_status"] == 400
        assert result["tampered_mentions_signature"] is True

    def test_both_accepted_is_no_signal_with_equal_tokens_uninformative(self):
        result = analyze_signature_roundtrip(_ok(57), _ok(57))
        assert result["verdict"] == "no-signal"
        joined = " ".join(result["notes"])
        assert "strip" in joined and "forged" in joined
        assert "uninformative" in joined

    def test_lower_tampered_input_tokens_is_an_inference_note_only(self):
        result = analyze_signature_roundtrip(_ok(57), _ok(40))
        assert result["verdict"] == "no-signal"
        inference = [n for n in result["notes"] if n.startswith("Inference")]
        assert len(inference) == 1
        assert "40 vs 57" in inference[0] and "dropped" in inference[0]

    def test_intact_rejected_is_inconclusive_and_records_error_type(self):
        result = analyze_signature_roundtrip(
            _rejected(400, "thinking.budget_tokens too small", "invalid_request_error"),
            None,
        )
        assert result["verdict"] == "inconclusive"
        assert "invalid_request_error" in result["notes"][0]

    @pytest.mark.parametrize("error, thinking_only", [
        ("thinking.budget_tokens: Input should be greater than or equal to 1024", True),
        ("messages.1.content.0: Invalid `thinking` block", True),
        ("Bad request: malformed body", False),
    ])
    def test_tampered_400_without_signature_is_inconclusive(self, error, thinking_only):
        result = analyze_signature_roundtrip(
            _ok(), _rejected(400, error, "invalid_request_error"))
        assert result["verdict"] == "inconclusive"
        assert result["tampered_mentions_signature"] is False
        note = result["notes"][0]
        assert "invalid_request_error" in note and "not attributed" in note
        assert ("thinking only" in note) is thinking_only

    def test_2xx_with_an_error_body_is_never_accepted(self):
        error_200 = {"status": 200, "error": "Overloaded",
                     "error_type": "overloaded_error", "input_tokens": None}
        assert not replay_accepted(error_200)
        intact_side = analyze_signature_roundtrip(error_200, None)
        assert intact_side["verdict"] == "inconclusive"
        assert "overloaded_error" in intact_side["notes"][0]
        tampered_side = analyze_signature_roundtrip(_ok(), error_200)
        assert tampered_side["verdict"] == "inconclusive"
        assert "non-message body" in tampered_side["notes"][0]

    @pytest.mark.parametrize("tampered", [
        _rejected(500, "signature service unavailable", "api_error"),
        _rejected(429, "rate limited", "rate_limit_error"),
        {"status": None, "error": "curl failed: timeout", "error_type": None,
         "input_tokens": None},
        None,
    ])
    def test_other_tampered_outcomes_are_inconclusive(self, tampered):
        assert analyze_signature_roundtrip(_ok(), tampered)["verdict"] == "inconclusive"


# ---------------------------------------------------------------------------
# 2. tamper_signature / build_replay_assistant_content
# ---------------------------------------------------------------------------


class TestReplayContent:

    @pytest.mark.parametrize("signature", [SIGNATURE, "AAAA", "abcAdefg", "x"])
    def test_tamper_changes_exactly_the_middle_character(self, signature):
        tampered = tamper_signature(signature)
        assert _diff_positions(signature, tampered) == [len(signature) // 2]

    def test_blocks_keep_order_and_only_the_first_signed_block_is_tampered(self):
        second = {"type": "thinking", "thinking": "More.", "signature": "c2lnMg=="}
        blocks = [REDACTED, SIGNED, second]
        intact = build_replay_assistant_content(blocks, "ok")
        assert intact == [REDACTED, SIGNED, second, {"type": "text", "text": "ok"}]
        tampered = build_replay_assistant_content(blocks, "ok", tamper=True)
        assert blocks == [REDACTED, SIGNED, second]
        assert SIGNED["signature"] == SIGNATURE
        assert tampered[0] == REDACTED and tampered[2] == second
        assert _diff_positions(SIGNATURE, tampered[1]["signature"]) == [len(SIGNATURE) // 2]
        assert build_replay_assistant_content([SIGNED], "  ") == [SIGNED]


# ---------------------------------------------------------------------------
# 3. thinking_blocks capture in the SSE parser
# ---------------------------------------------------------------------------


def _feed(events):
    signals = StreamSignals()
    for event in events:
        _populate_stream_signals(event, signals)
    return signals


def _start(block, index):
    return {"type": "content_block_start", "index": index, "content_block": block}


def _delta(delta, index):
    return {"type": "content_block_delta", "index": index, "delta": delta}


class TestThinkingCapture:

    def test_blocks_are_captured_in_stream_order(self):
        signals = _feed([
            {"type": "message_start", "message": {"model": "claude-opus-4-6"}},
            _start({"type": "thinking", "thinking": "", "signature": ""}, 0),
            _delta({"type": "thinking_delta", "thinking": "Short "}, 0),
            _delta({"type": "thinking_delta", "thinking": "reasoning."}, 0),
            _delta({"type": "signature_delta", "signature": SIGNATURE}, 0),
            {"type": "content_block_stop", "index": 0},
            _start(dict(REDACTED), 1),
            {"type": "content_block_stop", "index": 1},
            _start({"type": "text", "text": ""}, 2),
            _delta({"type": "text_delta", "text": "ok"}, 2),
            {"type": "content_block_stop", "index": 2},
        ])
        assert signals.thinking_blocks == [SIGNED, REDACTED]
        assert signals.thinking_block_indexes == [0, 1]
        assert signals.thinking_capture_issue is None
        assert signals.text == "ok"
        assert signals.empty_signature_delta_count == 0
        assert has_replayable_signature(signals)

    def test_interleaved_blocks_and_early_signature_are_attributed_by_index(self):
        signals = _feed([
            _start({"type": "thinking", "thinking": "", "signature": ""}, 0),
            _start({"type": "thinking", "thinking": "", "signature": ""}, 1),
            _delta({"type": "signature_delta", "signature": "S1"}, 1),
            _delta({"type": "thinking_delta", "thinking": "B"}, 1),
            _start({"type": "text", "text": ""}, 2),
            _delta({"type": "text_delta", "text": "ok"}, 2),
            _delta({"type": "thinking_delta", "thinking": "A"}, 0),
            _delta({"type": "signature_delta", "signature": "S0"}, 0),
        ])
        assert signals.thinking_blocks == [
            {"type": "thinking", "thinking": "A", "signature": "S0"},
            {"type": "thinking", "thinking": "B", "signature": "S1"},
        ]
        assert signals.thinking_capture_issue is None
        assert has_replayable_signature(signals)

    @pytest.mark.parametrize("events", [
        # signature_delta before its content_block_start
        [_delta({"type": "signature_delta", "signature": SIGNATURE}, 0),
         _start({"type": "thinking", "thinking": "", "signature": ""}, 0)],
        # thinking_delta inside a text block
        [_start({"type": "thinking", "thinking": "", "signature": SIGNATURE}, 0),
         _start({"type": "text", "text": ""}, 1),
         _delta({"type": "thinking_delta", "thinking": "stray"}, 1)],
        # delta without an index
        [_start({"type": "thinking", "thinking": "", "signature": ""}, 0),
         {"type": "content_block_delta",
          "delta": {"type": "signature_delta", "signature": SIGNATURE}}],
        # the same block index started twice
        [_start({"type": "thinking", "thinking": "", "signature": ""}, 0),
         _start({"type": "thinking", "thinking": "", "signature": ""}, 0)],
    ])
    def test_unattributable_events_stop_the_capture(self, events):
        signals = _feed(events)
        assert signals.thinking_capture_issue

    def test_only_redacted_thinking_has_no_replayable_signature(self):
        signals = _feed([_start(dict(REDACTED), 0)])
        assert signals.thinking_blocks == [REDACTED]
        assert not has_replayable_signature(signals)

    def test_capture_bounds_mark_the_capture_truncated(self):
        oversized = _feed([
            _start({"type": "thinking", "thinking": "", "signature": ""}, 0),
            _delta({"type": "thinking_delta",
                    "thinking": "x" * (MAX_STREAM_THINKING_CHARS + 1)}, 0),
            _delta({"type": "signature_delta", "signature": SIGNATURE}, 0),
        ])
        assert "bound" in oversized.thinking_capture_issue
        assert oversized.thinking_blocks[0]["signature"] == ""
        many = _feed([
            _start({"type": "thinking", "thinking": "", "signature": ""}, i)
            for i in range(MAX_STREAM_THINKING_BLOCKS + 1)
        ])
        assert "bound" in many.thinking_capture_issue
        assert len(many.thinking_blocks) == MAX_STREAM_THINKING_BLOCKS


# ---------------------------------------------------------------------------
# 4a. APIClient.replay_thinking, modular and standalone
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", params=["modular", "standalone"])
def dist(request):
    if request.param == "modular":
        return SimpleNamespace(
            APIClient=client_module.APIClient,
            build=stream_integrity.build_replay_assistant_content,
            analyze=stream_integrity.analyze_signature_roundtrip,
        )
    module = _load(REPO_ROOT / "audit.py", "standalone_audit_signature_client")
    return SimpleNamespace(
        APIClient=module.APIClient,
        build=module.build_replay_assistant_content,
        analyze=module.analyze_signature_roundtrip,
    )


def _client(dist, responses):
    client = dist.APIClient("https://relay.example.com/v1", API_KEY,
                            "claude-opus-4-6", verbose=False)
    client.raw_request = MagicMock(side_effect=responses)
    return client


def _raw(status, payload):
    return {"status": status, "headers": {}, "body": json.dumps(payload), "error": None}


class TestReplayThinkingClient:

    def test_replay_bodies_carry_the_original_and_a_one_char_tampered_signature(self, dist):
        client = _client(dist, [
            _raw(200, {"type": "message", "content": [{"type": "text", "text": "done"}],
                       "usage": {"input_tokens": 57, "output_tokens": 4}}),
            _raw(400, {"type": "error", "error": {"type": "invalid_request_error",
                                                   "message": SIGNATURE_ERROR}}),
        ])
        intact = client.replay_thinking(PROBE, dist.build([SIGNED], "ok"), FOLLOW_UP)
        tampered = client.replay_thinking(
            PROBE, dist.build([SIGNED], "ok", tamper=True), FOLLOW_UP)

        assert client.raw_request.call_count == 2
        bodies = []
        for call in client.raw_request.call_args_list:
            method, path, headers, raw_body = call.args
            assert (method, path) == ("POST", "/v1/messages")
            assert headers["x-api-key"] == API_KEY
            assert call.kwargs["content_type"] == "application/json"
            bodies.append(json.loads(raw_body))
        first, second = bodies
        for body in bodies:
            assert not {"temperature", "top_p", "top_k", "system", "tools",
                        "stream"} & set(body)
            assert body["model"] == "claude-opus-4-6"
            assert body["max_tokens"] == 32
            assert body["thinking"] == {"type": "enabled", "budget_tokens": 31}
            assert body["messages"][0] == PROBE[0]
            assert body["messages"][2] == {"role": "user", "content": FOLLOW_UP}
            assert body["messages"][1]["role"] == "assistant"
        assert first["messages"][1]["content"] == [SIGNED, {"type": "text", "text": "ok"}]
        sent = second["messages"][1]["content"][0]["signature"]
        assert len(_diff_positions(SIGNATURE, sent)) == 1
        second["messages"][1]["content"][0]["signature"] = SIGNATURE
        assert second == first

        assert intact == {"status": 200, "error": None, "error_type": None,
                          "input_tokens": 57}
        assert tampered["status"] == 400
        assert tampered["error_type"] == "invalid_request_error"
        assert tampered["error"] == SIGNATURE_ERROR
        assert dist.analyze(intact, tampered)["verdict"] == "upstream-verified"

    def test_error_text_is_redacted_before_it_is_clipped(self, dist):
        message = f"upstream rejected key {API_KEY} " + "x" * 300
        client = _client(dist, [_raw(401, {"type": "error", "error": {
            "type": "authentication_error", "message": message}})])
        result = client.replay_thinking(PROBE, dist.build([SIGNED], "ok"), FOLLOW_UP)
        assert result["status"] == 401
        assert result["error_type"] == "authentication_error"
        assert API_KEY not in result["error"] and API_KEY[:8] not in result["error"]
        assert "REDACTED" in result["error"]
        assert len(result["error"]) <= 160

    def test_error_bodies_are_not_accepted_and_raw_bodies_never_copied(self, dist):
        client = _client(dist, [
            _raw(200, {"type": "error", "error": {"type": "overloaded_error",
                                                   "message": "Overloaded"}}),
            {"status": 200, "headers": {}, "body": "<html>ok</html>", "error": None},
            {"status": 502, "headers": {},
             "body": "<html>internal-host-7.corp trace=abc123</html>", "error": None},
        ])
        content = dist.build([SIGNED], "ok")
        error_200 = client.replay_thinking(PROBE, content, FOLLOW_UP)
        assert error_200 == {"status": 200, "error": "Overloaded",
                             "error_type": "overloaded_error", "input_tokens": None}
        assert not replay_accepted(error_200)
        html_200 = client.replay_thinking(PROBE, content, FOLLOW_UP)
        assert html_200["error"] == "HTTP 200 without a message body"
        assert not replay_accepted(html_200)
        html_502 = client.replay_thinking(PROBE, content, FOLLOW_UP)
        assert html_502["status"] == 502 and html_502["error"] == "HTTP 502"
        assert dist.analyze(error_200, None)["verdict"] == "inconclusive"

    def test_transport_failure_and_exception_never_raise(self, dist):
        client = _client(dist, [
            {"status": 0, "headers": {}, "body": "", "error": "curl failed: timeout"},
            RuntimeError("boom"),
        ])
        failed = client.replay_thinking(PROBE, dist.build([SIGNED], "ok"), FOLLOW_UP)
        assert failed["status"] is None and failed["error"] == "curl failed: timeout"
        crashed = client.replay_thinking(PROBE, dist.build([SIGNED], "ok"), FOLLOW_UP)
        assert crashed["status"] is None and crashed["error"] == "RuntimeError: boom"


# ---------------------------------------------------------------------------
# 4b. Step 10 wiring, modular and standalone
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", params=["modular", "standalone"])
def audit_module(request):
    if request.param == "modular":
        return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_signature_roundtrip")
    return _load(REPO_ROOT / "audit.py", "standalone_audit_signature_roundtrip")


def _stream(blocks, text="ok"):
    """StreamSignals that analyze_stream judges clean, with thinking blocks."""
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
    s.input_tokens = 20
    s.output_tokens_samples = [5]
    s.raw_event_count = 6
    s.text = text
    s.stop_reason = "end_turn"
    s.thinking_blocks = [dict(block) for block in blocks]
    return s


class _FakeClient:
    def __init__(self, signals, replays=(), replay_exc=None,
                 detected_format="anthropic"):
        self._signals = signals
        self._replays = list(replays)
        self._replay_exc = replay_exc
        self.detected_format = detected_format
        self.replay_calls = []

    def stream_call(self, *args, **kwargs):
        return self._signals

    def call(self, *args, **kwargs):
        return {"text": "ok", "input_tokens": 20, "output_tokens": 5,
                "raw": {}, "time": 0.1}

    def replay_thinking(self, *args, **kwargs):
        self.replay_calls.append((args, kwargs))
        if self._replay_exc is not None:
            raise self._replay_exc
        return self._replays.pop(0)


def _run(audit_module, client, verify_signature=True):
    report = Reporter()
    if verify_signature:
        result = audit_module.test_stream_integrity(client, report, True)
    else:
        result = audit_module.test_stream_integrity(client, report)
    body = "".join(report.sections)
    assert result == ("clean", False)
    assert [level for level, _ in report.summary] == ["green"]
    return body


HEADING = "### Thinking signature round-trip (opt-in, informational)"
TAMPERED_ROW = "| tampered (1 signature character changed) |"


class TestStep10SignatureWiring:

    def test_flag_defaults_off_and_a_default_run_sends_and_renders_nothing(
            self, audit_module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["audit.py", "--key", "k", "--url", "https://x"])
        assert audit_module.parse_args().verify_signature is False
        monkeypatch.setattr("sys.argv", ["audit.py", "--key", "k", "--url", "https://x",
                                         "--verify-signature"])
        assert audit_module.parse_args().verify_signature is True
        assert ('getattr(args, "verify_signature", False)'
                in inspect.getsource(audit_module._run_audit))
        client = _FakeClient(_stream([SIGNED]), replays=[_ok(), _rejected()])
        body = _run(audit_module, client, verify_signature=False)
        assert client.replay_calls == []
        assert "signature round-trip" not in body

    def test_upstream_verified_is_reported_without_any_flag(self, audit_module):
        client = _FakeClient(_stream([SIGNED]), replays=[_ok(57), _rejected()])
        body = _run(audit_module, client)
        assert HEADING in body
        assert "| intact (signature unchanged) | 200 | — | 57 | accepted |" in body
        assert TAMPERED_ROW + " 400 | invalid_request_error | — | rejected |" in body
        assert "Observed round-trip result: **upstream-verified**" in body
        (intact_args, intact_kwargs), (tampered_args, tampered_kwargs) = client.replay_calls
        # Same max_tokens as the Step 10 stream, so the thinking config matches.
        assert intact_kwargs == tampered_kwargs == {"max_tokens": 100}
        assert intact_args[0] == PROBE and intact_args[2] == FOLLOW_UP
        assert intact_args[1] == [SIGNED, {"type": "text", "text": "ok"}]
        assert len(_diff_positions(SIGNATURE, tampered_args[1][0]["signature"])) == 1

    def test_no_signal_reports_the_token_inference_as_a_note(self, audit_module):
        client = _FakeClient(_stream([SIGNED]), replays=[_ok(57), _ok(40)])
        body = _run(audit_module, client)
        assert "Observed round-trip result: **no-signal**" in body
        assert "- Inference, not part of the verdict" in body
        assert "tool-use turn" in body

    @pytest.mark.parametrize("blocks, text, issue, fmt, reason", [
        ([REDACTED], "ok", None, "anthropic",
         "the stream carried only redacted_thinking blocks"),
        ([SIGNED, {"type": "thinking", "thinking": "x", "signature": ""}], "ok",
         None, "anthropic", "a thinking block carried no signature"),
        ([SIGNED], "ok", "content block 1 started twice", "anthropic",
         "the thinking capture cannot be replayed byte for byte"),
        ([SIGNED], "", None, "anthropic", "the stream carried no reply text"),
        ([SIGNED], "ok", None, "openai",
         "the client format is 'openai' rather than 'anthropic'"),
    ])
    def test_skips_send_nothing_and_are_recorded_inconclusive(
            self, audit_module, blocks, text, issue, fmt, reason):
        signals = _stream(blocks, text=text)
        signals.thinking_capture_issue = issue
        client = _FakeClient(signals, replays=[_ok(), _ok()], detected_format=fmt)
        body = _run(audit_module, client)
        assert client.replay_calls == []
        assert HEADING in body
        assert f"Skipped: {reason}" in body
        assert "Observed round-trip result: **inconclusive**" in body

    def test_rejected_intact_replay_sends_no_tampered_request(self, audit_module):
        client = _FakeClient(_stream([SIGNED]), replays=[
            _rejected(400, "thinking.budget_tokens: too small", "invalid_request_error")])
        body = _run(audit_module, client)
        assert len(client.replay_calls) == 1
        assert TAMPERED_ROW + " — | — | — | not sent |" in body
        assert "Observed round-trip result: **inconclusive**" in body
        assert "- intact replay error (redacted): thinking.budget_tokens" in body

    def test_replay_exception_is_inconclusive_and_never_escapes(self, audit_module):
        client = _FakeClient(_stream([SIGNED]), replay_exc=RuntimeError("boom"))
        body = _run(audit_module, client)
        assert "Observed round-trip result: **inconclusive**" in body
        assert "Signature round-trip failed: RuntimeError: boom" in body
