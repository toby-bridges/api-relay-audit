"""Tests for streaming client support (Sub-PR 1 of Step 10 Stream Integrity).

Covers three layers:

1. ``_populate_stream_signals()`` — the event dispatcher (unit tests
   with plain dicts, no network).
2. ``_parse_sse_stream()`` — the byte-iterator SSE parser (unit tests
   with in-memory byte lists, no network).
3. ``APIClient.stream_call()`` — the public method that glues
   everything together (integration tests with mocked httpx).
"""

import json
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from api_relay_audit.client import (
    APIClient,
    _parse_sse_stream,
    _populate_stream_signals,
)
from api_relay_audit.stream_integrity import KNOWN_SSE_EVENT_TYPES, StreamSignals


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sse_bytes(*events):
    """Build a single bytes chunk containing N SSE events.

    Each arg is a dict that gets JSON-serialised into a ``data: <json>\\n\\n``
    block. Trailing ``data: [DONE]\\n\\n`` is added automatically so the
    parser knows to stop.
    """
    out = []
    for event in events:
        out.append(b"data: " + json.dumps(event).encode("utf-8") + b"\n\n")
    out.append(b"data: [DONE]\n\n")
    return b"".join(out)


def _make_mock_response(content_bytes, status_code=200):
    """Build a fake httpx streaming response object that yields a single
    bytes chunk of SSE data, then EOF."""
    response = MagicMock()
    response.status_code = status_code
    response.iter_bytes = MagicMock(return_value=iter([content_bytes]))
    response.read = MagicMock(return_value=content_bytes)
    return response


def _stream_cm(response):
    """Wrap a response in a pretend context manager for client.stream()."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=response)
    cm.__exit__ = MagicMock(return_value=None)
    return cm


class _StreamingSSEHandler(BaseHTTPRequestHandler):
    """Tiny loopback SSE server used to exercise the real curl fallback."""

    protocol_version = "HTTP/1.0"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.server.request_body = self.rfile.read(length)
        self.server.request_path = self.path
        self.server.request_headers = dict(self.headers)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        for chunk in self.server.response_chunks:
            self.wfile.write(chunk)
            self.wfile.flush()
            time.sleep(self.server.chunk_delay)
        self.close_connection = True

    def log_message(self, *_args, **_kwargs):
        pass


class _StreamingSSEServer(HTTPServer):
    allow_reuse_address = True


class _LoopbackSSEServer:
    """Context manager for a one-shot local SSE server."""

    def __init__(self, response_chunks, chunk_delay=0.02):
        self.response_chunks = response_chunks
        self.chunk_delay = chunk_delay
        self.httpd = None
        self.thread = None

    def __enter__(self):
        self.httpd = _StreamingSSEServer(("127.0.0.1", 0), _StreamingSSEHandler)
        self.httpd.response_chunks = self.response_chunks
        self.httpd.chunk_delay = self.chunk_delay
        self.httpd.request_body = b""
        self.httpd.request_path = None
        self.httpd.request_headers = {}
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=1)

    @property
    def base_url(self):
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"


# ---------------------------------------------------------------------------
# _populate_stream_signals (unit tests)
# ---------------------------------------------------------------------------


class TestPopulateStreamSignals:

    def test_empty_event_increments_counter_only(self):
        signals = StreamSignals()
        _populate_stream_signals({}, signals)
        assert signals.raw_event_count == 1
        assert signals.event_types == []
        assert signals.has_message_start is False

    def test_message_start_captures_model_and_input_tokens(self):
        signals = StreamSignals()
        event = {
            "type": "message_start",
            "message": {
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 42},
            },
        }
        _populate_stream_signals(event, signals)
        assert signals.has_message_start is True
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.event_types == ["message_start"]

    def test_content_block_start_thinking(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "content_block_start", "content_block": {"type": "thinking"}},
            signals,
        )
        assert signals.has_content_block_start is True
        assert signals.thinking_start_seen is True
        assert "thinking" in signals.content_block_types

    def test_content_block_start_text_does_not_set_thinking_flag(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "content_block_start", "content_block": {"type": "text"}},
            signals,
        )
        assert signals.has_content_block_start is True
        assert signals.thinking_start_seen is False
        assert "text" in signals.content_block_types

    def test_content_block_delta_text_delta(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": "hello"},
            },
            signals,
        )
        assert signals.has_content_block_delta is True
        assert signals.has_text_delta is True
        assert "text_delta" in signals.delta_types

    def test_content_block_delta_thinking_delta(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "thinking_delta", "thinking": "ponder"},
            },
            signals,
        )
        assert signals.thinking_delta_seen is True

    def test_content_block_delta_empty_signature_counted(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "signature_delta", "signature": ""},
            },
            signals,
        )
        assert signals.empty_signature_delta_count == 1

    def test_content_block_delta_whitespace_signature_counted(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "signature_delta", "signature": "   \t\n"},
            },
            signals,
        )
        assert signals.empty_signature_delta_count == 1

    def test_content_block_delta_real_signature_not_counted(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "signature_delta", "signature": "abc123="},
            },
            signals,
        )
        assert signals.empty_signature_delta_count == 0

    def test_message_delta_populates_usage_samples(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "message_delta",
                "usage": {"input_tokens": 42, "output_tokens": 10},
            },
            signals,
        )
        assert signals.has_message_delta is True
        assert signals.message_delta_input_tokens_samples == [42]
        assert signals.output_tokens_samples == [10]

    def test_message_stop_flag(self):
        signals = StreamSignals()
        _populate_stream_signals({"type": "message_stop"}, signals)
        assert signals.has_message_stop is True

    def test_ping_event_tracked_in_event_types(self):
        signals = StreamSignals()
        _populate_stream_signals({"type": "ping"}, signals)
        assert "ping" in signals.event_types
        assert signals.raw_event_count == 1

    def test_unknown_event_type_still_tracked(self):
        """Unknown event types must appear in ``event_types`` so
        analyze_stream (Sub-PR 2) can detect them."""
        signals = StreamSignals()
        _populate_stream_signals({"type": "custom_relay_event"}, signals)
        assert "custom_relay_event" in signals.event_types
        assert signals.raw_event_count == 1

    def test_malformed_message_field_does_not_raise(self):
        """Non-dict ``message`` field in a message_start event must be
        silently ignored, not raise."""
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "message_start", "message": "oops not a dict"},
            signals,
        )
        assert signals.has_message_start is True
        assert signals.message_start_model is None
        assert signals.input_tokens is None


# ---------------------------------------------------------------------------
# _parse_sse_stream (unit tests)
# ---------------------------------------------------------------------------


class TestParseSseStream:

    def test_clean_single_chunk_all_events(self):
        signals = StreamSignals()
        chunk = sse_bytes(
            {"type": "message_start", "message": {"model": "claude-opus-4-6",
                                                   "usage": {"input_tokens": 42}}},
            {"type": "content_block_start", "content_block": {"type": "text"}},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hi"}},
            {"type": "message_delta", "usage": {"input_tokens": 42, "output_tokens": 5}},
            {"type": "message_stop"},
        )
        _parse_sse_stream(iter([chunk]), signals)
        assert signals.has_message_start
        assert signals.has_message_stop
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.output_tokens_samples == [5]
        assert signals.raw_event_count == 5

    def test_multi_chunk_partial_events_buffered_correctly(self):
        """An event split across multiple byte chunks must still parse."""
        signals = StreamSignals()
        full = sse_bytes({"type": "message_start", "message": {"model": "x"}})
        # Split at an arbitrary mid-point of the JSON
        half = len(full) // 2
        chunks = [full[:half], full[half:]]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start
        assert signals.message_start_model == "x"

    def test_done_sentinel_stops_parse(self):
        """[DONE] sentinel must short-circuit the parse — events after
        it must NOT be counted."""
        signals = StreamSignals()
        chunks = [
            b'data: {"type":"message_start","message":{"model":"x"}}\n\n',
            b"data: [DONE]\n\n",
            b'data: {"type":"message_stop"}\n\n',
        ]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start is True
        assert signals.has_message_stop is False
        assert signals.raw_event_count == 1

    def test_malformed_json_line_skipped_silently(self):
        """A broken JSON line must not abort the parse."""
        signals = StreamSignals()
        chunks = [
            b'data: {not json\n\n',
            b'data: {"type":"message_start","message":{"model":"x"}}\n\n',
            b'data: [DONE]\n\n',
        ]
        _parse_sse_stream(iter(chunks), signals)
        # Malformed line is silently skipped, real event is parsed
        assert signals.has_message_start is True
        assert signals.raw_event_count == 1

    def test_non_data_lines_ignored(self):
        """Lines that don't start with ``data: `` must be ignored (e.g.
        ``event: message_start`` lines are common in some SSE implementations)."""
        signals = StreamSignals()
        chunks = [
            b"event: message_start\n",
            b'data: {"type":"message_start","message":{"model":"x"}}\n\n',
            b"id: 12345\n",
            b"data: [DONE]\n\n",
        ]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start is True

    def test_empty_byte_stream_produces_empty_signals(self):
        signals = StreamSignals()
        _parse_sse_stream(iter([]), signals)
        assert signals.raw_event_count == 0
        assert signals.has_message_start is False
        assert signals.transport_error is None  # parser doesn't set this

    def test_multiple_events_same_chunk(self):
        """A single byte chunk containing multiple events must parse all."""
        signals = StreamSignals()
        chunk = (
            b'data: {"type":"ping"}\n\n'
            b'data: {"type":"message_start","message":{}}\n\n'
            b'data: {"type":"message_stop"}\n\n'
            b"data: [DONE]\n\n"
        )
        _parse_sse_stream(iter([chunk]), signals)
        assert signals.raw_event_count == 3
        assert signals.event_types == ["ping", "message_start", "message_stop"]

    # ----- v1.7.1 Codex fixes (Round 5 LOW finding) -----

    def test_parse_sse_stream_flushes_final_line_without_trailing_newline(self):
        """v1.7.1 fix: streams that end without a trailing newline
        (broken or truncated relay) must still have their final line
        parsed. Previously the last line stayed in the buffer forever."""
        signals = StreamSignals()
        chunks = [
            b'data: {"type":"message_start","message":{"model":"claude"}}\n\n',
            b'data: {"type":"message_stop"}',  # NO trailing newline
        ]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start is True
        assert signals.has_message_stop is True, (
            "Final line without trailing newline was dropped — v1.7.1 regression"
        )
        assert signals.raw_event_count == 2

    def test_parse_sse_stream_flushed_line_can_be_done_sentinel(self):
        """v1.7.1 fix: [DONE] as the flushed final line must NOT be
        parsed as an event (it's a sentinel, not a JSON payload)."""
        signals = StreamSignals()
        chunks = [
            b'data: {"type":"message_start","message":{"model":"claude"}}\n\n',
            b"data: [DONE]",  # final line, no trailing newline
        ]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start is True
        # [DONE] must not have been counted as an event
        assert signals.raw_event_count == 1

    def test_parse_sse_stream_buffer_cap_sets_transport_error(self):
        """v1.7.1 fix: an adversarial chunk > MAX_STREAM_BUFFER_BYTES
        with no newline must trigger a transport error and bail,
        preventing unbounded memory growth."""
        from api_relay_audit.client import MAX_STREAM_BUFFER_BYTES
        signals = StreamSignals()
        # Single chunk larger than the cap, no newline → no drain
        huge_chunk = b"A" * (MAX_STREAM_BUFFER_BYTES + 1024)
        _parse_sse_stream(iter([huge_chunk]), signals)
        assert signals.transport_error is not None
        assert "buffer exceeded" in signals.transport_error.lower()
        # No events should have been parsed from the garbage
        assert signals.raw_event_count == 0

    def test_parse_sse_stream_normal_sized_content_not_capped(self):
        """v1.7.1 regression guard: a 100 KB thinking block (well below
        the 1 MB cap) must parse normally."""
        signals = StreamSignals()
        large_text = "x" * 100_000  # 100 KB
        event = {
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": large_text},
        }
        chunk = b"data: " + json.dumps(event).encode("utf-8") + b"\n\n"
        _parse_sse_stream(iter([chunk]), signals)
        assert signals.transport_error is None
        assert signals.has_content_block_delta is True
        assert signals.has_text_delta is True


class TestCurlNonzeroExitHandling:
    """v1.7.1 Codex fix for Round 5 MEDIUM finding: any non-zero curl
    exit must set transport_error, even if partial events were parsed
    before the stream failed. The previous code guarded this with
    ``and signals.raw_event_count == 0`` which silently swallowed
    mid-stream failures and judged truncated streams as clean."""

    def test_curl_nonzero_exit_after_partial_events_sets_transport_error(self):
        """Mid-stream curl failure: some events parsed, then non-zero
        exit. transport_error must be set so analyze_stream returns
        inconclusive instead of the clean/anomaly verdict on partial data."""
        from io import BytesIO

        partial_sse = (
            b'data: {"type":"message_start","message":{"model":"claude-opus-4-6"}}\n\n'
            b'data: {"type":"content_block_start","content_block":{"type":"text"}}\n\n'
        )

        def mock_popen_factory(*args, **kwargs):
            proc = MagicMock()
            proc.stdin = MagicMock()
            proc.stdout = BytesIO(partial_sse)
            proc.stderr = BytesIO(
                b"curl: (18) transfer closed with outstanding read data remaining"
            )
            proc.wait = MagicMock(return_value=None)
            proc.returncode = 1  # non-zero = curl failed
            return proc

        with patch("api_relay_audit.client.subprocess.Popen",
                   side_effect=mock_popen_factory):
            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client._use_curl = True  # force curl path
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        # Partial events WERE parsed from the partial stream
        assert signals.has_message_start is True
        assert signals.has_content_block_start is True
        # BUT transport_error MUST be set because curl exited non-zero
        assert signals.transport_error is not None, (
            "v1.7.1 Codex fix regression: mid-stream curl failure was "
            "silently swallowed"
        )
        assert "curl failed" in signals.transport_error

    def test_curl_zero_exit_clean_stream_no_transport_error(self):
        """Regression guard: a clean curl exit (returncode 0) must NOT
        set transport_error, even for streams without any events."""
        from io import BytesIO

        def mock_popen_factory(*args, **kwargs):
            proc = MagicMock()
            proc.stdin = MagicMock()
            proc.stdout = BytesIO(
                b'data: {"type":"message_start","message":{"model":"claude"}}\n\n'
                b"data: [DONE]\n\n"
            )
            proc.stderr = BytesIO(b"")
            proc.wait = MagicMock(return_value=None)
            proc.returncode = 0  # success
            return proc

        with patch("api_relay_audit.client.subprocess.Popen",
                   side_effect=mock_popen_factory):
            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client._use_curl = True
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is None
        assert signals.has_message_start is True

    def test_curl_http_error_status_sets_transport_error_on_non_sse_body(self):
        from io import BytesIO

        def mock_popen_factory(*args, **kwargs):
            proc = MagicMock()
            proc.stdin = MagicMock()
            proc.stdout = BytesIO(
                b'{"error":"RateLimitReached","message":"too many requests"}\n'
                b"__CODEX_HTTP_STATUS__:429\n"
            )
            proc.stderr = BytesIO(b"")
            proc.wait = MagicMock(return_value=None)
            proc.returncode = 0
            return proc

        with patch("api_relay_audit.client.subprocess.Popen",
                   side_effect=mock_popen_factory):
            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client._use_curl = True
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.raw_event_count == 0
        assert signals.transport_error is not None
        assert "HTTP 429" in signals.transport_error
        assert "RateLimitReached" in signals.transport_error

    def test_curl_stream_reads_stdout_incrementally_via_readline(self):
        """Regression for the v1.8.2 curl fallback fix: the stream reader
        must consume stdout line-by-line, not via ``read(4096)``.

        Old behavior buffered short SSE frames until curl exited, so
        valid small streams on self-signed relays looked empty or timed
        out. This test forces ``read()`` to explode so only the
        line-buffered path can pass.
        """

        class _LineBufferedStdout:
            def __init__(self, lines):
                self._lines = iter(lines)

            def readline(self):
                try:
                    return next(self._lines)
                except StopIteration:
                    return b""

            def read(self, *_args, **_kwargs):
                raise AssertionError("curl SSE reader must not use read(4096)")

        def mock_popen_factory(*args, **kwargs):
            proc = MagicMock()
            proc.stdin = MagicMock()
            proc.stdout = _LineBufferedStdout([
                b'data: {"type":"message_start","message":{"model":"claude-opus-4-6"}}\n',
                b"\n",
                b"data: [DONE]\n",
                b"\n",
            ])
            proc.stderr = BytesIO(b"")
            proc.wait = MagicMock(return_value=None)
            proc.returncode = 0
            return proc

        with patch("api_relay_audit.client.subprocess.Popen",
                   side_effect=mock_popen_factory):
            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client._use_curl = True
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is None
        assert signals.has_message_start is True
        assert signals.raw_event_count == 1

    def test_curl_stream_bypasses_proxy_for_loopback(self):
        captured_cmds = []

        def mock_popen_factory(cmd, *args, **kwargs):
            captured_cmds.append(cmd)
            proc = MagicMock()
            proc.stdin = MagicMock()
            proc.stdout = BytesIO(
                b'data: {"type":"message_start","message":{"model":"claude-opus-4-6"}}\n'
                b"\n"
                b"data: [DONE]\n\n"
            )
            proc.stderr = BytesIO(b"")
            proc.wait = MagicMock(return_value=None)
            proc.returncode = 0
            return proc

        with patch("api_relay_audit.client.subprocess.Popen",
                   side_effect=mock_popen_factory):
            client = APIClient(
                "http://localhost:8765/v1", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client._use_curl = True
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is None
        cmd = captured_cmds[0]
        assert "--noproxy" in cmd
        assert cmd[cmd.index("--noproxy") + 1] == "localhost,127.0.0.1,::1"


# ---------------------------------------------------------------------------
# APIClient.stream_call (integration tests with mocked httpx)
# ---------------------------------------------------------------------------


class TestStreamCallHttpx:

    def test_clean_stream_populates_signals_via_httpx(self):
        sse_payload = sse_bytes(
            {"type": "message_start", "message": {"model": "claude-opus-4-6",
                                                   "usage": {"input_tokens": 42}}},
            {"type": "content_block_start", "content_block": {"type": "text"}},
            {"type": "content_block_delta",
             "delta": {"type": "text_delta", "text": "hi"}},
            {"type": "message_delta",
             "usage": {"input_tokens": 42, "output_tokens": 5}},
            {"type": "message_stop"},
        )

        mock_response = _make_mock_response(sse_payload)
        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None
            client_instance.stream.return_value = _stream_cm(mock_response)

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}], max_tokens=100,
            )

        assert signals.has_message_start is True
        assert signals.has_message_stop is True
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.output_tokens_samples == [5]
        assert signals.transport_error is None
        assert signals.total_duration_seconds is not None
        assert signals.total_duration_seconds >= 0

    def test_non_200_response_sets_transport_error(self):
        mock_response = _make_mock_response(b'{"error":"bad"}', status_code=422)
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value = MagicMock(
                stream=MagicMock(return_value=_stream_cm(mock_response))
            )
            mock_client_cls.return_value.__exit__.return_value = None

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is not None
        assert "422" in signals.transport_error
        assert signals.raw_event_count == 0

    def test_httpx_exception_sets_transport_error(self):
        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None

            def raising_stream(*args, **kwargs):
                raise RuntimeError("simulated connection failure")

            client_instance.stream.side_effect = raising_stream

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is not None
        assert "simulated connection failure" in signals.transport_error

    def test_stream_call_request_body_contains_stream_and_thinking(self):
        """Regression: the streaming body must have ``stream: true`` and
        ``thinking`` enabled by default so Step 10 can detect thinking
        block anomalies."""
        captured = {}

        def capture_stream(method, url, headers, json):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return _stream_cm(_make_mock_response(sse_bytes()))

        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None
            client_instance.stream.side_effect = capture_stream

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client.stream_call([{"role": "user", "content": "hi"}], max_tokens=100)

        assert captured["method"] == "POST"
        assert captured["url"].endswith("/v1/messages")
        assert captured["headers"]["x-api-key"] == "sk-test"
        assert captured["headers"]["anthropic-version"] == "2023-06-01"
        assert captured["json"]["stream"] is True
        assert captured["json"]["thinking"] == {"type": "enabled", "budget_tokens": 99}

    def test_with_thinking_false_omits_thinking_field(self):
        captured = {}

        def capture_stream(method, url, headers, json):
            captured["json"] = json
            return _stream_cm(_make_mock_response(sse_bytes()))

        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None
            client_instance.stream.side_effect = capture_stream

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client.stream_call(
                [{"role": "user", "content": "hi"}], with_thinking=False,
            )

        assert "thinking" not in captured["json"]


class TestStreamCallCurlIntegration:

    @pytest.mark.skipif(shutil.which("curl") is None, reason="curl required")
    def test_real_curl_handles_short_sse_frames_from_loopback_server(self):
        """Exercise the actual ``curl -N --no-buffer`` fallback against a
        local SSE server that flushes short frames one at a time.

        This is intentionally more end-to-end than the mocked curl tests:
        it validates the real subprocess path, loopback HTTP transport,
        stdin request piping, and SSE parsing on small flushed frames.
        """
        response_chunks = [
            b'data: {"type":"message_start","message":{"model":"claude-opus-4-6","usage":{"input_tokens":42}}}\n',
            b"\n",
            b'data: {"type":"content_block_start","content_block":{"type":"text"}}\n',
            b"\n",
            b'data: {"type":"message_delta","usage":{"input_tokens":42,"output_tokens":7}}\n',
            b"\n",
            b'data: {"type":"message_stop"}\n',
            b"\n",
            b"data: [DONE]\n",
            b"\n",
        ]

        with _LoopbackSSEServer(response_chunks) as server:
            client = APIClient(
                server.base_url, "sk-test", "claude-opus-4-6", verbose=False,
            )
            client._use_curl = True
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
                max_tokens=100,
                timeout=3,
            )

        assert signals.transport_error is None
        assert signals.has_message_start is True
        assert signals.has_content_block_start is True
        assert signals.has_message_stop is True
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.output_tokens_samples == [7]
        assert signals.raw_event_count == 4

        assert server.httpd.request_path == "/v1/messages"
        request_body = json.loads(server.httpd.request_body.decode("utf-8"))
        assert request_body["stream"] is True
        assert request_body["max_tokens"] == 100
        assert request_body["thinking"] == {"type": "enabled", "budget_tokens": 99}


# ---------------------------------------------------------------------------
# KNOWN_SSE_EVENT_TYPES invariants
# ---------------------------------------------------------------------------


class TestKnownSseEventTypes:

    def test_exactly_seven_known_events(self):
        """Matches hvoy.ai claude_detector.py:369-377 verified 2026-04-11."""
        assert len(KNOWN_SSE_EVENT_TYPES) == 7

    def test_contains_ping_and_block_stop(self):
        """The v1 WebFetch summary of hvoy.ai missed ``ping`` and
        ``content_block_stop``; this regression guard asserts both are
        present because our source read verified they belong."""
        assert "ping" in KNOWN_SSE_EVENT_TYPES
        assert "content_block_stop" in KNOWN_SSE_EVENT_TYPES

    def test_all_event_types_are_str(self):
        for event_type in KNOWN_SSE_EVENT_TYPES:
            assert isinstance(event_type, str)
            assert event_type  # non-empty
