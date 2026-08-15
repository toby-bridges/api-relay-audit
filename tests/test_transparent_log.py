"""Tests for api_relay_audit.transparent_log (v1.7.7, arXiv §7.3)."""

import hashlib
import json
import os
import tempfile
from datetime import datetime
from unittest.mock import MagicMock, patch

from api_relay_audit.transparent_log import TransparentLogger, redact_error, sha256hex
from api_relay_audit.client import APIClient, _parse_sse_stream
from api_relay_audit.stream_integrity import StreamSignals


# ---------------------------------------------------------------------------
# sha256hex helper
# ---------------------------------------------------------------------------

class TestSha256Hex:
    def test_bytes_input(self):
        expected = hashlib.sha256(b"hello").hexdigest()
        assert sha256hex(b"hello") == expected

    def test_str_input(self):
        expected = hashlib.sha256(b"hello").hexdigest()
        assert sha256hex("hello") == expected

    def test_none_returns_none(self):
        assert sha256hex(None) is None

    def test_empty_bytes(self):
        expected = hashlib.sha256(b"").hexdigest()
        assert sha256hex(b"") == expected

    def test_result_is_64_hex_chars(self):
        result = sha256hex("test data")
        assert len(result) == 64
        int(result, 16)  # must parse as hex


# ---------------------------------------------------------------------------
# TransparentLogger
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# redact_error (HIGH fix: no response body in error field)
# ---------------------------------------------------------------------------

class TestRedactError:
    def test_none_returns_none(self):
        assert redact_error(None) is None

    def test_http_error_strips_body(self):
        """'HTTP 400: {"error":"sk-real-key"}' → 'HTTP 400'"""
        assert redact_error('HTTP 400: {"error":"sk-real-secret"}') == "HTTP 400"

    def test_http_error_no_colon(self):
        assert redact_error("HTTP 500") == "HTTP 500"

    def test_curl_error_strips_stderr(self):
        assert redact_error("curl failed: SSL handshake error") == "curl failed"

    def test_exception_passthrough(self):
        assert redact_error("connection refused") == "connection refused"

    def test_timeout_passthrough(self):
        assert redact_error("curl stream timeout") == "curl stream timeout"

    def test_api_key_never_survives(self):
        """The exact attack: relay echoes the API key in a 401 error."""
        raw = "HTTP 401: {\"error\":\"invalid key sk-ant-abc123\"}"
        assert "sk-ant" not in redact_error(raw)


# ---------------------------------------------------------------------------
# TransparentLogger
# ---------------------------------------------------------------------------

class TestTransparentLogger:
    def test_creates_file(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        logger.close()
        assert os.path.exists(path)

    def test_appends_jsonl_lines(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        logger.log_entry({"a": 1})
        logger.log_entry({"b": 2})
        logger.close()

        lines = open(path).readlines()
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}

    def test_each_line_is_valid_json(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        for i in range(5):
            logger.log_entry({"index": i, "nested": {"key": "val"}})
        logger.close()

        for line in open(path):
            json.loads(line)  # must not raise

    def test_append_mode(self, tmp_path):
        """Opening the same file twice appends rather than overwrites."""
        path = str(tmp_path / "audit.jsonl")
        logger1 = TransparentLogger(path)
        logger1.log_entry({"first": True})
        logger1.close()

        logger2 = TransparentLogger(path)
        logger2.log_entry({"second": True})
        logger2.close()

        lines = open(path).readlines()
        assert len(lines) == 2

    def test_io_error_does_not_raise(self, tmp_path):
        """Writing to a closed file does not raise — prints to stderr."""
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        logger.close()
        # After close, writing should not raise
        logger.log_entry({"after": "close"})  # must not raise

    def test_close_is_idempotent(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        logger.close()
        logger.close()  # must not raise

    def test_creates_parent_directories(self, tmp_path):
        """MEDIUM fix: nested path like /a/b/c/audit.jsonl must not crash."""
        path = str(tmp_path / "deep" / "nested" / "dir" / "audit.jsonl")
        logger = TransparentLogger(path)
        logger.log_entry({"test": True})
        logger.close()
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# APIClient transparent-log integration
# ---------------------------------------------------------------------------

class TestClientLogIntegration:
    def _make_client(self, tmp_path):
        client = APIClient("https://relay.example.com/v1", "sk-test-key",
                           "claude-test", timeout=10, verbose=False)
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        client.set_transparent_logger(logger)
        return client, logger, path

    def test_no_log_when_logger_is_none(self, tmp_path):
        """Client without logger creates no file."""
        path = str(tmp_path / "nolog.jsonl")
        client = APIClient("https://relay.example.com/v1", "sk-test",
                           "claude-test", verbose=False)
        # Simulate a call that would log if logger were attached
        assert client._transparent_logger is None
        client._log_transparent("call", "https://x", "POST", b"body",
                                b"resp", 200, {}, 1.0)
        assert not os.path.exists(path)

    def test_call_logs_entry(self, tmp_path):
        """A mocked call() produces a JSONL entry with required fields."""
        client, logger, path = self._make_client(tmp_path)
        # Mock _call_with_detection to return a canned response
        client._format = "anthropic"
        with patch.object(client, "_call_with_detection") as mock:
            mock.return_value = {
                "text": "hello",
                "input_tokens": 10,
                "output_tokens": 5,
                "raw": {"id": "msg_123"},
            }
            client.call([{"role": "user", "content": "hi"}])
        logger.close()

        lines = open(path).readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["method"] == "call"
        assert entry["http_method"] == "POST"
        assert entry["status_code"] == 200
        assert "relay.example.com" in entry["url"]
        assert entry["request_body_sha256"] is not None
        assert entry["response_body_sha256"] is not None
        assert len(entry["request_body_sha256"]) == 64
        assert len(entry["response_body_sha256"]) == 64
        assert entry["error"] is None
        assert entry["tls_verification_disabled"] is False

    def test_call_error_logs_entry(self, tmp_path):
        """A failed call() still logs with error field set."""
        client, logger, path = self._make_client(tmp_path)
        client._format = "anthropic"
        with patch.object(client, "_call_with_detection") as mock:
            mock.side_effect = RuntimeError("connection refused")
            client.call([{"role": "user", "content": "hi"}])
        logger.close()

        lines = open(path).readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["status_code"] == 0
        assert "connection refused" in entry["error"]

    def test_raw_request_logs_entry(self, tmp_path):
        """raw_request() logs with status, headers, and body hash."""
        client, logger, path = self._make_client(tmp_path)
        with patch("httpx.request") as mock:
            mock_resp = MagicMock()
            mock_resp.status_code = 400
            mock_resp.headers = {"server": "nginx"}
            mock_resp.text = '{"error":"bad request"}'
            mock.return_value = mock_resp
            client.raw_request("POST", "/v1/messages", {}, b'{}')
        logger.close()

        lines = open(path).readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["method"] == "raw_request"
        assert entry["status_code"] == 400
        assert entry["response_headers"]["server"] == "nginx"

    def test_no_api_key_in_log(self, tmp_path):
        """The API key must never appear in any logged entry."""
        client, logger, path = self._make_client(tmp_path)
        client._format = "anthropic"
        with patch.object(client, "_call_with_detection") as mock:
            mock.return_value = {
                "text": "hello", "input_tokens": 10,
                "output_tokens": 5, "raw": {},
            }
            client.call([{"role": "user", "content": "hi"}])
        logger.close()

        full_text = open(path).read()
        assert "sk-test-key" not in full_text

    def test_no_api_key_in_error_path(self, tmp_path):
        """HIGH fix: even when the relay echoes the API key in an error
        response, the key must NOT appear in the JSONL error field."""
        client, logger, path = self._make_client(tmp_path)
        client._format = "anthropic"
        with patch.object(client, "_call_with_detection") as mock:
            mock.return_value = {
                "error": 'HTTP 401: {"detail":"invalid key sk-test-key"}',
            }
            client.call([{"role": "user", "content": "hi"}])
        logger.close()

        full_text = open(path).read()
        assert "sk-test-key" not in full_text

    def test_timestamp_is_iso8601(self, tmp_path):
        client, logger, path = self._make_client(tmp_path)
        client._format = "anthropic"
        with patch.object(client, "_call_with_detection") as mock:
            mock.return_value = {
                "text": "ok", "input_tokens": 1,
                "output_tokens": 1, "raw": {},
            }
            client.call([{"role": "user", "content": "test"}])
        logger.close()

        entry = json.loads(open(path).readline())
        # Must parse as ISO 8601
        datetime.fromisoformat(entry["timestamp"])

    def test_required_fields_present(self, tmp_path):
        """Every entry has the full 12-field schema."""
        client, logger, path = self._make_client(tmp_path)
        client._format = "anthropic"
        with patch.object(client, "_call_with_detection") as mock:
            mock.return_value = {
                "text": "ok", "input_tokens": 1,
                "output_tokens": 1, "raw": {},
            }
            client.call([{"role": "user", "content": "test"}])
        logger.close()

        entry = json.loads(open(path).readline())
        required = {
            "timestamp", "method", "url", "http_method",
            "request_body_sha256", "response_body_sha256",
            "status_code", "response_headers", "tls_version",
            "tls_cipher", "tls_verification_disabled", "elapsed_seconds",
            "transport", "error",
        }
        assert required.issubset(entry.keys())

    def test_actual_insecure_curl_request_is_recorded(self, tmp_path):
        client = APIClient(
            "https://relay.example.com/v1", "sk-test-key", "claude-test",
            timeout=10, verbose=False, allow_insecure_tls=True,
        )
        client._use_curl = True
        path = str(tmp_path / "audit.jsonl")
        logger = TransparentLogger(path)
        client.set_transparent_logger(logger)
        with patch("api_relay_audit.client.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"HTTP/1.1 400 Bad Request\r\n\r\nbad",
                stderr=b"",
            )
            client.raw_request("POST", "/v1/messages", {}, b"{}")
        logger.close()

        entry = json.loads(open(path).readline())
        assert entry["transport"] == "curl"
        assert entry["tls_verification_disabled"] is True


# ---------------------------------------------------------------------------
# Stream hashing in _parse_sse_stream
# ---------------------------------------------------------------------------

class TestStreamHashing:
    def test_hasher_captures_all_bytes(self):
        """The hasher fed to _parse_sse_stream receives every raw byte."""
        chunks = [
            b'data: {"type":"message_start","message":{"model":"claude"}}\n',
            b'data: {"type":"message_stop"}\n',
        ]
        signals = StreamSignals()
        hasher = hashlib.sha256()
        _parse_sse_stream(iter(chunks), signals, hasher)

        expected = hashlib.sha256(b"".join(chunks)).hexdigest()
        assert hasher.hexdigest() == expected

    def test_hasher_none_is_noop(self):
        """Passing hasher=None does not break parsing."""
        chunks = [b'data: {"type":"message_stop"}\n']
        signals = StreamSignals()
        _parse_sse_stream(iter(chunks), signals, None)
        assert signals.has_message_stop

    def test_hasher_with_string_chunks(self):
        """String chunks (non-bytes) are also hashed correctly."""
        chunks = ['data: {"type":"message_stop"}\n']
        signals = StreamSignals()
        hasher = hashlib.sha256()
        _parse_sse_stream(iter(chunks), signals, hasher)

        expected = hashlib.sha256(chunks[0].encode("utf-8", errors="ignore")).hexdigest()
        assert hasher.hexdigest() == expected
