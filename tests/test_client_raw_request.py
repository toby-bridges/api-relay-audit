"""Tests for the ``curl -i`` output parser in api_relay_audit.client.

The parser is the only piece of raw_request that has deterministic, testable
behavior without hitting a live relay. The httpx path is exercised
end-to-end by the Step 9 integration tests via MagicMock.
"""

import pytest

from api_relay_audit.client import _parse_curl_i_output


class TestParseCurlIOutput:
    def test_http11_simple_body(self):
        output = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 27\r\n"
            "\r\n"
            '{"error":"endpoint missing"}'
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 404
        assert r["headers"]["Content-Type"] == "application/json"
        assert r["headers"]["Content-Length"] == "27"
        assert r["body"] == '{"error":"endpoint missing"}'
        assert r["error"] is None

    def test_http2_status_line(self):
        output = (
            "HTTP/2 422\r\n"
            "content-type: application/json\r\n"
            "\r\n"
            '{"error":"unprocessable"}'
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 422
        assert r["headers"]["content-type"] == "application/json"
        assert r["body"] == '{"error":"unprocessable"}'

    def test_empty_body_with_headers(self):
        output = (
            "HTTP/1.1 204 No Content\r\n"
            "X-Request-Id: abc-123\r\n"
            "\r\n"
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 204
        assert r["headers"]["X-Request-Id"] == "abc-123"
        assert r["body"] == ""

    def test_100_continue_preface_skipped(self):
        """A ``HTTP/1.1 100 Continue`` preface must be skipped so the
        final status code is surfaced."""
        output = (
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "hello"
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 200
        assert r["headers"]["Content-Type"] == "text/plain"
        assert r["body"] == "hello"

    def test_multiline_body_preserved(self):
        output = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Traceback (most recent call last):\n"
            '  File "/app/server.py", line 42, in handler\n'
            "    raise ValueError('boom')\n"
            "ValueError: boom"
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 500
        assert 'File "/app/server.py"' in r["body"]
        assert "ValueError: boom" in r["body"]

    def test_empty_output(self):
        r = _parse_curl_i_output("")
        assert r["status"] == 0
        assert r["error"] == "empty curl output"
        assert r["body"] == ""

    def test_no_separator(self):
        """Malformed output without a header/body separator returns status 0."""
        r = _parse_curl_i_output("HTTP/1.1 200 OK\nno-blank-line-above-body")
        assert r["status"] == 0
        assert r["error"] == "no header/body separator"

    def test_lf_only_line_endings(self):
        """Some curl builds emit LF-only. Parser must normalise."""
        output = (
            "HTTP/1.1 418 I'm a teapot\n"
            "X-Cute: yes\n"
            "\n"
            '{"short":"and stout"}'
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 418
        assert r["headers"]["X-Cute"] == "yes"
        assert r["body"] == '{"short":"and stout"}'

    def test_header_value_with_colon(self):
        """Header values may contain ``:`` (e.g. URLs, timestamps).
        Only the first colon is a separator."""
        output = (
            "HTTP/1.1 200 OK\r\n"
            "Location: https://api.example.com:443/v1/messages\r\n"
            "\r\n"
            "ok"
        )
        r = _parse_curl_i_output(output)
        assert r["status"] == 200
        assert r["headers"]["Location"] == "https://api.example.com:443/v1/messages"
