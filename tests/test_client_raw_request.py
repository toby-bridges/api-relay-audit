"""Tests for the ``curl -i`` output parser in api_relay_audit.client.

The parser is the only piece of raw_request that has deterministic, testable
behavior without hitting a live relay. The httpx path is exercised
end-to-end by the Step 9 integration tests via MagicMock.
"""

from pathlib import Path
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from api_relay_audit.client import APIClient, _parse_curl_i_output


def test_curl_raw_request_keeps_credential_out_of_argv_and_cleans_body_file():
    secret = "sk-raw-request-secret"
    body = b'{"broken": true}'
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["config"] = kwargs["input"]
        captured["body_path"] = Path(cmd[cmd.index("--data-binary") + 1][1:])
        assert captured["body_path"].read_bytes() == body

        class Result:
            returncode = 0
            stdout = b"HTTP/1.1 400 Bad Request\r\n\r\nbad request"
            stderr = b""

        return Result()

    with patch("api_relay_audit.client.subprocess.run", side_effect=fake_run):
        client = APIClient("https://relay.example", secret, "claude-opus-4-6", verbose=False)
        client._use_curl = True
        result = client.raw_request(
            "POST", "/v1/messages", {"x-api-key": secret}, body, timeout=3,
        )

    assert result["status"] == 400
    assert secret not in " ".join(captured["cmd"])
    assert captured["cmd"][captured["cmd"].index("--config") + 1] == "-"
    assert secret.encode("utf-8") in captured["config"]
    assert not captured["body_path"].exists()


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl required")
def test_curl_raw_request_delivers_headers_and_body_to_loopback():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.seen = (
                self.headers.get("x-api-key"),
                self.rfile.read(int(self.headers["Content-Length"])),
            )
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid request")

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = APIClient(
            f"http://127.0.0.1:{server.server_port}", "sk-loopback", "claude-opus-4-6",
            verbose=False,
        )
        client._use_curl = True
        result = client.raw_request(
            "POST", "/v1/messages", {"x-api-key": "sk-loopback"}, b"broken",
            timeout=3,
        )
        assert result["status"] == 400
        assert server.seen == ("sk-loopback", b"broken")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


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
