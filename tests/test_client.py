"""Tests for api_relay_audit.client.APIClient."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from api_relay_audit.client import APIClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return APIClient(
        base_url="https://relay.example.com/v1",
        api_key="sk-test-key",
        model="claude-3-haiku",
        timeout=30,
        verbose=False,
    )


@pytest.fixture
def verbose_client():
    return APIClient(
        base_url="https://relay.example.com/v1",
        api_key="sk-test-key",
        model="claude-3-haiku",
        timeout=30,
        verbose=True,
    )


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_base_url_trailing_slash_stripped(self):
        c = APIClient("https://example.com/v1/", "key", "model")
        assert c.base_url == "https://example.com/v1"

    def test_defaults(self, client):
        assert client._format is None
        assert client._use_curl is False
        assert client.timeout == 30
        assert client.verbose is False

    def test_detected_format_initially_none(self, client):
        assert client.detected_format is None


# ---------------------------------------------------------------------------
# _call_anthropic
# ---------------------------------------------------------------------------

class TestCallAnthropic:
    def _anthropic_response(self, text="Hello", input_tokens=10, output_tokens=5):
        return {
            "content": [{"text": text}],
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        }

    @patch("api_relay_audit.client.httpx.post")
    def test_success(self, mock_post, client):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = self._anthropic_response("Hi there")
        mock_post.return_value = resp

        result = client._call_anthropic([{"role": "user", "content": "Hi"}])

        assert result["text"] == "Hi there"
        assert result["input_tokens"] == 10
        assert result["output_tokens"] == 5
        assert "raw" in result

    @patch("api_relay_audit.client.httpx.post")
    def test_url_construction_strips_v1(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._anthropic_response()
        mock_post.return_value = resp

        client._call_anthropic([{"role": "user", "content": "x"}])
        called_url = mock_post.call_args[0][0]
        assert called_url == "https://relay.example.com/v1/messages"
        assert "/v1/v1/" not in called_url

    @patch("api_relay_audit.client.httpx.post")
    def test_system_message_included(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._anthropic_response()
        mock_post.return_value = resp

        client._call_anthropic([{"role": "user", "content": "x"}], system="Be helpful")
        body = mock_post.call_args[1]["json"]
        assert body["system"] == "Be helpful"

    @patch("api_relay_audit.client.httpx.post")
    def test_system_message_omitted_when_none(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._anthropic_response()
        mock_post.return_value = resp

        client._call_anthropic([{"role": "user", "content": "x"}])
        body = mock_post.call_args[1]["json"]
        assert "system" not in body

    @patch("api_relay_audit.client.httpx.post")
    def test_http_error(self, mock_post, client):
        resp = MagicMock(status_code=500)
        resp.text = "Internal Server Error"
        mock_post.return_value = resp

        result = client._call_anthropic([{"role": "user", "content": "x"}])
        assert "error" in result

    @patch("api_relay_audit.client.httpx.post")
    def test_empty_content(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"content": [{}], "usage": {}}
        mock_post.return_value = resp

        result = client._call_anthropic([{"role": "user", "content": "x"}])
        assert result["text"] == ""
        assert result["input_tokens"] == 0


# ---------------------------------------------------------------------------
# _call_openai
# ---------------------------------------------------------------------------

class TestCallOpenAI:
    def _openai_response(self, text="Hello", prompt_tokens=10, completion_tokens=5):
        return {
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        }

    @patch("api_relay_audit.client.httpx.post")
    def test_success(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._openai_response("World")
        mock_post.return_value = resp

        result = client._call_openai([{"role": "user", "content": "Hi"}])

        assert result["text"] == "World"
        assert result["input_tokens"] == 10
        assert result["output_tokens"] == 5

    @patch("api_relay_audit.client.httpx.post")
    def test_url_appends_v1(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._openai_response()
        mock_post.return_value = resp

        # base_url already ends with /v1
        client._call_openai([{"role": "user", "content": "x"}])
        called_url = mock_post.call_args[0][0]
        assert called_url == "https://relay.example.com/v1/chat/completions"

    @patch("api_relay_audit.client.httpx.post")
    def test_url_without_v1_suffix(self, mock_post):
        c = APIClient("https://relay.example.com", "key", "model", verbose=False)
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._openai_response()
        mock_post.return_value = resp

        c._call_openai([{"role": "user", "content": "x"}])
        called_url = mock_post.call_args[0][0]
        assert called_url == "https://relay.example.com/v1/chat/completions"

    @patch("api_relay_audit.client.httpx.post")
    def test_system_prepended(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = self._openai_response()
        mock_post.return_value = resp

        client._call_openai(
            [{"role": "user", "content": "x"}],
            system="Be concise",
        )
        body = mock_post.call_args[1]["json"]
        assert body["messages"][0] == {"role": "system", "content": "Be concise"}
        assert body["messages"][1] == {"role": "user", "content": "x"}

    @patch("api_relay_audit.client.httpx.post")
    def test_http_error(self, mock_post, client):
        resp = MagicMock(status_code=400)
        resp.text = "Bad Request"
        mock_post.return_value = resp

        result = client._call_openai([{"role": "user", "content": "x"}])
        assert "error" in result


# ---------------------------------------------------------------------------
# curl fallback
# ---------------------------------------------------------------------------

class TestCurlFallback:
    @patch("api_relay_audit.client.subprocess.run")
    def test_curl_post_success(self, mock_run, client):
        client._use_curl = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"content": [{"text": "curl ok"}], "usage": {}}),
        )

        result = client._call_anthropic([{"role": "user", "content": "x"}])
        assert result["text"] == "curl ok"
        mock_run.assert_called_once()

    @patch("api_relay_audit.client.subprocess.run")
    def test_curl_post_failure_raises(self, mock_run, client):
        client._use_curl = True
        mock_run.return_value = MagicMock(returncode=7, stderr="Connection refused")

        with pytest.raises(RuntimeError, match="curl failed"):
            client._curl_post("https://x", {}, {})

    @patch("api_relay_audit.client.subprocess.run")
    def test_curl_post_builds_correct_command(self, mock_run, client):
        client._use_curl = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ok": true}',
        )

        client._curl_post(
            "https://relay.example.com/v1/messages",
            {"x-api-key": "sk-test", "content-type": "application/json"},
            {"model": "test"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "curl"
        assert "-sk" in cmd
        assert "https://relay.example.com/v1/messages" in cmd
        assert "-H" in cmd


# ---------------------------------------------------------------------------
# Auto-detection flow
# ---------------------------------------------------------------------------

class TestAutoDetection:
    @patch("api_relay_audit.client.httpx.post")
    def test_anthropic_detected_first(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "content": [{"text": "detected"}],
            "usage": {"input_tokens": 5, "output_tokens": 3},
        }
        mock_post.return_value = resp

        result = client.call([{"role": "user", "content": "hi"}])
        assert result["text"] == "detected"
        assert client.detected_format == "anthropic"
        assert "time" in result

    @patch("api_relay_audit.client.httpx.post")
    def test_openai_fallback_when_anthropic_empty(self, mock_post, client):
        anthropic_resp = MagicMock(status_code=200)
        anthropic_resp.json.return_value = {"content": [{"text": ""}], "usage": {}}

        openai_resp = MagicMock(status_code=200)
        openai_resp.json.return_value = {
            "choices": [{"message": {"content": "openai works"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_post.side_effect = [anthropic_resp, openai_resp]

        result = client.call([{"role": "user", "content": "hi"}])
        assert result["text"] == "openai works"
        assert client.detected_format == "openai"

    @patch("api_relay_audit.client.httpx.post")
    def test_format_cached_after_detection(self, mock_post, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "content": [{"text": "cached"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        mock_post.return_value = resp

        client.call([{"role": "user", "content": "1"}])
        assert client.detected_format == "anthropic"

        # Second call should use cached format (only 1 httpx call)
        mock_post.reset_mock()
        client.call([{"role": "user", "content": "2"}])
        assert mock_post.call_count == 1

    @patch("api_relay_audit.client.httpx.post")
    def test_both_formats_fail_returns_error(self, mock_post, client):
        resp = MagicMock(status_code=500)
        resp.text = "Server Error"
        mock_post.return_value = resp

        result = client.call([{"role": "user", "content": "hi"}])
        assert "error" in result

    @patch("api_relay_audit.client.httpx.post")
    def test_ssl_error_triggers_curl_switch(self, mock_post, verbose_client):
        mock_post.side_effect = Exception("SSL: CERTIFICATE_VERIFY_FAILED")

        with patch("api_relay_audit.client.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "content": [{"text": "via curl"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }),
            )
            result = verbose_client.call([{"role": "user", "content": "hi"}])

        assert verbose_client._use_curl is True

    @patch("api_relay_audit.client.httpx.post")
    def test_exception_returns_error_with_time(self, mock_post, client):
        mock_post.side_effect = RuntimeError("boom")

        result = client.call([{"role": "user", "content": "x"}])
        assert "error" in result
        assert "time" in result
        assert result["time"] >= 0


# ---------------------------------------------------------------------------
# _handle_ssl_error
# ---------------------------------------------------------------------------

class TestHandleSSLError:
    def test_ssl_keyword_triggers_curl(self, client):
        assert client._handle_ssl_error(Exception("SSL error occurred")) is True
        assert client._use_curl is True

    def test_connect_error_type_triggers_curl(self, client):
        class ConnectError(Exception):
            pass
        assert client._handle_ssl_error(ConnectError("fail")) is True
        assert client._use_curl is True

    def test_non_ssl_error_does_not_trigger(self, client):
        assert client._handle_ssl_error(Exception("timeout")) is False
        assert client._use_curl is False

    def test_already_using_curl_returns_false(self, client):
        client._use_curl = True
        assert client._handle_ssl_error(Exception("SSL again")) is False


# ---------------------------------------------------------------------------
# get_models
# ---------------------------------------------------------------------------

class TestGetModels:
    @patch("api_relay_audit.client.httpx.get")
    def test_success(self, mock_get, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "data": [{"id": "claude-3-haiku"}, {"id": "gpt-4"}],
        }
        mock_get.return_value = resp

        models = client.get_models()
        assert len(models) == 2
        assert models[0]["id"] == "claude-3-haiku"

    @patch("api_relay_audit.client.httpx.get")
    def test_url_construction(self, mock_get, client):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": []}
        mock_get.return_value = resp

        client.get_models()
        called_url = mock_get.call_args[0][0]
        assert called_url == "https://relay.example.com/v1/models"

    @patch("api_relay_audit.client.httpx.get")
    def test_http_error_returns_empty(self, mock_get, client):
        resp = MagicMock(status_code=403)
        mock_get.return_value = resp

        assert client.get_models() == []

    @patch("api_relay_audit.client.httpx.get")
    def test_exception_returns_empty(self, mock_get, client):
        mock_get.side_effect = Exception("network down")
        assert client.get_models() == []

    @patch("api_relay_audit.client.subprocess.run")
    def test_curl_mode(self, mock_run, client):
        client._use_curl = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"data": [{"id": "m1"}]}),
        )

        models = client.get_models()
        assert len(models) == 1
        assert models[0]["id"] == "m1"

    @patch("api_relay_audit.client.subprocess.run")
    def test_curl_mode_failure(self, mock_run, client):
        client._use_curl = True
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="fail")

        assert client.get_models() == []


# ---------------------------------------------------------------------------
# _log
# ---------------------------------------------------------------------------

class TestLog:
    def test_verbose_prints(self, verbose_client, capsys):
        verbose_client._log("hello")
        assert "hello" in capsys.readouterr().out

    def test_quiet_no_output(self, client, capsys):
        client._log("hello")
        assert capsys.readouterr().out == ""
