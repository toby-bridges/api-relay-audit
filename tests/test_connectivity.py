import json

import pytest

from api_relay_audit import connectivity
from api_relay_audit.connectivity import CONNECTIVITY_PROMPT, run_connectivity_check


class FakeClient:
    def __init__(self, responses, api_key="sk-secret-connectivity"):
        self.base_url = "https://relay.example.com/v1"
        self.api_key = api_key
        self.model = "claude-test"
        self.timeout = 17
        self._responses = list(responses)
        self.calls = []

    def raw_request(self, method, path, headers, body, content_type, timeout):
        self.calls.append({
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "content_type": content_type,
            "timeout": timeout,
        })
        return self._responses.pop(0)


def response(status, body, headers=None, error=None):
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    return {
        "status": status,
        "headers": headers or {"content-type": "application/json"},
        "body": body,
        "error": error,
    }


def anthropic_ok(text="ok"):
    return response(
        200,
        {
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 9, "output_tokens": 1},
        },
        headers={"content-type": "application/json", "x-request-id": "req_1"},
    )


def openai_ok(text="ok"):
    return response(
        200,
        {
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 1},
        },
        headers={"content-type": "application/json", "x-request-id": "req_2"},
    )


@pytest.fixture(autouse=True)
def deterministic_time(monkeypatch):
    ticks = iter([1.0, 1.125, 2.0, 2.250])
    monkeypatch.setattr(connectivity.time, "time", lambda: next(ticks))


def test_anthropic_success_openai_failure_reports_warning_and_request_shape():
    client = FakeClient([anthropic_ok(), response(404, {"error": {"message": "missing"}})])

    result = run_connectivity_check(client)

    assert result["success"] is True
    assert result["verdict"] == "WARNING"
    assert result["successful_formats"] == ["Anthropic Chat"]
    assert len(client.calls) == 2

    anthropic_call = client.calls[0]
    assert anthropic_call["method"] == "POST"
    assert anthropic_call["path"] == "/v1/messages"
    assert anthropic_call["headers"] == {
        "x-api-key": client.api_key,
        "anthropic-version": "2023-06-01",
    }
    assert anthropic_call["content_type"] == "application/json"
    assert anthropic_call["timeout"] == client.timeout
    anthropic_body = json.loads(anthropic_call["body"])
    assert anthropic_body["max_tokens"] == 8
    assert anthropic_body["messages"][0]["content"] == CONNECTIVITY_PROMPT

    openai_call = client.calls[1]
    assert openai_call["path"] == "/v1/chat/completions"
    assert openai_call["headers"] == {"Authorization": f"Bearer {client.api_key}"}
    assert "API Relay Connectivity Report" in result["markdown"]
    assert "WARNING" in result["markdown"]
    assert "LOW RISK" not in result["markdown"]


def test_openai_success_anthropic_failure_reports_openai_format():
    client = FakeClient([response(400, {"error": {"message": "bad format"}}), openai_ok()])

    result = run_connectivity_check(client)

    assert result["success"] is True
    assert result["verdict"] == "WARNING"
    assert result["successful_formats"] == ["OpenAI Chat"]
    assert "Bad request" in result["markdown"]
    assert "OpenAI Chat" in result["markdown"]


def test_both_formats_success_reports_ok():
    client = FakeClient([anthropic_ok("ok anthropic"), openai_ok("ok openai")])

    result = run_connectivity_check(client)

    assert result["success"] is True
    assert result["verdict"] == "OK"
    assert result["successful_formats"] == ["Anthropic Chat", "OpenAI Chat"]
    assert "9/1" in result["markdown"]
    assert "8/1" in result["markdown"]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "Authentication or authorization failed"),
        (403, "Authentication or authorization failed"),
        (404, "Endpoint not found"),
        (429, "Rate limited or quota exhausted"),
        (500, "Relay or upstream server error"),
        (0, "Transport failure"),
    ],
)
def test_both_formats_fail_with_common_status_diagnostics(status, expected):
    client = FakeClient([
        response(status, {"error": {"message": "fail"}}, error="network failure"),
        response(status, {"error": {"message": "fail"}}, error="network failure"),
    ])

    result = run_connectivity_check(client)

    assert result["success"] is False
    assert result["verdict"] == "FAILED"
    assert expected in result["markdown"]


def test_malformed_json_warns_when_other_format_succeeds():
    client = FakeClient([response(200, "not json"), openai_ok()])

    result = run_connectivity_check(client)

    assert result["success"] is True
    assert result["verdict"] == "WARNING"
    assert "response was not valid JSON" in result["markdown"]


def test_malformed_or_empty_2xx_without_success_fails():
    client = FakeClient([
        response(200, "not json"),
        response(200, {"choices": [{"message": {"content": ""}}]}),
    ])

    result = run_connectivity_check(client)

    assert result["success"] is False
    assert result["verdict"] == "FAILED"
    assert "response was not valid JSON" in result["markdown"]
    assert "did not contain parsed text" in result["markdown"]


def test_report_does_not_leak_api_key_from_errors_or_body():
    key = "sk-secret-connectivity"
    client = FakeClient([
        response(0, f"server echoed {key}", error=f"curl failed with {key}"),
        response(401, {"error": {"message": f"bad key {key}"}}),
    ], api_key=key)

    result = run_connectivity_check(client)

    assert key not in result["markdown"]
    assert "[redacted-api-key]" in result["markdown"]
