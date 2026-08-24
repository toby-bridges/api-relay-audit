"""Public-interface tests for APIClient structured Tool Call probes."""

import json

from unittest.mock import MagicMock, patch

from api_relay_audit.client import APIClient
from api_relay_audit.transparent_log import TransparentLogger, sha256hex


def make_client(format_name):
    client = APIClient(
        "https://relay.example.com/v1",
        "sk-test-key",
        "claude-test",
        timeout=30,
        verbose=False,
    )
    client._format = format_name
    return client


TOOL_SPEC = {
    "name": "record_probe_fixed",
    "description": "Record an inert canary without executing anything.",
    "input_schema": {
        "type": "object",
        "properties": {"probe_token": {"type": "string"}},
        "required": ["probe_token"],
        "additionalProperties": False,
    },
}


@patch("api_relay_audit.client.httpx.post")
def test_anthropic_tool_probe_forces_one_strict_tool_and_normalizes_response(
    mock_post,
):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "content": [
            {"type": "text", "text": "calling now"},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "record_probe_fixed",
                "input": {"probe_token": "TC_fixed"},
            },
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 11, "output_tokens": 4},
    }
    mock_post.return_value = response
    client = make_client("anthropic")

    result = client.call_tool_probe(
        [{"role": "user", "content": "call it"}],
        TOOL_SPEC,
        max_tokens=256,
    )

    assert result["tool_calls"] == [{
        "type": "function",
        "id": "toolu_1",
        "name": "record_probe_fixed",
        "arguments": {"probe_token": "TC_fixed"},
        "arguments_error": None,
    }]
    assert result["stop_reason"] == "tool_use"
    assert result["input_tokens"] == 11
    assert result["output_tokens"] == 4
    assert result["raw"] == response.json.return_value
    assert result["time"] >= 0

    called_url = mock_post.call_args.args[0]
    body = mock_post.call_args.kwargs["json"]
    assert called_url == "https://relay.example.com/v1/messages"
    assert body["tools"] == [{**TOOL_SPEC, "strict": True}]
    assert body["tool_choice"] == {
        "type": "tool",
        "name": "record_probe_fixed",
        "disable_parallel_tool_use": True,
    }
    assert "tool_result" not in str(body)


@patch("api_relay_audit.client.httpx.post")
def test_openai_tool_probe_forces_one_strict_function_and_parses_arguments(
    mock_post,
):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "choices": [{
            "message": {
                "content": None,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "record_probe_fixed",
                        "arguments": '{"probe_token":"TC_fixed"}',
                    },
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 13, "completion_tokens": 5},
    }
    mock_post.return_value = response
    client = make_client("openai")

    result = client.call_tool_probe(
        [{"role": "user", "content": "call it"}],
        TOOL_SPEC,
        max_tokens=256,
    )

    assert result["tool_calls"] == [{
        "type": "function",
        "id": "call_1",
        "name": "record_probe_fixed",
        "arguments": {"probe_token": "TC_fixed"},
        "arguments_error": None,
    }]
    assert result["stop_reason"] == "tool_calls"
    assert result["input_tokens"] == 13
    assert result["output_tokens"] == 5

    called_url = mock_post.call_args.args[0]
    body = mock_post.call_args.kwargs["json"]
    assert called_url == "https://relay.example.com/v1/chat/completions"
    assert body["tools"] == [{
        "type": "function",
        "function": {
            "name": TOOL_SPEC["name"],
            "description": TOOL_SPEC["description"],
            "parameters": TOOL_SPEC["input_schema"],
            "strict": True,
        },
    }]
    assert body["tool_choice"] == {
        "type": "function",
        "function": {"name": "record_probe_fixed"},
    }
    assert body["parallel_tool_calls"] is False
    assert "tool_result" not in str(body)


@patch("api_relay_audit.client.httpx.post")
def test_openai_tool_probe_preserves_multiple_calls_and_invalid_arguments(
    mock_post,
):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "choices": [{
            "message": {"tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "record_probe_fixed",
                        "arguments": "{not-json",
                    },
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "unexpected_tool",
                        "arguments": "[]",
                    },
                },
            ]},
            "finish_reason": "tool_calls",
        }],
        "usage": {},
    }
    mock_post.return_value = response
    client = make_client("openai")

    result = client.call_tool_probe([], TOOL_SPEC)

    assert len(result["tool_calls"]) == 2
    assert result["tool_calls"][0]["arguments"] is None
    assert result["tool_calls"][0]["arguments_error"] == "invalid JSON arguments"
    assert result["tool_calls"][1]["arguments"] is None
    assert result["tool_calls"][1]["arguments_error"] == (
        "OpenAI tool arguments were not a JSON object"
    )


@patch("api_relay_audit.client.httpx.post")
def test_tool_probe_http_error_uses_existing_error_shape(mock_post):
    response = MagicMock(status_code=400, text="strict tools unsupported")
    mock_post.return_value = response
    client = make_client("anthropic")

    result = client.call_tool_probe([], TOOL_SPEC)

    assert result["error"] == "HTTP 400: strict tools unsupported"
    assert result["diagnosis"]["category"] == "bad-request"
    assert result["time"] >= 0


@patch("api_relay_audit.client.httpx.post")
def test_tool_probe_transparent_log_hashes_exact_wire_body(mock_post, tmp_path):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "choices": [{"message": {"tool_calls": []}, "finish_reason": "stop"}],
        "usage": {},
    }
    mock_post.return_value = response
    client = make_client("openai")
    log_path = tmp_path / "tool-probe.jsonl"
    logger = TransparentLogger(str(log_path))
    client.set_transparent_logger(logger)

    client.call_tool_probe(
        [{"role": "user", "content": "call it"}], TOOL_SPEC, max_tokens=256)
    logger.close()

    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    wire_body = mock_post.call_args.kwargs["json"]
    assert entry["method"] == "tool_call_probe"
    assert entry["request_body_sha256"] == sha256hex(json.dumps(wire_body))
    assert "sk-test-key" not in log_path.read_text(encoding="utf-8")


@patch("api_relay_audit.client.httpx.post")
def test_tool_probe_uses_existing_format_detection_before_adapter(mock_post):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "content": [],
        "stop_reason": "end_turn",
        "usage": {},
    }
    mock_post.return_value = response
    client = make_client(None)

    def detect_format():
        client._format = "anthropic"
        return True

    client.ensure_format = MagicMock(side_effect=detect_format)

    result = client.call_tool_probe([], TOOL_SPEC)

    client.ensure_format.assert_called_once_with()
    assert result["tool_calls"] == []
    assert mock_post.call_args.args[0].endswith("/messages")


@patch("api_relay_audit.client.httpx.post")
def test_anthropic_tool_probe_preserves_tool_like_block_type_mutation(mock_post):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "content": [{
            "type": "custom_tool",
            "id": "toolu_1",
            "name": "record_probe_fixed",
            "input": {"probe_token": "TC_fixed"},
        }],
        "stop_reason": "tool_use",
        "usage": {},
    }
    mock_post.return_value = response
    client = make_client("anthropic")

    result = client.call_tool_probe([], TOOL_SPEC)

    assert result["tool_calls"][0]["type"] == "custom_tool"
    assert result["tool_calls"][0]["arguments"] == {"probe_token": "TC_fixed"}
