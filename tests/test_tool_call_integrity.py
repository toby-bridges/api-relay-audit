"""Behavior tests for structured Tool Call integrity detection."""

from unittest.mock import MagicMock

import pytest

from api_relay_audit.tool_call_integrity import (
    analyze_tool_call_integrity,
    format_tool_calls_preview,
    run_tool_call_integrity_test,
)


def test_exact_single_tool_call_is_clean():
    expected = {"probe_token": "TC_fixed", "sequence": 1, "mode": "observe_only"}
    response = {
        "tool_calls": [
            {
                "type": "function",
                "id": "tool-1",
                "name": "record_probe_fixed",
                "arguments": dict(expected),
                "arguments_error": None,
            }
        ],
        "stop_reason": "tool_use",
    }

    result = analyze_tool_call_integrity(
        response,
        expected_name="record_probe_fixed",
        expected_arguments=expected,
    )

    assert result == {
        "verdict": "clean",
        "expected_count": 1,
        "received_count": 1,
        "name_match": True,
        "arguments_match": True,
        "findings": [],
    }


def test_changed_tool_name_is_anomaly():
    expected = {"probe_token": "TC_fixed", "sequence": 1, "mode": "observe_only"}
    response = {
        "tool_calls": [{
            "type": "function",
            "id": "tool-1",
            "name": "read_private_file",
            "arguments": dict(expected),
            "arguments_error": None,
        }],
        "stop_reason": "tool_use",
    }

    result = analyze_tool_call_integrity(
        response,
        expected_name="record_probe_fixed",
        expected_arguments=expected,
    )

    assert result["verdict"] == "anomaly"
    assert result["name_match"] is False
    assert result["arguments_match"] is True
    assert result["findings"] == [
        "Tool name changed: expected 'record_probe_fixed', received 'read_private_file'"
    ]


def test_changed_arguments_are_anomaly_even_when_json_key_order_is_irrelevant():
    expected = {"probe_token": "TC_fixed", "sequence": 1, "mode": "observe_only"}
    response = {
        "tool_calls": [{
            "type": "function",
            "id": "tool-1",
            "name": "record_probe_fixed",
            "arguments": {
                "mode": "observe_only",
                "sequence": 2,
                "probe_token": "TC_fixed",
            },
            "arguments_error": None,
        }],
        "stop_reason": "tool_use",
    }

    result = analyze_tool_call_integrity(
        response,
        expected_name="record_probe_fixed",
        expected_arguments=expected,
    )

    assert result["verdict"] == "anomaly"
    assert result["name_match"] is True
    assert result["arguments_match"] is False
    assert result["findings"] == ["Tool arguments differed from the forced canary payload"]


def test_json_argument_types_are_compared_strictly():
    result = analyze_tool_call_integrity(
        {
            "tool_calls": [{
                "type": "function",
                "id": "tool-1",
                "name": "record_probe_fixed",
                "arguments": {
                    "probe_token": "TC_fixed",
                    "sequence": True,
                    "mode": "observe_only",
                },
                "arguments_error": None,
            }],
            "stop_reason": "tool_use",
        },
        expected_name="record_probe_fixed",
        expected_arguments={
            "probe_token": "TC_fixed",
            "sequence": 1,
            "mode": "observe_only",
        },
    )

    assert result["verdict"] == "anomaly"
    assert result["arguments_match"] is False


@pytest.mark.parametrize(
    "arguments",
    [
        {"probe_token": "TC_fixed", "sequence": 1},
        {
            "probe_token": "TC_fixed",
            "sequence": 1,
            "mode": "observe_only",
            "extra": "injected",
        },
    ],
)
def test_missing_or_extra_json_fields_are_anomalies(arguments):
    result = analyze_tool_call_integrity(
        {
            "tool_calls": [{
                "type": "function",
                "id": "tool-1",
                "name": "record_probe_fixed",
                "arguments": arguments,
                "arguments_error": None,
            }],
            "stop_reason": "tool_use",
        },
        expected_name="record_probe_fixed",
        expected_arguments={
            "probe_token": "TC_fixed",
            "sequence": 1,
            "mode": "observe_only",
        },
    )

    assert result["verdict"] == "anomaly"
    assert result["arguments_match"] is False


def test_extra_tool_call_is_anomaly():
    expected = {"probe_token": "TC_fixed", "sequence": 1, "mode": "observe_only"}
    clean_call = {
        "type": "function",
        "id": "tool-1",
        "name": "record_probe_fixed",
        "arguments": dict(expected),
        "arguments_error": None,
    }
    response = {
        "tool_calls": [clean_call, {**clean_call, "id": "tool-2"}],
        "stop_reason": "tool_use",
    }

    result = analyze_tool_call_integrity(
        response,
        expected_name="record_probe_fixed",
        expected_arguments=expected,
    )

    assert result["verdict"] == "anomaly"
    assert result["received_count"] == 2
    assert result["findings"] == ["Tool call count changed: expected 1, received 2"]


def test_no_tool_call_is_inconclusive_when_relay_does_not_honor_forcing():
    result = analyze_tool_call_integrity(
        {"tool_calls": [], "stop_reason": "stop"},
        expected_name="record_probe_fixed",
        expected_arguments={"probe_token": "TC_fixed"},
    )

    assert result == {
        "verdict": "inconclusive",
        "expected_count": 1,
        "received_count": 0,
        "name_match": None,
        "arguments_match": None,
        "findings": [
            "Forced tool request returned no structured Tool Call; support could not be verified"
        ],
    }


def test_tool_stop_reason_without_calls_is_anomaly():
    result = analyze_tool_call_integrity(
        {"tool_calls": [], "stop_reason": "tool_calls"},
        expected_name="record_probe_fixed",
        expected_arguments={"probe_token": "TC_fixed"},
    )

    assert result["verdict"] == "anomaly"
    assert result["received_count"] == 0
    assert result["findings"] == [
        "Response claimed a Tool Call stop reason but contained zero Tool Calls"
    ]


def test_probe_error_is_inconclusive():
    result = analyze_tool_call_integrity(
        {"error": "HTTP 400 strict tools unsupported"},
        expected_name="record_probe_fixed",
        expected_arguments={"probe_token": "TC_fixed"},
    )

    assert result["verdict"] == "inconclusive"
    assert result["received_count"] == 0
    assert result["name_match"] is None
    assert result["arguments_match"] is None
    assert result["findings"] == [
        "Structured Tool Call probe failed: HTTP 400 strict tools unsupported"
    ]


def test_malformed_normalized_response_is_inconclusive():
    result = analyze_tool_call_integrity(
        {"tool_calls": "not-a-list", "stop_reason": None},
        expected_name="record_probe_fixed",
        expected_arguments={"probe_token": "TC_fixed"},
    )

    assert result["verdict"] == "inconclusive"
    assert result["received_count"] == 0
    assert result["findings"] == [
        "Structured Tool Call response format was invalid"
    ]


def test_invalid_json_arguments_are_anomaly():
    result = analyze_tool_call_integrity(
        {
            "tool_calls": [{
                "type": "function",
                "id": "tool-1",
                "name": "record_probe_fixed",
                "arguments": None,
                "arguments_error": "invalid JSON arguments",
            }],
            "stop_reason": "tool_calls",
        },
        expected_name="record_probe_fixed",
        expected_arguments={"probe_token": "TC_fixed"},
    )

    assert result["verdict"] == "anomaly"
    assert result["arguments_match"] is False
    assert result["findings"] == [
        "Tool arguments could not be parsed: invalid JSON arguments"
    ]


def test_non_function_tool_type_is_anomaly():
    result = analyze_tool_call_integrity(
        {
            "tool_calls": [{
                "type": "custom",
                "id": "tool-1",
                "name": "record_probe_fixed",
                "arguments": {"probe_token": "TC_fixed"},
                "arguments_error": None,
            }],
            "stop_reason": "tool_calls",
        },
        expected_name="record_probe_fixed",
        expected_arguments={"probe_token": "TC_fixed"},
    )

    assert result["verdict"] == "anomaly"
    assert result["findings"] == [
        "Tool call type changed: expected 'function', received 'custom'"
    ]


def test_runner_builds_inert_strict_probe_and_returns_clean_verdict():
    nonce = "0123456789abcdef0123456789abcdef"
    client = MagicMock()

    def respond(messages, tool_spec, max_tokens=256):
        assert messages == [{
            "role": "user",
            "content": (
                "Call the provided record tool exactly once with the exact "
                "arguments encoded in its schema. Do not answer in text."
            ),
        }]
        assert tool_spec == {
            "name": "record_probe_0123456789ab",
            "description": (
                "Record an inert relay-audit canary. This tool performs no I/O, "
                "has no side effects, and will not be executed. Call it exactly once."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "probe_token": {"type": "string", "enum": [f"TC_{nonce}"]},
                    "sequence": {"type": "integer", "enum": [1]},
                    "mode": {"type": "string", "enum": ["observe_only"]},
                },
                "required": ["probe_token", "sequence", "mode"],
                "additionalProperties": False,
            },
        }
        return {
            "tool_calls": [{
                "type": "function",
                "id": "tool-1",
                "name": tool_spec["name"],
                "arguments": {
                    "mode": "observe_only",
                    "sequence": 1,
                    "probe_token": f"TC_{nonce}",
                },
                "arguments_error": None,
            }],
            "stop_reason": "tool_use",
        }

    client.call_tool_probe.side_effect = respond

    result = run_tool_call_integrity_test(client, nonce_factory=lambda: nonce)

    assert result["verdict"] == "clean"
    assert result["expected_name"] == "record_probe_0123456789ab"
    assert result["expected_arguments"] == {
        "probe_token": f"TC_{nonce}",
        "sequence": 1,
        "mode": "observe_only",
    }
    assert result["received_calls"][0]["name"] == "record_probe_0123456789ab"
    client.call_tool_probe.assert_called_once()


def test_runner_treats_non_object_client_result_as_format_error():
    client = MagicMock()
    client.call_tool_probe.return_value = None

    result = run_tool_call_integrity_test(client, nonce_factory=lambda: "fixed")

    assert result["verdict"] == "inconclusive"
    assert result["received_calls"] == []


def test_tool_call_preview_is_escaped_and_bounded():
    preview = format_tool_calls_preview(
        [{
            "type": "function",
            "name": "must-not-be-rendered",
            "arguments": {"command": "bad|`" + "x" * 200},
            "arguments_error": None,
        }],
        max_chars=80,
    )

    assert len(preview) <= 80
    assert "\\|" in preview
    assert "\\`" in preview
    assert "must-not-be-rendered" not in preview
    assert preview.endswith("...")
