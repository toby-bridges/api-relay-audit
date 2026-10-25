"""Map veridrop's structured_output sub-checks onto PR #95's Step 8 probe.

The five mandatory checks come from canarybyte/veridrop
``src/relay_detector/protocols/anthropic/detectors/structured_output.py``
(AGPL-3.0, same license as this project). Only the concepts are referenced;
no veridrop code is copied.

V1 block present, V3 name, V4 input: already covered by stricter checks.
V2 id prefix and V5 forward stop_reason: covered once the client marks the
normalized response with ``protocol``; a response without the marker keeps
the protocol-neutral checks.
"""

from api_relay_audit.client import _clip_probe_text
from api_relay_audit.tool_call_integrity import analyze_tool_call_integrity

EXPECTED = {"probe_token": "TC_fixed", "sequence": 1, "mode": "observe_only"}
NAME = "record_probe_fixed"


def _call(**over):
    base = {
        "type": "function",
        "id": "toolu_01abc",
        "name": NAME,
        "arguments": dict(EXPECTED),
        "arguments_error": None,
    }
    base.update(over)
    return base


def _analyze(response):
    return analyze_tool_call_integrity(
        response, expected_name=NAME, expected_arguments=EXPECTED
    )


# V1: veridrop "has_tool_use_block" (fail) -> here inconclusive, or anomaly
# when the relay claims a tool stop reason without any call.
def test_v1_missing_tool_use_block_is_inconclusive():
    result = _analyze({"tool_calls": [], "stop_reason": "end_turn"})
    assert result["verdict"] == "inconclusive"


def test_v1_missing_block_with_claimed_tool_stop_is_anomaly():
    result = _analyze({"tool_calls": [], "stop_reason": "tool_use"})
    assert result["verdict"] == "anomaly"


# V3: veridrop "name == TOOL_NAME" -> here name_match feeds anomaly.
def test_v3_tool_name_mismatch_is_anomaly():
    result = _analyze({"tool_calls": [_call(name="get_weather")], "stop_reason": "tool_use"})
    assert result["verdict"] == "anomaly"
    assert result["name_match"] is False


# V4: veridrop only checks schema fit; here a schema-valid but different
# payload is still an anomaly because the canary is compared exactly.
def test_v4_schema_valid_but_different_arguments_is_anomaly():
    swapped = {"probe_token": "TC_other", "sequence": 1, "mode": "observe_only"}
    result = _analyze({"tool_calls": [_call(arguments=swapped)], "stop_reason": "tool_use"})
    assert result["verdict"] == "anomaly"
    assert result["arguments_match"] is False


# V2: veridrop checks tool_use.id startswith "toolu_". Here the verdict stays
# clean and a protocol note is recorded, because a non-standard id alone is
# not rewriting.
def test_v2_anthropic_id_without_toolu_prefix_is_noted_but_clean():
    result = _analyze({
        "protocol": "anthropic",
        "tool_calls": [_call(id="call_abc123")],
        "stop_reason": "tool_use",
    })
    assert result["verdict"] == "clean"
    assert any("toolu_" in note for note in result.get("protocol_notes", []))


# V5: veridrop checks stop_reason == "tool_use". A call that arrives with
# ``end_turn`` can make an agent loop ignore the call, so Anthropic-format
# probes treat it as an anomaly; OpenAI-format forced calls legitimately
# return ``stop`` (see the OpenAI test below).
def test_v5_tool_call_with_end_turn_stop_reason_is_anomaly():
    result = _analyze({
        "protocol": "anthropic",
        "tool_calls": [_call()],
        "stop_reason": "end_turn",
    })
    assert result["verdict"] == "anomaly"
    assert any("stop reason" in f.lower() for f in result["findings"])


def test_openai_stop_or_tool_calls_finish_reason_with_exact_call_is_clean():
    for finish_reason in ("stop", "tool_calls"):
        result = _analyze({
            "protocol": "openai",
            "tool_calls": [_call(id="call_abc123")],
            "stop_reason": finish_reason,
        })
        assert result["verdict"] == "clean", finish_reason
        assert result["findings"] == []
        assert result["protocol_notes"] == []


def test_text_excerpt_redacts_sk_style_key():
    key = "sk-" + "A1b2C3d4" * 4
    result = _analyze({
        "protocol": "anthropic",
        "tool_calls": [],
        "stop_reason": "end_turn",
        "text": f"Tools are disabled here.\nUse {key} | `cat` instead.",
    })
    assert result["verdict"] == "inconclusive"
    excerpt = result["text_excerpt"]
    assert key not in excerpt
    assert key[:12] not in excerpt
    assert "<REDACTED_SECRET>" in excerpt
    assert "\\|" in excerpt and "\\`" in excerpt and "\n" not in excerpt
    assert len(excerpt) <= 200

    # A key cut by the client's 200-character bound must not survive as a
    # partial tail that is too short for the redaction pattern.
    clipped = _clip_probe_text("x" * 190 + " " + key)
    assert len(clipped) <= 200
    assert "sk-" not in clipped
