"""Structured Tool Call integrity analysis for Step 8.

The detector inspects inert client-tool requests only.  It never executes a
returned tool call and never sends a ``tool_result`` follow-up request.
"""

import json
import re
import uuid

from api_relay_audit.error_leakage import redact_sensitive_text


PROBE_PROMPT = (
    "Call the provided record tool exactly once with the exact arguments "
    "encoded in its schema. Do not answer in text."
)
PROBE_DESCRIPTION = (
    "Record an inert relay-audit canary. This tool performs no I/O, "
    "has no side effects, and will not be executed. Call it exactly once."
)
TEXT_EXCERPT_LIMIT = 200


def _json_deep_equal(left, right):
    """Compare parsed JSON values without Python's bool/int coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (
            left.keys() == right.keys()
            and all(_json_deep_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, list):
        return (
            len(left) == len(right)
            and all(_json_deep_equal(a, b) for a, b in zip(left, right))
        )
    return left == right


def _markdown_safe(text, max_chars, api_key=""):
    """Redact secrets, escape Markdown table/code delimiters, then bound."""
    text = redact_sensitive_text(text, api_key)
    text = text.replace("|", "\\|").replace("`", "\\`")
    limit = max(3, int(max_chars))
    if len(text) > limit:
        return text[:limit - 3] + "..."
    return text


def format_tool_calls_preview(calls, max_chars=240, api_key=""):
    """Return a redacted, Markdown-safe, bounded preview of arguments only."""
    arguments = [
        call.get("arguments") if isinstance(call, dict) else None
        for call in calls
    ]
    text = json.dumps(
        arguments,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return _markdown_safe(text, max_chars, api_key)


def format_text_excerpt(text, max_chars=TEXT_EXCERPT_LIMIT, api_key=""):
    """Return a redacted, Markdown-safe, single-line excerpt of returned text."""
    return _markdown_safe(" ".join(str(text).split()), max_chars, api_key)


def _id_prefix(value):
    if not isinstance(value, str) or not value:
        return "missing"
    match = re.match(r"[A-Za-z]{1,16}_", value)
    return match.group(0) if match else "none"


def _describe_stop_reason(value):
    if value is None:
        return "missing"
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z_]{0,31}", value):
        return f"'{value}'"
    return "a non-standard value"


def analyze_tool_call_integrity(response, expected_name, expected_arguments,
                                api_key=""):
    """Compare a normalized Tool Call response with the forced expectation.

    When the client marks ``protocol`` as ``anthropic``, two protocol checks
    apply. A ``tool_use`` id without the ``toolu_`` prefix is recorded in
    ``protocol_notes`` only: a non-standard id alone is not rewriting
    evidence. A returned call whose stop reason is not ``tool_use`` is an
    anomaly, because agent loops key on that field and may ignore the call.
    OpenAI-format forced calls may finish with ``stop`` or ``tool_calls``, so
    neither value is flagged. A response without ``protocol`` keeps the
    protocol-neutral checks only. When no call is returned, a redacted,
    bounded ``text_excerpt`` records what the relay said instead.

    Concept inspired by canarybyte/veridrop structured_output.py (AGPL-3.0); reimplemented independently.
    """
    if not isinstance(response, dict):
        response = {}
    if "error" in response:
        return {
            "verdict": "inconclusive",
            "expected_count": 1,
            "received_count": 0,
            "name_match": None,
            "arguments_match": None,
            "findings": [
                "Structured Tool Call probe failed; support could not be verified"
            ],
            "protocol_notes": [],
        }
    calls = response.get("tool_calls", [])
    if not isinstance(calls, list) or any(not isinstance(call, dict) for call in calls):
        return {
            "verdict": "inconclusive",
            "expected_count": 1,
            "received_count": 0,
            "name_match": None,
            "arguments_match": None,
            "findings": ["Structured Tool Call response format was invalid"],
            "protocol_notes": [],
        }
    if not calls:
        claimed_tool_stop = response.get("stop_reason") in {"tool_use", "tool_calls"}
        result = {
            "verdict": "anomaly" if claimed_tool_stop else "inconclusive",
            "expected_count": 1,
            "received_count": 0,
            "name_match": None,
            "arguments_match": None,
            "findings": ([
                "Response claimed a Tool Call stop reason but contained zero Tool Calls"
            ] if claimed_tool_stop else [
                "Forced tool request returned no structured Tool Call; "
                "support could not be verified"
            ]),
            "protocol_notes": [],
        }
        text = response.get("text")
        if isinstance(text, str) and text.strip():
            result["text_excerpt"] = format_text_excerpt(text, api_key=api_key)
        return result
    call = calls[0]
    count_match = len(calls) == 1
    type_match = call.get("type") == "function"
    name_match = call.get("name") == expected_name
    arguments_match = (
        call.get("arguments_error") is None
        and _json_deep_equal(call.get("arguments"), expected_arguments)
    )
    findings = []
    if not count_match:
        findings.append(
            f"Tool call count changed: expected 1, received {len(calls)}"
        )
    if not type_match:
        findings.append("Tool call type differed from the forced function type")
    if not name_match:
        findings.append("Tool name differed from the forced canary name")
    if call.get("arguments_error"):
        findings.append(
            f"Tool arguments could not be parsed: {call['arguments_error']}"
        )
    elif not arguments_match:
        findings.append("Tool arguments differed from the forced canary payload")
    protocol_notes = []
    stop_reason_match = True
    if response.get("protocol") == "anthropic":
        unprefixed = [
            item.get("id") for item in calls
            if not (isinstance(item.get("id"), str) and item["id"].startswith("toolu_"))
        ]
        if unprefixed:
            protocol_notes.append(
                f"{len(unprefixed)} of {len(calls)} Anthropic tool_use id(s) lacked "
                "the standard toolu_ prefix (first observed prefix: "
                f"{_id_prefix(unprefixed[0])}); recorded for context, not counted "
                "as rewriting"
            )
        stop_reason = response.get("stop_reason")
        if stop_reason != "tool_use":
            stop_reason_match = False
            findings.append(
                f"Anthropic stop reason was {_describe_stop_reason(stop_reason)}, "
                "not 'tool_use', although a Tool Call was returned; agent loops "
                "keyed on stop_reason may ignore the call"
            )
    return {
        "verdict": (
            "clean"
            if (count_match and type_match and name_match and arguments_match
                and stop_reason_match)
            else "anomaly"
        ),
        "expected_count": 1,
        "received_count": len(calls),
        "name_match": name_match,
        "arguments_match": arguments_match,
        "findings": findings,
        "protocol_notes": protocol_notes,
    }


def run_tool_call_integrity_test(client, nonce_factory=None):
    """Send one inert structured probe and return its tri-state analysis.

    The returned Tool Call is inspected only.  This function intentionally has
    no executor callback and never sends a follow-up tool result.
    """
    if nonce_factory is None:
        nonce_factory = lambda: uuid.uuid4().hex
    nonce = str(nonce_factory())
    tool_name = f"record_probe_{nonce[:12]}"
    expected_arguments = {
        "probe_token": f"TC_{nonce}",
        "sequence": 1,
        "mode": "observe_only",
    }
    tool_spec = {
        "name": tool_name,
        "description": PROBE_DESCRIPTION,
        "input_schema": {
            "type": "object",
            "properties": {
                "probe_token": {
                    "type": "string",
                    "enum": [expected_arguments["probe_token"]],
                },
                "sequence": {"type": "integer", "enum": [1]},
                "mode": {"type": "string", "enum": ["observe_only"]},
            },
            "required": ["probe_token", "sequence", "mode"],
            "additionalProperties": False,
        },
    }
    response = client.call_tool_probe(
        [{"role": "user", "content": PROBE_PROMPT}],
        tool_spec,
        max_tokens=256,
    )
    result = analyze_tool_call_integrity(
        response,
        expected_name=tool_name,
        expected_arguments=expected_arguments,
        api_key=getattr(client, "api_key", ""),
    )
    result["expected_name"] = tool_name
    result["expected_arguments"] = expected_arguments
    result["received_calls"] = (
        response.get("tool_calls", []) if isinstance(response, dict) else []
    )
    return result
