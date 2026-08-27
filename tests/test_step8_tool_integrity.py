"""Step 8 orchestration tests for text and structured Tool Call probes."""

from unittest.mock import MagicMock

import scripts.audit as audit
from api_relay_audit.reporter import Reporter


TEXT_CLEAN = ([
    {
        "manager": "pip",
        "expected": "pip install requests==2.31.0",
        "received": "pip install requests==2.31.0",
        "verdict": "exact",
    }
], False, False)

TEXT_ANOMALY = ([
    {
        "manager": "pip",
        "expected": "pip install requests==2.31.0",
        "received": "pip install reqeusts==2.31.0",
        "verdict": "substituted",
    }
], True, False)


def _structured(verdict):
    return {
        "verdict": verdict,
        "expected_count": 1,
        "received_count": 1 if verdict != "inconclusive" else 0,
        "name_match": True if verdict == "clean" else None,
        "arguments_match": True if verdict == "clean" else None,
        "findings": [] if verdict == "clean" else [f"structured {verdict}"],
        "received_calls": [],
    }


def test_text_clean_and_structured_clean_is_step8_clean(monkeypatch):
    monkeypatch.setattr(audit, "run_tool_substitution_test", MagicMock(return_value=TEXT_CLEAN))
    monkeypatch.setattr(
        audit,
        "run_tool_call_integrity_test",
        MagicMock(return_value=_structured("clean")),
        raising=False,
    )
    report = Reporter()

    assert audit.test_tool_substitution(MagicMock(), report) == (False, False)
    assert report.summary[-1][0] == "green"
    assert "Tool-Call Integrity (AC-1 / AC-1.a)" in "".join(report.sections)


def test_structured_anomaly_sets_d3(monkeypatch):
    monkeypatch.setattr(audit, "run_tool_substitution_test", MagicMock(return_value=TEXT_CLEAN))
    monkeypatch.setattr(
        audit,
        "run_tool_call_integrity_test",
        MagicMock(return_value=_structured("anomaly")),
    )
    report = Reporter()

    assert audit.test_tool_substitution(MagicMock(), report) == (True, False)
    assert report.summary[-1][0] == "red"


def test_structured_inconclusive_sets_d3i(monkeypatch):
    monkeypatch.setattr(audit, "run_tool_substitution_test", MagicMock(return_value=TEXT_CLEAN))
    monkeypatch.setattr(
        audit,
        "run_tool_call_integrity_test",
        MagicMock(return_value=_structured("inconclusive")),
    )
    report = Reporter()

    assert audit.test_tool_substitution(MagicMock(), report) == (False, True)
    assert report.summary[-1][0] == "yellow"


def test_text_anomaly_wins_over_structured_inconclusive(monkeypatch):
    monkeypatch.setattr(audit, "run_tool_substitution_test", MagicMock(return_value=TEXT_ANOMALY))
    monkeypatch.setattr(
        audit,
        "run_tool_call_integrity_test",
        MagicMock(return_value=_structured("inconclusive")),
    )
    report = Reporter()

    assert audit.test_tool_substitution(MagicMock(), report) == (True, False)
    assert report.summary[-1][0] == "red"


def test_structured_report_hides_tool_name_and_redacts_secrets(monkeypatch):
    caller_key = "sk-caller-key-abcdefghijklmnopqrstuvwxyz"
    upstream_key = "sk-upstream-key-abcdefghijklmnopqrstuvwxyz"
    malicious_name = "read_private_file"
    structured = _structured("anomaly")
    structured["received_calls"] = [{
        "type": "function",
        "id": "tool-1",
        "name": malicious_name,
        "arguments": {
            "caller": caller_key,
            "upstream": upstream_key,
        },
        "arguments_error": None,
    }]
    monkeypatch.setattr(
        audit,
        "run_tool_substitution_test",
        MagicMock(return_value=TEXT_CLEAN),
    )
    monkeypatch.setattr(
        audit,
        "run_tool_call_integrity_test",
        MagicMock(return_value=structured),
    )
    client = MagicMock()
    client.api_key = caller_key
    report = Reporter()

    assert audit.test_tool_substitution(client, report) == (True, False)
    rendered = "".join(report.sections)
    assert malicious_name not in rendered
    assert caller_key not in rendered
    assert caller_key[:8] not in rendered
    assert upstream_key not in rendered
    assert "<REDACTED" in rendered
