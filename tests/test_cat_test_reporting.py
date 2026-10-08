"""Step 5 reports the exact caller probe and its observed outcome."""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(params=["modular", "standalone"])
def audit(request):
    path = (REPO_ROOT / "scripts" / "audit.py"
            if request.param == "modular" else REPO_ROOT / "audit.py")
    spec = importlib.util.spec_from_file_location(
        f"cat_reporting_{request.param}", path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(audit, monkeypatch, first_response):
    monkeypatch.setattr(audit.time, "sleep", lambda _: None)
    client = MagicMock()
    client.call.side_effect = [
        first_response,
        {"text": "I am Claude by Anthropic.", "input_tokens": 55},
    ]
    report = audit.Reporter()
    result = audit.test_instruction_conflict(client, report)
    return result, client, report


def test_cat_failure_reports_exact_sent_prompt_and_nonadherence(audit, monkeypatch):
    result, client, report = _run(
        audit, monkeypatch, {"text": "2", "input_tokens": 142},
    )

    assert result is True
    call = client.call.call_args_list[0]
    sent_system = call.kwargs["system"]
    sent_user = call.args[0][0]["content"]
    body = "\n".join(report.sections).split("### Test D2:")[0]
    assert f"system: `{sent_system}`" in body
    assert f"user: `{sent_user}`" in body
    findings = [message for _, message in report.summary if "Cat test failed" in message]
    assert len(findings) == 1
    assert "system instruction was not followed in this response" in findings[0]
    assert "overridden" not in findings[0].lower()


def test_identity_probe_reports_exact_sent_prompts(audit, monkeypatch):
    result, client, report = _run(
        audit, monkeypatch, {"text": "meow", "input_tokens": 142},
    )

    assert result is False
    call = client.call.call_args_list[1]
    sent_system = call.kwargs["system"]
    sent_user = call.args[0][0]["content"]
    body = "\n".join(report.sections).split("### Test D2:")[1]
    assert f"system: `{sent_system}`" in body
    assert f"user: `{sent_user}`" in body


def test_http_422_reports_rejection_without_attribution(audit, monkeypatch):
    result, _, report = _run(
        audit, monkeypatch, {"error": "HTTP 422 Unprocessable Entity"},
    )

    assert result is True
    findings = [message for _, message in report.summary if "Cat test blocked" in message]
    assert len(findings) == 1
    assert "returned HTTP 422" in findings[0]
    assert "relay rejects" not in findings[0]
