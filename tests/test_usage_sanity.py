"""Step 3 token usage sanity observation (informational, both distributions)."""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from api_relay_audit import usage_sanity as us


REPO_ROOT = Path(__file__).resolve().parent.parent
LONG_PROMPT = "Say hi" + " apple" * 80


def _load(path, name, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=["modular", "standalone"])
def audit_module(request, monkeypatch):
    rel = "scripts/audit.py" if request.param == "modular" else "audit.py"
    return _load(REPO_ROOT / rel, f"usage_sanity_{request.param}", monkeypatch)


def _ok(input_tokens, output_tokens, fmt="anthropic"):
    if fmt == "anthropic":
        usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    else:
        usage = {"prompt_tokens": input_tokens, "completion_tokens": output_tokens}
    return {"text": "hi", "input_tokens": input_tokens,
            "output_tokens": output_tokens, "raw": {"usage": usage}, "time": 0.01}


def _count(status, body, error=None):
    return {"status": status, "headers": {}, "body": body, "error": error}


class FakeClient:
    """Offline double that records every request and never touches the network."""

    def __init__(self, long_result, count_response=None,
                 detected_format="anthropic", step3_results=None):
        self.model = "claude-test"
        self.api_key = "sk-usage-sanity-test"
        self.detected_format = detected_format
        self.long_result = long_result
        self.count_response = count_response
        self.step3_results = list(step3_results or [])
        self.calls = []
        self.raw_calls = []

    def call(self, messages, system=None, max_tokens=512, with_thinking=False):
        self.calls.append({"messages": messages, "system": system,
                           "max_tokens": max_tokens})
        if self.step3_results:
            return self.step3_results.pop(0)
        return self.long_result

    def raw_request(self, method, path, headers, body,
                    content_type="application/json", timeout=30):
        self.raw_calls.append({"method": method, "path": path,
                               "headers": headers, "body": body})
        return self.count_response


def _run(client, baseline):
    return us.run_usage_sanity(client, baseline, sleep_fn=lambda _s: None)


def _verdicts(result):
    return {check["check"]: check["verdict"] for check in result["checks"]}


# -- Check A: input delta ---------------------------------------------------

@pytest.mark.parametrize("long_input", [9 + 40, 9 + 80, 9 + 240])
def test_input_delta_plausible_inside_range(long_input):
    check = us.check_usage_input_delta(9, long_input)
    assert check["verdict"] == "plausible"
    assert check["delta"] == long_input - 9


@pytest.mark.parametrize("long_input", [9, 9 + 39, 9 + 241])
def test_input_delta_implausible_outside_range(long_input):
    check = us.check_usage_input_delta(9, long_input)
    assert check["verdict"] == "implausible"
    assert "outside 40..240" in check["note"]


# -- Check B: output cap ----------------------------------------------------

@pytest.mark.parametrize("output_tokens", [3, 16, 20])
def test_output_cap_plausible_at_or_below_limit(output_tokens):
    check = us.check_usage_output_cap(output_tokens)
    assert check["verdict"] == "plausible"
    assert check["limit"] == 20


@pytest.mark.parametrize("output_tokens", [21, 64])
def test_output_cap_implausible_above_limit(output_tokens):
    check = us.check_usage_output_cap(output_tokens)
    assert check["verdict"] == "implausible"
    assert "above 20" in check["note"]


# -- Check C: count_tokens reconciliation -----------------------------------

@pytest.mark.parametrize("counted", [8, 10, 12])
def test_count_tokens_plausible_within_tolerance(counted):
    check = us.check_usage_count_tokens(
        10, _count(200, json.dumps({"input_tokens": counted})))
    assert check["verdict"] == "plausible"
    assert check["difference"] == 10 - counted


def test_count_tokens_implausible_beyond_tolerance():
    check = us.check_usage_count_tokens(40, _count(200, '{"input_tokens": 10}'))
    assert check["verdict"] == "implausible"
    assert check["difference"] == 30


@pytest.mark.parametrize("response, note_part", [
    (_count(404, '{"error": "not found"}'), "HTTP 404"),
    (_count(400, '{"error": "bad request"}'), "HTTP 400"),
    (_count(200, "<html>relay home</html>"), "without an integer"),
    (_count(200, '{"tokens": 9}'), "without an integer"),
    (_count(0, "", error="ConnectError: refused"), "request failed"),
])
def test_count_tokens_unsupported_answers_are_inconclusive(response, note_part):
    check = us.check_usage_count_tokens(10, response)
    assert check["verdict"] == "inconclusive"
    assert note_part in check["note"]


# -- Verdict composition ----------------------------------------------------

@pytest.mark.parametrize("verdicts, expected", [
    (["plausible", "plausible", "plausible"], "plausible"),
    (["plausible", "inconclusive", "inconclusive"], "plausible"),
    (["plausible", "implausible", "plausible"], "implausible"),
    (["implausible", "inconclusive", "inconclusive"], "implausible"),
    (["inconclusive", "inconclusive", "inconclusive"], "inconclusive"),
    ([], "inconclusive"),
])
def test_combine_usage_verdicts(verdicts, expected):
    assert us.combine_usage_verdicts(verdicts) == expected


# -- Runner -----------------------------------------------------------------

def test_runner_request_shapes_and_no_sampling_params():
    client = FakeClient(_ok(89, 16), _count(200, '{"input_tokens": 9}'))
    result = _run(client, _ok(9, 5))

    assert result["verdict"] == "plausible"
    assert _verdicts(result) == {"input_delta": "plausible",
                                 "output_cap": "plausible",
                                 "count_tokens": "plausible"}
    assert result["requests_sent"] == 2
    (long_call,) = client.calls
    assert long_call == {"messages": [{"role": "user", "content": LONG_PROMPT}],
                         "system": None, "max_tokens": 16}
    (raw,) = client.raw_calls
    assert (raw["method"], raw["path"]) == ("POST", "/v1/messages/count_tokens")
    assert raw["headers"]["anthropic-version"] == "2023-06-01"
    body = json.loads(raw["body"].decode("utf-8"))
    assert body == {"model": "claude-test",
                    "messages": [{"role": "user", "content": "Say hi"}]}


def test_runner_count_tokens_404_keeps_overall_plausible():
    client = FakeClient(_ok(89, 16), _count(404, "not found"))
    result = _run(client, _ok(9, 5))
    assert _verdicts(result)["count_tokens"] == "inconclusive"
    assert result["verdict"] == "plausible"


def test_runner_any_implausible_check_wins():
    client = FakeClient(_ok(89, 16), _count(200, '{"input_tokens": 9}'))
    result = _run(client, _ok(9, 5) | {"raw": {"usage": {
        "input_tokens": 60, "output_tokens": 5}}})
    assert _verdicts(result)["input_delta"] == "implausible"
    assert _verdicts(result)["count_tokens"] == "implausible"
    assert result["verdict"] == "implausible"


def test_runner_request_error_is_inconclusive():
    client = FakeClient({"error": "HTTP 500: upstream exploded", "time": 0.1},
                        detected_format="openai")
    result = _run(client, _ok(9, 5, fmt="openai"))
    assert set(_verdicts(result).values()) == {"inconclusive"}
    assert result["verdict"] == "inconclusive"
    assert result["requests_sent"] == 1
    assert client.raw_calls == []
    notes = " ".join(check["note"] for check in result["checks"])
    assert "long-prompt request failed: HTTP 500" in notes
    assert "Anthropic-format only" in notes


@pytest.mark.parametrize("baseline", [
    {"error": "HTTP 503: gate", "time": 0.1},
    {"text": "hi", "input_tokens": 0, "output_tokens": 0, "raw": {"id": "m"}},
    None,
])
def test_runner_unusable_baseline_sends_nothing(baseline):
    client = FakeClient(_ok(89, 16), _count(200, '{"input_tokens": 9}'))
    result = _run(client, baseline)
    assert result["verdict"] == "inconclusive"
    assert result["requests_sent"] == 0
    assert client.calls == [] and client.raw_calls == []
    assert all(check["note"].startswith("not sent") for check in result["checks"])


def test_runner_missing_usage_on_long_reply_is_inconclusive():
    usage_less = {"text": "hi", "input_tokens": 0, "output_tokens": 0,
                  "raw": {"id": "chatcmpl-x"}}
    client = FakeClient(usage_less, detected_format="openai")
    result = _run(client, _ok(9, 5, fmt="openai"))
    assert result["verdict"] == "inconclusive"
    assert "usage field missing" in result["checks"][0]["note"]
    assert "usage field missing" in result["checks"][1]["note"]


def test_runner_never_raises_on_broken_client():
    client = FakeClient(_ok(89, 16))
    client.call = MagicMock(side_effect=RuntimeError("boom"))
    client.raw_request = MagicMock(side_effect=RuntimeError("boom"))
    result = _run(client, _ok(9, 5))
    assert result["verdict"] == "inconclusive"
    assert result["requests_sent"] == 2


# -- Step 3 rendering and wiring (both distributions) -----------------------

def _step3_client(count_body):
    # expected 10 / 20 / 15 in Step 3; these readings stay below them
    step3 = [_ok(9, 5), _ok(15, 5), _ok(11, 5)]
    return FakeClient(_ok(89, 16), _count(200, count_body), step3_results=step3)


@pytest.mark.parametrize("count_body, verdict", [
    ('{"input_tokens": 9}', "plausible"),
    ('{"input_tokens": 40}', "implausible"),
])
def test_step3_renders_usage_sanity_without_flags(audit_module, monkeypatch,
                                                  count_body, verdict):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    reporter = audit_module.Reporter()
    client = _step3_client(count_body)

    result = audit_module.test_token_injection(client, reporter)

    assert result == 0
    assert reporter.summary == [("green", "No token injection detected")]
    text = "".join(reporter.sections)
    heading = "### Token usage sanity (informational)"
    assert heading in text
    assert text.index(heading) > text.index("No token injection detected")
    assert f"| Observed usage sanity | {verdict} | not scored |" in text
    assert "Extra requests sent by this subsection: 2." in text
    assert len(client.calls) == 4 and len(client.raw_calls) == 1


def test_step3_skip_sends_no_extra_requests(audit_module, monkeypatch):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    reporter = audit_module.Reporter()
    client = _step3_client('{"input_tokens": 9}')

    result = audit_module.test_token_injection(client, reporter, False)

    assert result == 0
    assert len(client.calls) == 3 and client.raw_calls == []
    assert "Skipped by `--skip-usage-sanity`" in "".join(reporter.sections)
    assert reporter.summary == [("green", "No token injection detected")]


@pytest.mark.parametrize("extra, expected", [
    ((), True),
    (("--skip-usage-sanity",), False),
])
def test_cli_skip_flag_reaches_step3(audit_module, monkeypatch, capsys,
                                     extra, expected):
    from tests.test_json_report import _argv, _stub_audit

    _stub_audit(audit_module, monkeypatch)
    seen = []

    def fake_step3(*args):
        seen.append(args)
        return 0

    monkeypatch.setattr(audit_module, "test_token_injection", fake_step3)
    _argv(monkeypatch, "--format", "json", *extra)
    assert audit_module.main() == 0
    capsys.readouterr()
    assert len(seen) == 1
    assert seen[0][2] is expected


def test_standalone_usage_constants_match_modular(monkeypatch):
    standalone = _load(REPO_ROOT / "audit.py", "usage_sanity_consts", monkeypatch)
    for name in (
        "USAGE_BASELINE_PROMPT", "USAGE_PAYLOAD_WORD", "USAGE_PAYLOAD_REPEATS",
        "USAGE_DELTA_MIN", "USAGE_DELTA_MAX", "USAGE_OUTPUT_MAX_TOKENS",
        "USAGE_OUTPUT_TOLERANCE", "USAGE_COUNT_TOKENS_TOLERANCE",
        "USAGE_COUNT_TOKENS_PATH",
    ):
        assert getattr(standalone, name) == getattr(us, name), name
    assert (us.USAGE_DELTA_MIN, us.USAGE_DELTA_MAX) == (40, 240)
    assert us.USAGE_OUTPUT_TOLERANCE == 4
