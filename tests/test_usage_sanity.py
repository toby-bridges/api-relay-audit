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
    stop = ({"stop_reason": "end_turn"} if fmt == "anthropic"
            else {"choices": [{"finish_reason": "stop"}]})
    return {"text": "hi", "input_tokens": input_tokens,
            "output_tokens": output_tokens, "raw": {"usage": usage, **stop},
            "time": 0.01}


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
    check = us.check_usage_output_cap(output_tokens, stop_reason="max_tokens")
    assert check["verdict"] == "plausible"
    assert check["limit"] == 20


@pytest.mark.parametrize("output_tokens", [21, 64])
def test_output_cap_implausible_above_limit(output_tokens):
    check = us.check_usage_output_cap(output_tokens, stop_reason="max_tokens")
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
    (_count(200, "<html>relay home</html>"), "without input_tokens"),
    (_count(200, '{"tokens": 9}'), "without input_tokens"),
    (_count(200, '{"input_tokens": 9.0}'), "not an integer"),
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


# -- Rework: redaction, injection decoupling, readings, thinking, cache -----

FAKE_SECRET = "sk-ant-api03-" + "Z" * 32


def _raw(usage, **raw_extra):
    raw = {"usage": usage, **raw_extra}
    if "stop_reason" not in raw and "choices" not in raw:
        raw["stop_reason"] = "end_turn"
    return {"text": "hi", "input_tokens": 0, "output_tokens": 0,
            "raw": raw, "time": 0.01}


@pytest.mark.parametrize("error_text", [
    'HTTP 500: {"error": {"message": "upstream rejected ' + FAKE_SECRET + '"}}',
    "ConnectError: tunnel refused " + FAKE_SECRET + " for sk-usage-sanity-test",
])
def test_long_request_error_body_never_reaches_report(audit_module, monkeypatch,
                                                      error_text):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    reporter = audit_module.Reporter()
    client = FakeClient({"error": error_text, "time": 0.1},
                        _count(200, '{"input_tokens": 9}'),
                        step3_results=[_ok(9, 5), _ok(15, 5), _ok(11, 5)])

    assert audit_module.test_token_injection(client, reporter) == 0

    text = "".join(reporter.sections)
    assert "### Token usage sanity (informational)" in text
    assert FAKE_SECRET not in text
    assert "sk-usage-sanity-test" not in text
    assert "upstream rejected" not in text
    assert "long-prompt request failed:" in text


def test_count_tokens_transport_error_is_redacted():
    check = us.check_usage_count_tokens(
        10, _count(0, "", error="ConnectError: " + FAKE_SECRET), api_key="sk-x")
    assert check["verdict"] == "inconclusive"
    assert FAKE_SECRET not in check["note"]
    assert "<REDACTED_SECRET>" in check["note"]


@pytest.mark.parametrize("injection_size, sent", [
    (None, True), (0, True), (20, True), (21, False), (140, False),
])
def test_count_tokens_skipped_when_step3_reports_injection(injection_size, sent):
    client = FakeClient(_ok(89, 16), _count(200, '{"input_tokens": 9}'))
    result = us.run_usage_sanity(client, _ok(9, 5), injection_size,
                                 sleep_fn=lambda _s: None)
    count = result["checks"][2]
    if sent:
        assert len(client.raw_calls) == 1
        assert count["verdict"] == "plausible"
    else:
        assert client.raw_calls == []
        assert count["verdict"] == "inconclusive"
        assert "count_tokens cannot see injected content" in count["note"]
        assert result["requests_sent"] == 1


def test_step3_injection_path_keeps_flag_and_skips_count_tokens(audit_module,
                                                               monkeypatch):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    reporter = audit_module.Reporter()
    # Step 3 expects 10 / 20 / 15, so every probe reads ~140 tokens high.
    client = FakeClient(_ok(230, 16), _count(200, '{"input_tokens": 9}'),
                        step3_results=[_ok(150, 5), _ok(160, 5), _ok(155, 5)])

    assert audit_module.test_token_injection(client, reporter) == 140

    assert reporter.summary == [
        ("red", "Hidden system prompt injection detected (~140 tokens/request)")]
    assert client.raw_calls == []
    text = "".join(reporter.sections)
    assert "count_tokens cannot see injected content" in text
    assert "| A. Input delta (long - short input_tokens) | +80" in text


@pytest.mark.parametrize("baseline, long_result, count_body, expected, note_part", [
    (_ok(-5, 5), _ok(75, -7), '{"input_tokens": 9}',
     ("implausible", "implausible", "implausible"), "negative"),
    (_ok(0, 0), _ok(0, 0), '{"input_tokens": 9}',
     ("implausible", "plausible", "implausible"), "outside 40..240"),
    (_ok(9, 5), _raw({"input_tokens": True, "output_tokens": 16}),
     '{"input_tokens": 9}',
     ("inconclusive", "plausible", "plausible"), "not an integer"),
    (_raw({"input_tokens": 9.0, "output_tokens": 5}), _ok(89, 16),
     '{"input_tokens": 9}',
     ("inconclusive", "inconclusive", "inconclusive"), "not an integer"),
    (_ok(9, 5), _ok(89, 16), '{"input_tokens": "12"}',
     ("plausible", "plausible", "inconclusive"), "not an integer"),
], ids=["negative", "zero", "bool-true", "float", "string"])
def test_odd_readings_are_pinned(baseline, long_result, count_body, expected,
                                 note_part):
    client = FakeClient(long_result, _count(200, count_body))
    result = _run(client, baseline)
    assert tuple(check["verdict"] for check in result["checks"]) == expected
    assert note_part in " ".join(check["note"] or "" for check in result["checks"])


@pytest.mark.parametrize("raw_extra, usage_extra, verdict, note_part", [
    ({"stop_reason": "max_tokens"}, {}, "plausible", None),
    ({"stop_reason": "refusal"}, {}, "inconclusive", "neither a natural stop"),
    ({"choices": [{"finish_reason": "length"}]},
     {"completion_tokens_details": {"reasoning_tokens": 0}}, "plausible", None),
    ({"choices": [{"finish_reason": "stop"}]},
     {"completion_tokens_details": {"reasoning_tokens": 12}}, "inconclusive",
     "completion_tokens_details.reasoning_tokens=12"),
    ({}, {"thinking_tokens": 7}, "inconclusive", "thinking_tokens=7"),
], ids=["max-tokens", "refusal", "reasoning-zero", "reasoning-12", "thinking"])
def test_output_cap_inconclusive_on_thinking_or_odd_stop(raw_extra, usage_extra,
                                                         verdict, note_part):
    long_result = _raw({"input_tokens": 89, "output_tokens": 16, **usage_extra},
                       **raw_extra)
    client = FakeClient(long_result, _count(200, '{"input_tokens": 9}'))
    cap = _run(client, _ok(9, 5))["checks"][1]
    assert cap["verdict"] == verdict
    if note_part:
        assert note_part in cap["note"]


@pytest.mark.parametrize("where", ["baseline", "long", "zero"])
def test_prompt_caching_makes_input_checks_inconclusive(where):
    baseline = _ok(9, 5)
    long_result = _ok(89, 16)
    if where == "baseline":
        baseline = _raw({"input_tokens": 9, "output_tokens": 5,
                         "cache_read_input_tokens": 4096})
    elif where == "long":
        long_result = _raw({"input_tokens": 89, "output_tokens": 16,
                            "cache_creation_input_tokens": 3})
    else:
        baseline = _raw({"input_tokens": 9, "output_tokens": 5,
                         "cache_read_input_tokens": 0,
                         "cache_creation_input_tokens": 0})
    client = FakeClient(long_result, _count(200, '{"input_tokens": 9}'))
    delta, cap, count = _run(client, baseline)["checks"]

    assert cap["verdict"] == "plausible"
    if where == "zero":
        assert (delta["verdict"], count["verdict"]) == ("plausible", "plausible")
        return
    assert delta["verdict"] == "inconclusive"
    assert "prompt caching" in delta["note"]
    if where == "baseline":
        assert count["verdict"] == "inconclusive"
        assert "prompt caching" in count["note"]
        assert client.raw_calls == []
    else:
        assert count["verdict"] == "plausible"
        assert len(client.raw_calls) == 1


def test_real_client_count_tokens_url_and_headers(monkeypatch):
    from api_relay_audit import _transport
    from api_relay_audit.client import APIClient

    posts, raws = [], []

    def fake_post(url, headers, body, timeout, httpx_module=None):
        posts.append(url)
        long = body["messages"][0]["content"] != "Say hi"
        return {"content": [{"type": "text", "text": "Hi"}],
                "usage": {"input_tokens": 89 if long else 9,
                          "output_tokens": 16 if long else 5},
                "stop_reason": "max_tokens" if long else "end_turn"}

    def fake_raw(method, url, headers, body, content_type, timeout,
                 httpx_module=None):
        raws.append({"method": method, "url": url, "headers": headers,
                     "body": body, "content_type": content_type})
        return {"status": 200, "headers": {}, "body": '{"input_tokens": 9}',
                "error": None}

    monkeypatch.setattr(_transport, "httpx_post_json", fake_post)
    monkeypatch.setattr(_transport, "httpx_raw_request", fake_raw)
    client = APIClient("https://x/v1", "sk-real-client-test-key", "claude-test",
                       verbose=False)
    baseline = client.call([{"role": "user", "content": "Say hi"}], max_tokens=100)
    assert client.detected_format == "anthropic"

    result = us.run_usage_sanity(client, baseline, 0, sleep_fn=lambda _s: None)

    assert result["verdict"] == "plausible"
    assert result["requests_sent"] == 2
    assert posts == ["https://x/v1/messages", "https://x/v1/messages"]
    (raw,) = raws
    assert raw["method"] == "POST"
    assert raw["url"] == "https://x/v1/messages/count_tokens"
    assert raw["headers"]["x-api-key"] == "sk-real-client-test-key"
    assert raw["headers"]["anthropic-version"] == "2023-06-01"
    assert raw["content_type"] == "application/json"
    assert json.loads(raw["body"]) == {
        "model": "claude-test",
        "messages": [{"role": "user", "content": "Say hi"}]}


def test_runner_openai_positive_path():
    client = FakeClient(_ok(89, 16, fmt="openai"), detected_format="openai")
    result = _run(client, _ok(9, 5, fmt="openai"))
    assert _verdicts(result) == {"input_delta": "plausible",
                                 "output_cap": "plausible",
                                 "count_tokens": "inconclusive"}
    assert result["verdict"] == "plausible"
    assert result["requests_sent"] == 1
    assert client.raw_calls == []


def test_step3_all_errors_keeps_result_and_flag(audit_module, monkeypatch):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    reporter = audit_module.Reporter()
    err = {"error": "HTTP 503: no available accounts", "time": 0.1}
    client = FakeClient(_ok(89, 16), _count(200, '{"input_tokens": 9}'),
                        step3_results=[err, err, err])

    assert audit_module.test_token_injection(client, reporter) is None

    assert len(reporter.summary) == 1
    level, message = reporter.summary[0]
    assert level == "yellow" and "Token injection test INCONCLUSIVE" in message
    assert len(client.calls) == 3 and client.raw_calls == []
    text = "".join(reporter.sections)
    assert "### Token usage sanity (informational)" in text
    assert "not sent" in text
    assert "| Observed usage sanity | inconclusive |" in text


def test_report_usage_sanity_exception_branch(audit_module, monkeypatch):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    monkeypatch.setattr(audit_module, "run_usage_sanity",
                        lambda *args, **kwargs: {"verdict": "plausible"})
    reporter = audit_module.Reporter()

    result = audit_module.test_token_injection(
        _step3_client('{"input_tokens": 9}'), reporter)

    assert result == 0
    assert reporter.summary == [("green", "No token injection detected")]
    assert ("Usage sanity could not be evaluated (KeyError)"
            in "".join(reporter.sections))


def test_step3_call_site_guard_contains_render_crash(audit_module, monkeypatch):
    monkeypatch.setattr(audit_module, "time", MagicMock())

    def boom(*args, **kwargs):
        raise RuntimeError("renderer exploded")

    monkeypatch.setattr(audit_module, "_report_usage_sanity", boom)
    reporter = audit_module.Reporter()

    result = audit_module.test_token_injection(
        _step3_client('{"input_tokens": 9}'), reporter)

    assert result == 0
    assert reporter.summary == [("green", "No token injection detected")]


# -- Round 2: missing stop reason, relay key names ---------------------------

@pytest.mark.parametrize("raw_extra", [{"stop_reason": None}, {"choices": [{}]}],
                         ids=["anthropic", "openai"])
def test_output_cap_inconclusive_when_stop_reason_missing(raw_extra):
    long_result = _raw({"input_tokens": 89, "output_tokens": 16}, **raw_extra)
    client = FakeClient(long_result, _count(200, '{"input_tokens": 9}'))
    cap = _run(client, _ok(9, 5))["checks"][1]
    assert cap["verdict"] == "inconclusive"
    assert cap["note"] == "stop reason missing"


def test_relay_usage_key_names_cannot_inject_markdown(audit_module, monkeypatch):
    monkeypatch.setattr(audit_module, "time", MagicMock())
    evil = "reasoning_tokens\n# FAKE HEADING\n| x | y |"
    long_result = _raw({"input_tokens": 89, "output_tokens": 16, evil: 3,
                        "completion_tokens_details": {evil: 12}})
    client = FakeClient(long_result, _count(200, '{"input_tokens": 9}'),
                        step3_results=[_ok(9, 5), _ok(15, 5), _ok(11, 5)])
    reporter = audit_module.Reporter()

    assert audit_module.test_token_injection(client, reporter) == 0

    lines = "".join(reporter.sections).splitlines()
    assert not any(line.startswith("# FAKE HEADING") for line in lines)
    assert not any(line.startswith("| x |") for line in lines)
    (note_line,) = [line for line in lines if line.startswith("- B: ")]
    assert "FAKE HEADING" in note_line
    assert "|" not in note_line and "\n" not in note_line
