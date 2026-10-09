"""Public JSON report behavior for the modular and standalone distributions."""

import importlib.util
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = "https://relay.example.com/v1"
MODEL = "claude-test"
SECRET = "sk-synthetic-json-report-secret"


@pytest.fixture(params=["modular", "standalone"])
def audit_module(request, monkeypatch):
    path = REPO_ROOT / ("scripts/audit.py" if request.param == "modular" else "audit.py")
    name = f"json_report_{request.param}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def _argv(monkeypatch, *options):
    monkeypatch.setattr(sys, "argv", [
        "audit.py", "--key", SECRET, "--url", TARGET, "--model", MODEL,
        *options,
    ])


def _assert_utc_timestamp(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert timestamp.utcoffset() == timedelta(0)


class FakeClient:
    """Keep CLI tests offline and retain a secret that must not be serialized."""

    def __init__(self, base_url, api_key, model, timeout=120):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def set_transparent_logger(self, logger):
        pass

    def raw_request(self, *args, **kwargs):
        raise AssertionError("unexpected network probe")


STEP_RESULTS = {
    "test_infrastructure": None,
    "test_models": [],
    "test_token_injection": 0,
    "test_prompt_extraction": False,
    "test_instruction_conflict": False,
    "test_jailbreak": None,
    "test_context_length": None,
    "test_tool_substitution": (False, False),
    "test_error_leakage": ("none", False),
    "test_stream_integrity": ("clean", False),
    "test_web3_injection": ("clean", False),
    "test_infra_fingerprint": (None, "unknown"),
    "test_latency_variance": None,
    "test_channel_classifier": None,
}


def _stub_audit(module, monkeypatch, results=None, crash_step=None):
    values = {**STEP_RESULTS, **(results or {})}
    called = []
    monkeypatch.setattr(module, "APIClient", FakeClient)
    monkeypatch.setattr(module, "_tool_version", lambda: "2.4.1")
    monkeypatch.setattr(module, "_tool_commit_from_checkout", lambda: "abc123456789")

    def make_step(name, result):
        def step(*args, **kwargs):
            called.append(name)
            print(f"synthetic progress: {name}")
            if name == crash_step:
                raise RuntimeError("synthetic step crash")
            if name == "test_models":
                report = next(arg for arg in args if isinstance(arg, module.Reporter))
                report.p("中文测试结果")
                report.flag("green", "模型列表成功")
            return result
        return step

    for name, result in values.items():
        monkeypatch.setattr(module, name, make_step(name, result))
    monkeypatch.setattr(module, "run_warmup", make_step("run_warmup", None))
    return called


def test_reporter_exports_metadata_flags_and_authoritative_risk(audit_module):
    report = audit_module.Reporter()
    report.p("中文结果")
    report.flag("red", "模型列表中存在未知模型")
    coverage = {"skipped_steps": [], "risk_matrix_inconclusive_steps": [], "crashed_steps": []}

    result = report.to_dict(
        target_url=TARGET, model=MODEL, tool_version="v2.4.1", profile="full",
        tool_commit="abc123456789", risk_level="LOW", coverage=coverage,
    )

    assert result["schema_version"] == 1
    assert result["report_type"] == "audit"
    _assert_utc_timestamp(result["generated_at"])
    assert result["target"] == TARGET
    assert result["model"] == MODEL
    assert result["tool_version"] == "v2.4.1"
    assert result["profile"] == "full"
    assert result["tool_commit"] == "abc123456789"
    assert result["risk_level"] == "LOW"
    assert result["flags"] == [{"level": "red", "message": "模型列表中存在未知模型"}]
    assert result["coverage"] == coverage
    assert "# API Relay Security Audit Report" in result["markdown"]
    assert "中文结果" in result["markdown"]
    assert f'**Generated**: {result["generated_at"]}' in result["markdown"]
    assert "**Tool Commit**: `abc123456789`" in result["markdown"]
    assert json.loads(json.dumps(result, ensure_ascii=False)) == result


def test_unrated_report_does_not_infer_risk_from_flags(audit_module):
    report = audit_module.Reporter()
    report.flag("red", "informational finding")
    result = report.to_dict()
    assert result["risk_level"] is None
    assert result["coverage"] is None


def test_json_preserves_inconclusive_prompt_extraction_evidence(
    audit_module, monkeypatch, capsys,
):
    real_step = audit_module.test_prompt_extraction
    _stub_audit(audit_module, monkeypatch)

    class WeakResponseClient(FakeClient):
        def call(self, messages, max_tokens):
            return {"text": "coding", "input_tokens": 0, "output_tokens": 0}

    monkeypatch.setattr(audit_module, "APIClient", WeakResponseClient)
    monkeypatch.setattr(audit_module, "test_prompt_extraction", real_step)
    monkeypatch.setattr(audit_module.time, "sleep", lambda _: None)
    _argv(monkeypatch, "--format", "json")

    assert audit_module.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["risk_level"] == "LOW"
    assert result["coverage"]["risk_matrix_inconclusive_steps"] == []
    assert any(flag["level"] == "yellow" and "INCONCLUSIVE" in flag["message"]
               for flag in result["flags"])
    assert not any(flag["level"] == "red" for flag in result["flags"])
    assert "INCONCLUSIVE" in result["markdown"]
    assert "Hidden prompt content extracted" not in result["markdown"]


def test_reporter_preserves_supplied_markdown(audit_module):
    result = audit_module.Reporter().to_dict(
        report_type="connectivity", markdown="# 自定义连通性报告\n",
    )
    assert result["report_type"] == "connectivity"
    assert result["markdown"] == "# 自定义连通性报告\n"
    assert result["risk_level"] is None


def test_cli_format_defaults_and_choices(audit_module, monkeypatch, capsys):
    _argv(monkeypatch)
    assert audit_module.parse_args().format == "markdown"
    for value in ("markdown", "json"):
        _argv(monkeypatch, "--format", value)
        assert audit_module.parse_args().format == value
    _argv(monkeypatch, "--format", "yaml")
    with pytest.raises(SystemExit) as failure:
        audit_module.parse_args()
    assert failure.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("results", "crash_step", "expected_risk", "inconclusive_step"),
    [
        ({}, None, "LOW", None),
        ({"test_token_injection": 101}, None, "MEDIUM", None),
        ({"test_instruction_conflict": True}, None, "MEDIUM", None),
        ({"test_token_injection": 101, "test_instruction_conflict": True}, None, "HIGH", None),
        ({"test_tool_substitution": (True, False)}, None, "HIGH", None),
        ({"test_error_leakage": ("critical", False)}, None, "HIGH", None),
        ({"test_error_leakage": ("high", False)}, None, "HIGH", None),
        ({"test_error_leakage": ("medium", False)}, None, "MEDIUM", None),
        ({"test_stream_integrity": ("anomaly", False)}, None, "HIGH", None),
        ({"test_web3_injection": ("anomaly", False)}, None, "HIGH", None),
        ({"test_token_injection": None}, None, "MEDIUM", "Step 3 token injection"),
        ({"test_instruction_conflict": None}, None, "MEDIUM", "Step 5 instruction override"),
        ({"test_tool_substitution": (False, True)}, None, "MEDIUM", "Step 8 tool substitution"),
        ({"test_error_leakage": ("none", True)}, None, "MEDIUM", "Step 9 error leakage"),
        ({"test_stream_integrity": ("clean", True)}, None, "MEDIUM", "Step 10 stream integrity"),
        ({"test_web3_injection": ("clean", True)}, None, "MEDIUM", "Step 11 web3 injection"),
        ({}, "test_models", "MEDIUM", None),
    ],
    ids=[
        "clean", "injection", "override", "injection-and-override", "tool-substitution",
        "critical-leak", "high-leak", "medium-leak", "stream-anomaly", "web3-anomaly",
        "injection-inconclusive", "override-inconclusive", "tool-inconclusive",
        "leak-inconclusive", "stream-inconclusive", "web3-inconclusive", "step-crash",
    ],
)
def test_json_stdout_matches_rating_and_coverage(
    audit_module, monkeypatch, capsys, results, crash_step, expected_risk, inconclusive_step,
):
    _stub_audit(audit_module, monkeypatch, results, crash_step)
    _argv(monkeypatch, "--format", "json", "--profile", "full", "--warmup", "1")
    assert audit_module.main() == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["schema_version"] == 1
    assert result["report_type"] == "audit"
    assert f'**Generated**: {result["generated_at"]}' in result["markdown"]
    assert result["risk_level"] == expected_risk
    assert f"### {expected_risk} RISK" in result["markdown"]
    assert result["target"] == TARGET
    assert result["model"] == MODEL
    assert result["tool_version"] == "v2.4.1"
    assert result["profile"] == "full"
    assert result["tool_commit"] == "abc123456789"
    assert result["coverage"]["skipped_steps"] == []
    if inconclusive_step:
        assert inconclusive_step in result["coverage"]["risk_matrix_inconclusive_steps"]
    else:
        assert result["coverage"]["risk_matrix_inconclusive_steps"] == []
    expected_crashes = ["Step 2 model list"] if crash_step else []
    assert result["coverage"]["crashed_steps"] == expected_crashes
    assert "synthetic progress: run_warmup" in captured.err
    assert "Audit complete" in captured.err
    assert SECRET not in captured.out


def test_json_output_file_is_utf8_and_stdout_stays_empty(
    audit_module, monkeypatch, capsys, tmp_path,
):
    _stub_audit(audit_module, monkeypatch)
    output = tmp_path / "nested" / "report.json"
    _argv(monkeypatch, "--format", "json", "--output", str(output))
    assert audit_module.main() == 0
    captured = capsys.readouterr()
    contents = output.read_text(encoding="utf-8")
    result = json.loads(contents)
    assert "中文测试结果" in contents
    assert result["risk_level"] == "LOW"
    assert result["coverage"]["skipped_steps"] == ["Step 11 web3 injection"]
    assert captured.out == ""
    assert "Report saved" in captured.err


def test_json_records_skipped_checks_without_running_them(
    audit_module, monkeypatch, capsys,
):
    called = _stub_audit(audit_module, monkeypatch)
    _argv(
        monkeypatch, "--format", "json", "--profile", "full", "--skip-infra",
        "--skip-context", "--skip-tool-substitution", "--skip-error-leakage",
        "--skip-stream-integrity", "--skip-web3-injection", "--skip-infra-fingerprint",
        "--skip-latency-variance", "--skip-channel-classifier",
    )
    assert audit_module.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["coverage"] == {
        "skipped_steps": [
            "Step 1 infrastructure", "Step 7 context length", "Step 8 tool substitution",
            "Step 9 error leakage", "Step 10 stream integrity", "Step 11 web3 injection",
            "Step 12 infra fingerprint", "Step 13 latency variance", "Step 14 channel classifier",
        ],
        "risk_matrix_inconclusive_steps": [],
        "crashed_steps": [],
    }
    assert set(called) == {
        "test_models", "test_token_injection", "test_prompt_extraction",
        "test_instruction_conflict", "test_jailbreak",
    }
    assert result["risk_level"] == "LOW"


def test_default_markdown_output_remains_available(audit_module, monkeypatch, capsys):
    _stub_audit(audit_module, monkeypatch)
    _argv(monkeypatch)
    assert audit_module.main() == 0
    captured = capsys.readouterr()
    assert "# API Relay Security Audit Report" in captured.out
    assert "### LOW RISK" in captured.out
    assert "Audit complete" in captured.out


@pytest.mark.parametrize("success", [True, False], ids=["reachable", "failed"])
def test_connectivity_json_is_unrated_and_redacts_secrets(
    audit_module, monkeypatch, capsys, success,
):
    class ConnectivityClient(FakeClient):
        def raw_request(self, method, path, headers, body, content_type, timeout):
            if success and path == "/v1/messages":
                return {
                    "status": 200, "headers": {}, "error": None,
                    "body": json.dumps({
                        "content": [{"type": "text", "text": f"ok {self.api_key}"}],
                        "usage": {"input_tokens": 8, "output_tokens": 1},
                    }),
                }
            return {
                "status": 0, "headers": {}, "body": "",
                "error": f"transport failed with {self.api_key}",
            }

    def forbidden(*args, **kwargs):
        raise AssertionError("connectivity must not run security audit steps")

    monkeypatch.setattr(audit_module, "APIClient", ConnectivityClient)
    for name in ["run_warmup", *STEP_RESULTS]:
        monkeypatch.setattr(audit_module, name, forbidden)
    _argv(monkeypatch, "--format", "json", "--connectivity", "--warmup", "1")
    assert audit_module.main() == (0 if success else 1)
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["schema_version"] == 1
    assert result["report_type"] == "connectivity"
    assert result["risk_level"] is None
    assert result["coverage"] is None
    connectivity = result["connectivity"]
    assert connectivity["success"] is success
    assert connectivity["verdict"] == ("WARNING" if success else "FAILED")
    assert connectivity["successful_formats"] == (["Anthropic Chat"] if success else [])
    assert len(connectivity["probes"]) == 2
    assert all(isinstance(probe, dict) for probe in connectivity["probes"])
    assert connectivity["probes"][0]["success"] is success
    assert "API Relay Connectivity Report" in result["markdown"]
    assert "[redacted-api-key]" in captured.out
    assert SECRET not in captured.out + captured.err
    assert "client" not in connectivity
    assert "api_key" not in connectivity
