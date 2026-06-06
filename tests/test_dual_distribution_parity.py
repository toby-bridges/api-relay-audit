"""Dual-distribution invariant regression tests.

The repo ships two parallel versions of the audit tool:

    - ``scripts/audit.py`` (modular, uses ``api_relay_audit/*.py``)
    - ``audit.py`` at repo root (standalone, zero-dep, curl-only)

The root ``audit.py`` is a generated artifact. The primary invariant is
therefore no longer "hand-edit two files identically"; it is "the committed
artifact must be exactly what scripts/build-standalone.py generates", plus
focused behavior/constant regression tests for public standalone semantics.
"""

import ast
import sys
import re
import subprocess
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_standalone_artifact_generated_from_sources():
    """The committed root audit.py must be exactly generator output."""
    subprocess.run(
        [sys.executable, "scripts/build-standalone.py", "--check"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )


def test_standalone_has_no_package_or_httpx_runtime_imports():
    """curl-download users must not need api_relay_audit/ or httpx installed."""
    tree = ast.parse((REPO_ROOT / "audit.py").read_text(encoding="utf-8"))
    forbidden = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "httpx" or alias.name.startswith("api_relay_audit"):
                    forbidden.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "httpx" or module.startswith("api_relay_audit"):
                forbidden.append((node.lineno, module))

    assert not forbidden, (
        "Generated standalone audit.py must not import modular package "
        f"or httpx at runtime; found {forbidden}"
    )


def _load_standalone_audit():
    """Load the standalone audit.py as a module so tests can assert against
    its internal constants and helpers."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_standalone_audit_for_parity",
        REPO_ROOT / "audit.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_identity_keywords_standalone_parity():
    """Regression (v1.7.6): the non-Claude identity keyword tuple and the
    strict-keyword frozenset in the standalone audit.py must match the
    modular api_relay_audit/identity_patterns.py. Protects against drift
    on the identity-detection block, which is dual-distributed but not
    covered by the risk-matrix parity test above.
    """
    from api_relay_audit.identity_patterns import (
        NON_CLAUDE_IDENTITY_KEYWORDS as MODULAR_KEYWORDS,
    )
    from api_relay_audit.identity_patterns import (
        _STRICT_ASCII_KEYWORDS as MODULAR_STRICT,
    )

    standalone = _load_standalone_audit()

    assert standalone.NON_CLAUDE_IDENTITY_KEYWORDS == MODULAR_KEYWORDS, (
        "Identity keyword tuple drift between api_relay_audit/identity_patterns.py "
        "and standalone audit.py. Update modular source and regenerate audit.py."
    )
    assert standalone._NON_CLAUDE_STRICT_KEYWORDS == MODULAR_STRICT, (
        "Strict-keyword frozenset drift between identity_patterns.py and "
        "standalone audit.py. Update modular source and regenerate audit.py."
    )


def test_warp_windsurf_present_in_standalone():
    """Regression (v1.7.6→v1.7.7): warp + windsurf must be present AND
    context-strict in standalone audit.py (common English words requiring
    anchor + post-keyword identity signal)."""
    standalone = _load_standalone_audit()
    for kw in ("warp", "windsurf"):
        assert kw in standalone.NON_CLAUDE_IDENTITY_KEYWORDS, (
            f"{kw!r} missing from standalone audit.py"
        )
        assert kw in standalone._NON_CLAUDE_CONTEXT_STRICT_KEYWORDS, (
            f"{kw!r} must be context-strict in standalone audit.py"
        )


def test_standalone_find_non_claude_identities_behaves_like_modular():
    """End-to-end parity: identical inputs must yield identical outputs from
    both distributions' identity-matching functions on v1.7.6 probes."""
    from api_relay_audit.identity_patterns import find_non_claude_identities as modular_fn

    standalone = _load_standalone_audit()
    standalone_fn = standalone.find_non_claude_identities

    probes = [
        "I am Warp, a coding assistant.",
        "I'm Windsurf, an AI IDE.",
        "Engage warp speed.",
        "My hobby is windsurf.",
        "I am Claude, made by Anthropic. Tools like Warp and Windsurf are alternatives.",
    ]
    for text in probes:
        assert modular_fn(text) == standalone_fn(text), (
            f"Divergent identity-match output for probe: {text!r}"
        )


# ---------------------------------------------------------------------------
# Step 12 / Step 13 (v1.8) constants parity
# ---------------------------------------------------------------------------

def test_infra_fingerprint_constants_parity():
    """Regression (v1.8, Codex LOW finding 2026-04-18): Step 12
    fingerprinting constants must match between the modular and
    standalone distributions. Changing a signal, a precedence order,
    or the body scan cap on one side without the other would silently
    bifurcate detection behavior.
    """
    from api_relay_audit.infra_fingerprint import (
        FRAMEWORK_SIGNATURES as MODULAR_SIGS,
        INFORMATIVE_HEADERS as MODULAR_HEADERS,
        _BODY_SCAN_LIMIT as MODULAR_LIMIT,
    )

    standalone = _load_standalone_audit()

    assert standalone.FRAMEWORK_SIGNATURES == MODULAR_SIGS, (
        "FRAMEWORK_SIGNATURES drift between api_relay_audit/infra_fingerprint.py "
        "and standalone audit.py. Regenerate audit.py -- signal order "
        "matters (specific frameworks before generic ones)."
    )
    assert standalone.INFORMATIVE_HEADERS == MODULAR_HEADERS, (
        "INFORMATIVE_HEADERS drift between infra_fingerprint.py and standalone "
        "audit.py. These headers are surfaced in the report for 'unknown' "
        "classifications too; divergence leads to asymmetric reports."
    )
    assert standalone._BODY_SCAN_LIMIT == MODULAR_LIMIT, (
        "_BODY_SCAN_LIMIT drift between infra_fingerprint.py and standalone "
        "audit.py. Divergence would change detection on large landing pages."
    )


def test_channel_classifier_constants_parity():
    """Regression (v1.9): Step 14 channel-classifier constants must match
    between the modular and standalone distributions. Adding a new channel
    label, changing a Tier 2 weight, or rearranging TIER2_PRIORITY on one
    side without the other would silently produce different verdicts for
    the same response data depending on which distribution a user installed.
    """
    from api_relay_audit.channel_classifier import (
        TIER1_RULES as MODULAR_TIER1,
        TIER2_PRIORITY as MODULAR_TIER2_PRIORITY,
        TIER2_WEIGHTS as MODULAR_TIER2_WEIGHTS,
        TIER3_RELAY_CONFIDENCE as MODULAR_TIER3_CONFIDENCE,
        TIER3_RELAY_ID_PATTERN as MODULAR_TIER3_PATTERN,
        _CHANNEL_BODY_SCAN_LIMIT as MODULAR_CHANNEL_BODY_LIMIT,
    )

    standalone = _load_standalone_audit()

    assert standalone.TIER1_RULES == MODULAR_TIER1, (
        "TIER1_RULES drift between api_relay_audit/channel_classifier.py "
        "and standalone audit.py. Order matters (first match wins)."
    )
    assert standalone.TIER2_WEIGHTS == MODULAR_TIER2_WEIGHTS, (
        "TIER2_WEIGHTS drift. Weight changes silently shift the score "
        "boundary at which a channel wins; regenerate audit.py."
    )
    assert standalone.TIER2_PRIORITY == MODULAR_TIER2_PRIORITY, (
        "TIER2_PRIORITY drift. The tie-break order determines the "
        "winner when two channels score equally; regenerate audit.py."
    )
    assert standalone.TIER3_RELAY_ID_PATTERN.pattern == MODULAR_TIER3_PATTERN.pattern, (
        "TIER3_RELAY_ID_PATTERN drift between channel_classifier.py and "
        "standalone audit.py. Pattern controls the transparent-relay "
        "inference; regenerate audit.py."
    )
    assert standalone.TIER3_RELAY_CONFIDENCE == MODULAR_TIER3_CONFIDENCE, (
        "TIER3_RELAY_CONFIDENCE drift. The 0.5 confidence is the user-"
        "visible signal strength of the relay-proxy inference."
    )
    assert standalone._CHANNEL_BODY_SCAN_LIMIT == MODULAR_CHANNEL_BODY_LIMIT, (
        "_CHANNEL_BODY_SCAN_LIMIT drift between channel_classifier.py and "
        "standalone audit.py."
    )


def test_latency_variance_constants_parity():
    """Regression (v1.8, Codex LOW finding 2026-04-18): Step 13
    latency-variance thresholds must match between the modular and
    standalone distributions. A one-sided change to BIMODAL_GAP_THRESHOLD
    or the CV cutoffs would silently produce different verdicts for
    the same latency data depending on which distribution a user
    installed.
    """
    from api_relay_audit.latency_variance import (
        BIMODAL_GAP_THRESHOLD as MODULAR_BIMODAL,
        CV_STABLE_CUTOFF as MODULAR_STABLE,
        CV_VARIABLE_CUTOFF as MODULAR_VARIABLE,
        DEFAULT_PROBE_COUNT as MODULAR_PROBE_COUNT,
        LATENCY_PROBE_MAX as MODULAR_PROBE_MAX,
        LATENCY_PROBE_MIN as MODULAR_PROBE_MIN,
    )

    standalone = _load_standalone_audit()

    assert standalone.BIMODAL_GAP_THRESHOLD == MODULAR_BIMODAL, (
        "BIMODAL_GAP_THRESHOLD drift between latency_variance.py and "
        "standalone audit.py."
    )
    assert standalone.CV_STABLE_CUTOFF == MODULAR_STABLE, (
        "CV_STABLE_CUTOFF drift between latency_variance.py and "
        "standalone audit.py."
    )
    assert standalone.CV_VARIABLE_CUTOFF == MODULAR_VARIABLE, (
        "CV_VARIABLE_CUTOFF drift between latency_variance.py and "
        "standalone audit.py."
    )
    assert standalone.DEFAULT_PROBE_COUNT == MODULAR_PROBE_COUNT, (
        "DEFAULT_PROBE_COUNT drift between latency_variance.py and "
        "standalone audit.py."
    )
    # v1.8.1 Codex review #5 fix: --latency-probe-count CLI bounds
    # must match across distributions, otherwise a value accepted on
    # one side (e.g. N=60 on modular) would be rejected on the other
    # and documented help text would lie.
    assert standalone.LATENCY_PROBE_MIN == MODULAR_PROBE_MIN, (
        "LATENCY_PROBE_MIN drift between latency_variance.py and "
        "standalone audit.py. CLI bounds must match."
    )
    assert standalone.LATENCY_PROBE_MAX == MODULAR_PROBE_MAX, (
        "LATENCY_PROBE_MAX drift between latency_variance.py and "
        "standalone audit.py. CLI bounds must match."
    )


def test_standalone_uses_perf_counter_not_wall_clock(monkeypatch):
    """v1.8.1 Codex review cycle #2 follow-up: parity regression on the
    clock source.

    The modular side is guarded by
    ``tests/test_latency_variance.py::test_uses_perf_counter_not_wall_clock``.
    This test mirrors that guard onto the standalone distribution so
    neither side can silently revert Step 13 timing to ``time.time``.

    Strategy: patch ``time.perf_counter`` at the module level to a
    deterministic 1-per-call counter, patch ``time.time`` to a constant,
    run the standalone's ``run_latency_variance`` against a mock client,
    then assert:
      * perf_counter invoked >= 2 times per probe (t0 + elapsed)
      * time.time never invoked during the timing loop
      * latencies exactly equal to the fake clock deltas

    Under a wall-clock implementation these assertions fail loudly
    because the mock client returns instantaneously (elapsed ~ 0),
    whereas our fake perf_counter yields elapsed = 1.0 per probe.
    """
    import time as time_mod
    from unittest.mock import MagicMock

    perf_counter_calls = [0]
    time_time_calls = [0]
    counter = [0]

    def fake_perf_counter():
        perf_counter_calls[0] += 1
        counter[0] += 1
        return float(counter[0])

    def fake_time():
        time_time_calls[0] += 1
        return 1_700_000_000.0

    monkeypatch.setattr(time_mod, "perf_counter", fake_perf_counter)
    monkeypatch.setattr(time_mod, "time", fake_time)

    standalone = _load_standalone_audit()

    client = MagicMock()
    client.ensure_format = MagicMock()
    client.call = MagicMock(return_value={
        "text": "ok",
        "input_tokens": 1,
        "output_tokens": 1,
        "raw": {},
        "time": 0.0,
    })

    result = standalone.run_latency_variance(client, count=3, sleep=0)

    assert perf_counter_calls[0] >= 6, (
        f"Standalone audit.py invoked perf_counter "
        f"{perf_counter_calls[0]} times; expected >= 6 for 3 probes. "
        f"Step 13 may have reverted to time.time() in the standalone "
        f"distribution, which would silently re-introduce wall-clock "
        f"artifacts."
    )
    assert time_time_calls[0] == 0, (
        f"Standalone audit.py called time.time() {time_time_calls[0]} "
        f"times during latency-variance timing; must use monotonic "
        f"perf_counter only."
    )
    assert result["latencies"] == [1.0, 1.0, 1.0]


def test_standalone_stream_model_helper_parity():
    """Regression: missing message_start.model must no longer pass as
    Claude-like on either distribution."""
    from api_relay_audit.stream_integrity import StreamSignals, _check_stream_model

    standalone = _load_standalone_audit()

    cases = [None, "claude-opus-4-6", "gpt-5"]
    for model in cases:
        modular_signals = StreamSignals()
        modular_signals.message_start_model = model

        standalone_signals = standalone.StreamSignals()
        standalone_signals.message_start_model = model

        assert _check_stream_model(modular_signals) == standalone._check_stream_model(
            standalone_signals
        ), f"Standalone stream-model helper drift for model={model!r}"


def _assert_parser_rejects_latency_probe_count(module, monkeypatch, value):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit.py",
            "--key",
            "sk-test",
            "--url",
            "https://relay.example.com/v1",
            "--latency-probe-count",
            str(value),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        module.parse_args()
    assert exc.value.code == 2


def test_latency_probe_count_argparse_wiring_rejects_invalid_values(monkeypatch):
    """Regression: validate_probe_count must be wired into argparse on both
    distributions, not only tested as a bare helper."""
    import scripts.audit as modular
    from api_relay_audit.latency_variance import LATENCY_PROBE_MAX, LATENCY_PROBE_MIN

    standalone = _load_standalone_audit()

    for module in (modular, standalone):
        for value in (LATENCY_PROBE_MIN - 1, 0, -1, LATENCY_PROBE_MAX + 1):
            _assert_parser_rejects_latency_probe_count(module, monkeypatch, value)


def test_standalone_ensure_format_real_body_detects_anthropic(monkeypatch):
    """Mirror the ensure_format body coverage onto the curl-only artifact."""
    standalone = _load_standalone_audit()
    client = standalone.APIClient(
        "https://relay.example.com/v1",
        "sk-test",
        "claude-3-haiku",
        verbose=False,
    )
    calls = []

    def fake_curl_post(url, headers, body):
        calls.append((url, headers, body))
        return {
            "content": [{"text": "detected"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }

    monkeypatch.setattr(client, "_curl_post", fake_curl_post)

    client.ensure_format()

    assert client.detected_format == "anthropic"
    assert len(calls) == 1
    assert calls[0][0] == "https://relay.example.com/v1/messages"
    assert calls[0][2]["max_tokens"] == 1


def _help_option_set(path):
    result = subprocess.run(
        [sys.executable, str(path), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return set(re.findall(r"--[a-z0-9-]+", result.stdout))


def test_public_help_flags_parity():
    """Both curl-only and modular entrypoints must expose the same public
    CLI flags even when their implementations differ internally."""
    modular_flags = _help_option_set(REPO_ROOT / "scripts" / "audit.py")
    standalone_flags = _help_option_set(REPO_ROOT / "audit.py")
    assert "--connectivity" in modular_flags
    assert modular_flags == standalone_flags


def test_connectivity_mode_exits_before_full_audit(monkeypatch, tmp_path):
    """--connectivity must not run warmup or any of the 14 audit steps."""
    import scripts.audit as modular

    standalone = _load_standalone_audit()

    audit_functions = [
        "run_warmup",
        "test_infrastructure",
        "test_models",
        "test_token_injection",
        "test_prompt_extraction",
        "test_instruction_conflict",
        "test_jailbreak",
        "test_context_length",
        "test_tool_substitution",
        "test_error_leakage",
        "test_stream_integrity",
        "test_web3_injection",
        "test_infra_fingerprint",
        "test_latency_variance",
        "test_channel_classifier",
    ]

    class FakeClient:
        def __init__(self, base_url, api_key, model, timeout=120):
            self.base_url = base_url.rstrip("/")
            self.api_key = api_key
            self.model = model
            self.timeout = timeout

        def set_transparent_logger(self, logger):
            pass

        def raw_request(self, method, path, headers, body, content_type, timeout):
            if path == "/v1/messages":
                return {
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({
                        "content": [{"type": "text", "text": "ok"}],
                        "usage": {"input_tokens": 8, "output_tokens": 1},
                    }),
                    "error": None,
                }
            return {
                "status": 404,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"error": {"message": "not found"}}),
                "error": None,
            }

    for module in (modular, standalone):
        monkeypatch.setattr(module, "APIClient", FakeClient)

        def forbidden(*args, **kwargs):
            raise AssertionError("--connectivity should exit before full audit steps")

        for name in audit_functions:
            monkeypatch.setattr(module, name, forbidden)

        output = tmp_path / f"{module.__name__.replace('.', '_')}-connectivity.md"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "audit.py",
                "--connectivity",
                "--key",
                "sk-test",
                "--url",
                "https://relay.example.com/v1",
                "--model",
                "claude-test",
                "--warmup",
                "3",
                "--skip-infra",
                "--output",
                str(output),
            ],
        )

        assert module.main() == 0
        markdown = output.read_text(encoding="utf-8")
        assert "API Relay Connectivity Report" in markdown
        assert "Security Audit Report" not in markdown
        assert "LOW RISK" not in markdown


def _extract_overall_rating(markdown):
    match = re.search(r"### (HIGH|MEDIUM|LOW) RISK", markdown)
    assert match, f"Could not find overall rating in report:\n{markdown[-1000:]}"
    return match.group(1)


def _run_stubbed_audit_and_rating(module, monkeypatch, tmp_path, case_name, scenario):
    class FakeClient:
        base_url = "https://relay.example.com"
        model = "claude-test"

        def __init__(self, *args, **kwargs):
            pass

        def set_transparent_logger(self, logger):
            pass

    monkeypatch.setattr(module, "APIClient", FakeClient)
    monkeypatch.setattr(module, "run_warmup", lambda client, count: None)
    monkeypatch.setattr(module, "test_infrastructure", lambda *args: None)
    monkeypatch.setattr(module, "test_models", lambda *args: None)
    monkeypatch.setattr(module, "test_prompt_extraction", lambda *args: False)
    monkeypatch.setattr(module, "test_jailbreak", lambda *args: None)
    monkeypatch.setattr(module, "test_context_length", lambda *args: None)
    monkeypatch.setattr(module, "test_infra_fingerprint", lambda *args: None)
    monkeypatch.setattr(module, "test_latency_variance", lambda *args: None)
    monkeypatch.setattr(module, "test_channel_classifier", lambda *args: None)

    if scenario.get("crash_step"):
        def crash(*args):
            raise RuntimeError("synthetic step crash")

        monkeypatch.setattr(module, scenario["crash_step"], crash)

    monkeypatch.setattr(
        module,
        "test_token_injection",
        lambda *args: scenario.get("injection", 0),
    )
    monkeypatch.setattr(
        module,
        "test_instruction_conflict",
        lambda *args: scenario.get("overridden", False),
    )
    monkeypatch.setattr(
        module,
        "test_tool_substitution",
        lambda *args: (
            scenario.get("substitution_detected", False),
            scenario.get("substitution_inconclusive", False),
        ),
    )
    monkeypatch.setattr(
        module,
        "test_error_leakage",
        lambda *args: (
            scenario.get("error_severity", "none"),
            scenario.get("error_inconclusive", False),
        ),
    )
    monkeypatch.setattr(
        module,
        "test_stream_integrity",
        lambda *args: (
            scenario.get("stream_verdict", "clean"),
            scenario.get("stream_inconclusive", False),
        ),
    )
    monkeypatch.setattr(
        module,
        "test_web3_injection",
        lambda *args: (
            scenario.get("web3_verdict", "clean"),
            scenario.get("web3_inconclusive", False),
        ),
    )

    output = tmp_path / f"{module.__name__.replace('.', '_')}-{case_name}.md"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit.py",
            "--key",
            "sk-test",
            "--url",
            "https://relay.example.com/v1",
            "--model",
            "claude-test",
            "--profile",
            "full",
            "--output",
            str(output),
        ],
    )

    module.main()
    return _extract_overall_rating(output.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("case_name", "scenario", "expected"),
    [
        ("clean", {}, "LOW"),
        ("d1_only", {"injection": 101}, "MEDIUM"),
        ("d1_and_d2", {"injection": 101, "overridden": True}, "HIGH"),
        ("d3_substitution", {"substitution_detected": True}, "HIGH"),
        ("d4_medium", {"error_severity": "medium"}, "MEDIUM"),
        ("d4_high", {"error_severity": "high"}, "HIGH"),
        ("d5_anomaly", {"stream_verdict": "anomaly"}, "HIGH"),
        ("d6_inconclusive", {"web3_inconclusive": True}, "MEDIUM"),
        ("step_crash", {"crash_step": "test_models"}, "MEDIUM"),
    ],
)
def test_overall_risk_matrix_semantic_parity(monkeypatch, tmp_path, case_name, scenario, expected):
    """The generated standalone and modular entrypoints must make the same
    user-visible risk decision for representative D1-D6 matrix paths.

    The generated-artifact check prevents textual drift, but this semantic
    smoke test keeps the important public behavior pinned without restoring
    the old brittle byte-level risk-matrix block parity.
    """
    import scripts.audit as modular

    standalone = _load_standalone_audit()

    modular_rating = _run_stubbed_audit_and_rating(
        modular, monkeypatch, tmp_path, f"modular-{case_name}", scenario,
    )
    standalone_rating = _run_stubbed_audit_and_rating(
        standalone, monkeypatch, tmp_path, f"standalone-{case_name}", scenario,
    )

    assert modular_rating == expected
    assert standalone_rating == expected
    assert standalone_rating == modular_rating


def test_standalone_transparent_log_call_writes_entry(tmp_path, monkeypatch):
    """The standalone --transparent-log flag must be backed by real logging,
    not merely accepted by argparse."""
    standalone = _load_standalone_audit()
    client = standalone.APIClient(
        "https://relay.example.com/v1",
        "sk-test",
        "claude-3-haiku",
        verbose=False,
    )
    path = tmp_path / "audit.jsonl"
    logger = standalone.TransparentLogger(str(path))
    client.set_transparent_logger(logger)
    client._format = "anthropic"

    def fake_call_with_detection(messages, system, max_tokens):
        return {
            "text": "ok",
            "input_tokens": 1,
            "output_tokens": 1,
            "raw": {"id": "msg_1"},
        }

    monkeypatch.setattr(client, "_call_with_detection", fake_call_with_detection)

    client.call([{"role": "user", "content": "hi"}])
    logger.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["method"] == "call"
    assert entry["transport"] == "curl"
    assert entry["status_code"] == 200
    assert entry["request_body_sha256"] is not None
    assert entry["response_body_sha256"] is not None


def test_fast_context_scan_wiring_parity(monkeypatch):
    """--fast-context should feed the same reduced Step 7 ladder into both
    distributions without changing the default full-scan path."""
    import scripts.audit as modular
    from unittest.mock import MagicMock

    standalone = _load_standalone_audit()

    for module in (modular, standalone):
        seen = []

        def fake_run_context_scan(client, coarse_steps=None):
            seen.append(coarse_steps)
            return [(10, 5, 5, 1000, "ok", 0.1)]

        monkeypatch.setattr(module, "run_context_scan", fake_run_context_scan)

        report = MagicMock()
        module.test_context_length(MagicMock(), report, fast_mode=False)
        module.test_context_length(MagicMock(), report, fast_mode=True)

        assert seen == [None, [10, 50, 100, 200]]


def test_standalone_curl_post_keeps_large_body_out_of_argv(monkeypatch):
    """Issue #14: standalone curl POST must not put long JSON bodies or
    credentials in process argv."""
    standalone = _load_standalone_audit()
    client = standalone.APIClient(
        "https://relay.example.com/v1",
        "sk-test",
        "claude-3-haiku",
        verbose=False,
    )
    calls = []

    class FakeRunResult:
        returncode = 0
        stdout = '{"ok": true}'
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return FakeRunResult()

    monkeypatch.setattr(standalone.subprocess, "run", fake_run)

    client._curl_post(
        "https://relay.example.com/v1/messages",
        {"x-api-key": "sk-test", "content-type": "application/json"},
        {"model": "test", "messages": [{"content": "x" * 40000}]},
    )

    cmd, kwargs = calls[0]
    cmd_text = " ".join(cmd)
    assert "--data-binary" in cmd
    assert cmd[cmd.index("--data-binary") + 1].startswith("@")
    assert "x" * 100 not in cmd_text
    assert "sk-test" not in cmd_text
    assert "x-api-key: sk-test" in kwargs["input"]


def test_standalone_get_models_bypasses_proxy_for_loopback(monkeypatch):
    """Standalone model-list GET must keep loopback URLs out of proxy env routing."""
    standalone = _load_standalone_audit()
    calls = []

    class FakeRunResult:
        returncode = 0
        stdout = (
            'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            '{"data":[{"id":"claude-opus-4-6"}]}'
        )
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return FakeRunResult()

    monkeypatch.setattr(standalone.subprocess, "run", fake_run)

    status, data, text, headers = standalone.httpx_get_json_data(
        "http://localhost:8765/v1/models",
        {"Authorization": "Bearer sk-test"},
        timeout=3,
    )

    assert status == 200
    assert data == [{"id": "claude-opus-4-6"}]
    cmd, _kwargs = calls[0]
    assert "--noproxy" in cmd
    assert cmd[cmd.index("--noproxy") + 1] == "localhost,127.0.0.1,::1"
    assert standalone._transport.curl_loopback_no_proxy_args(
        "http://127.0.0.1:8765/v1/messages"
    ) == ["--noproxy", "localhost,127.0.0.1,::1"]


def test_standalone_stream_bypasses_proxy_for_loopback(monkeypatch):
    """Standalone SSE curl path uses the same loopback proxy bypass facade."""
    from io import BytesIO
    from unittest.mock import MagicMock

    standalone = _load_standalone_audit()
    captured_cmds = []

    def fake_popen(cmd, *args, **kwargs):
        captured_cmds.append(cmd)
        proc = MagicMock()
        proc.stdin = MagicMock()
        proc.stdout = BytesIO(
            b'data: {"type":"message_start","message":{"model":"claude-opus-4-6"}}\n'
            b"\n"
            b"data: [DONE]\n\n"
        )
        proc.stderr = BytesIO(b"")
        proc.wait = MagicMock(return_value=None)
        proc.returncode = 0
        return proc

    monkeypatch.setattr(standalone.subprocess, "Popen", fake_popen)

    client = standalone.APIClient(
        "http://localhost:8765/v1",
        "sk-test",
        "claude-opus-4-6",
        verbose=False,
    )
    client._use_curl = True
    signals = client.stream_call([{"role": "user", "content": "hi"}])

    assert signals.transport_error is None
    cmd = captured_cmds[0]
    assert "--noproxy" in cmd
    assert cmd[cmd.index("--noproxy") + 1] == "localhost,127.0.0.1,::1"
