"""Dual-distribution invariant regression test.

The repo ships two parallel versions of the audit tool:

    - ``scripts/audit.py`` (modular, uses ``api_relay_audit/*.py``)
    - ``audit.py`` at repo root (standalone, zero-dep, curl-only)

Any change to one must be mirrored into the other. This test slices the
risk-matrix block from both files and asserts they are character-identical
so that drift is caught immediately.
"""

from pathlib import Path
from unittest.mock import MagicMock


REPO_ROOT = Path(__file__).resolve().parent.parent


def _extract_risk_matrix(path: Path) -> str:
    """Slice the risk-matrix block between the ``# Overall rating`` comment
    and the following ``# Output`` comment. Both files MUST contain both
    markers, otherwise the test is broken and should fail loudly.
    """
    text = path.read_text(encoding="utf-8")
    start_marker = "    # Overall rating\n"
    end_marker = "    # Output\n"
    start = text.find(start_marker)
    end = text.find(end_marker, start)
    if start == -1:
        raise AssertionError(f"Could not find '# Overall rating' marker in {path}")
    if end == -1:
        raise AssertionError(f"Could not find '# Output' marker in {path}")
    return text[start:end]


def test_risk_matrix_character_identical():
    """Regression: the risk matrix code in scripts/audit.py and audit.py MUST
    be character-identical. If this test fails, one of the two was updated
    without the other and the dual-distribution invariant is broken.
    """
    modular = _extract_risk_matrix(REPO_ROOT / "scripts" / "audit.py")
    standalone = _extract_risk_matrix(REPO_ROOT / "audit.py")
    assert modular == standalone, (
        "Risk matrix drift between scripts/audit.py and audit.py. "
        "Update both files so they are character-identical."
    )


def test_curl_post_uses_stdin_payload_in_both_distributions(monkeypatch):
    """Regression: the curl POST fallback must not place large JSON bodies or
    secrets on the command line.

    The GUI fork surfaced a Windows failure mode where long context bodies
    exceed the 32 KB command-line limit. Both distributions should pipe the
    request body via stdin with ``--data-binary @-`` while keeping headers in a
    temporary curl config file rather than in argv.
    """
    import api_relay_audit.client as modular_client

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return MagicMock(returncode=0, stdout=b'{"ok": true}', stderr=b"")

    monkeypatch.setattr(modular_client.subprocess, "run", fake_run)
    modular = modular_client.APIClient(
        "https://relay.example.com/v1", "sk-test", "claude-opus-4-6",
    )
    modular._curl_post(
        "https://relay.example.com/v1/messages",
        {"x-api-key": "sk-test", "content-type": "application/json"},
        {"model": "claude-opus-4-6", "messages": [{"role": "user", "content": "x"}]},
    )

    standalone = _load_standalone_audit()
    monkeypatch.setattr(standalone.subprocess, "run", fake_run)
    standalone_client = standalone.APIClient(
        "https://relay.example.com/v1", "sk-test", "claude-opus-4-6",
    )
    standalone_client._curl_post(
        "https://relay.example.com/v1/messages",
        {"x-api-key": "sk-test", "content-type": "application/json"},
        {"model": "claude-opus-4-6", "messages": [{"role": "user", "content": "x"}]},
    )

    assert len(calls) == 2
    for cmd, kwargs in calls:
        assert "--data-binary" in cmd
        assert "@-" in cmd
        assert "-d" not in cmd
        assert not any("sk-test" in str(part) for part in cmd)
        payload = kwargs["input"]
        assert isinstance(payload, bytes)
        assert b'"model": "claude-opus-4-6"' in payload


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
        "and standalone audit.py. Mirror the change into both."
    )
    assert standalone._NON_CLAUDE_STRICT_KEYWORDS == MODULAR_STRICT, (
        "Strict-keyword frozenset drift between identity_patterns.py and "
        "standalone audit.py. Mirror the change into both."
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
        "and standalone audit.py. Mirror the change into both -- signal order "
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
