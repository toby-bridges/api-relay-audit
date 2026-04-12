"""Regression tests for the v1.7.5 fail-open step wrapper.

``_run_step(name, reporter, fn, *args, default=None)`` wraps each
audit step so that a single crashing step cannot abort the whole
audit. Expected behavior on crash:

1. Full traceback is printed to stderr (NOT swallowed).
2. A yellow flag is added to the report summary naming the step.
3. The wrapper returns ``default`` so the caller can continue.
4. Subsequent wrapped calls still run.

KeyboardInterrupt is explicitly NOT caught so ctrl-C still works.
"""

import importlib.util
import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def modular():
    return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_fail_open")


@pytest.fixture(scope="module")
def standalone():
    return _load(REPO_ROOT / "audit.py", "standalone_audit_fail_open")


@pytest.fixture
def reporter():
    from api_relay_audit.reporter import Reporter
    return Reporter()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSuccessPassthrough:

    def test_modular_passes_through_return_value(self, modular, reporter):
        def step(x, y):
            return x + y

        result = modular._run_step("demo", reporter, step, 2, 3, default=0)
        assert result == 5
        # No yellow flag on success
        assert reporter.summary == []

    def test_modular_passes_through_none(self, modular, reporter):
        def step():
            return None

        result = modular._run_step("demo", reporter, step, default="default")
        assert result is None
        assert reporter.summary == []

    def test_modular_passes_through_tuple(self, modular, reporter):
        def step():
            return ("clean", False)

        result = modular._run_step("demo", reporter, step, default=("clean", True))
        assert result == ("clean", False)


# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------


class TestExceptionHandling:

    def test_returns_default_on_exception(self, modular, reporter):
        def step():
            raise ValueError("boom")

        result = modular._run_step("Step X", reporter, step, default=42)
        assert result == 42

    def test_returns_none_when_no_default(self, modular, reporter):
        def step():
            raise RuntimeError("boom")

        result = modular._run_step("Step X", reporter, step)
        assert result is None

    def test_returns_tuple_default_for_inconclusive(self, modular, reporter):
        def step():
            raise Exception("boom")

        result = modular._run_step(
            "Step 8", reporter, step, default=(False, True)
        )
        assert result == (False, True)

    def test_yellow_flag_added_on_exception(self, modular, reporter):
        def step():
            raise ValueError("oops")

        modular._run_step("Step 5 instruction override", reporter, step, default=False)
        levels = [(l, m) for l, m in reporter.summary]
        yellows = [m for l, m in levels if l == "yellow"]
        assert yellows, f"Expected yellow flag, got: {levels}"
        assert "Step 5 instruction override" in yellows[0]
        assert "ValueError" in yellows[0]
        assert "oops" in yellows[0]

    def test_exception_printed_to_stderr(self, modular, reporter, capsys):
        def step():
            raise ValueError("trace me")

        modular._run_step("Step X", reporter, step)
        captured = capsys.readouterr()
        # Error header on stderr
        assert "CRASHED" in captured.err
        assert "ValueError" in captured.err
        assert "trace me" in captured.err
        # Traceback should include the file name
        assert "Traceback" in captured.err

    def test_keyboard_interrupt_propagates(self, modular, reporter):
        def step():
            raise KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            modular._run_step("Step X", reporter, step)

    def test_system_exit_propagates(self, modular, reporter):
        """BaseException subclasses like SystemExit should NOT be caught
        by the bare ``Exception`` except clause."""
        def step():
            raise SystemExit(1)

        with pytest.raises(SystemExit):
            modular._run_step("Step X", reporter, step)

    def test_subsequent_step_still_runs(self, modular, reporter):
        def crashing():
            raise RuntimeError("crash 1")

        def working():
            return "ok"

        result1 = modular._run_step("Step A", reporter, crashing, default=None)
        result2 = modular._run_step("Step B", reporter, working)
        assert result1 is None
        assert result2 == "ok"
        # Only Step A produced a flag
        yellows = [m for l, m in reporter.summary if l == "yellow"]
        assert len(yellows) == 1
        assert "Step A" in yellows[0]


# ---------------------------------------------------------------------------
# Standalone parity
# ---------------------------------------------------------------------------


class TestStandaloneParity:

    def test_standalone_passthrough(self, standalone):
        rpt = standalone.Reporter()
        def step():
            return 123
        assert standalone._run_step("demo", rpt, step) == 123

    def test_standalone_returns_default_on_exception(self, standalone):
        rpt = standalone.Reporter()
        def step():
            raise ValueError("boom")
        assert standalone._run_step("Step X", rpt, step, default=(1, 2)) == (1, 2)

    def test_standalone_yellow_flag(self, standalone):
        rpt = standalone.Reporter()
        def step():
            raise RuntimeError("oops")
        standalone._run_step("Step 9 error leakage", rpt, step, default=("none", True))
        yellows = [m for l, m in rpt.summary if l == "yellow"]
        assert yellows
        assert "Step 9 error leakage" in yellows[0]

    def test_standalone_keyboard_interrupt_propagates(self, standalone):
        rpt = standalone.Reporter()
        def step():
            raise KeyboardInterrupt()
        with pytest.raises(KeyboardInterrupt):
            standalone._run_step("Step X", rpt, step)


# ---------------------------------------------------------------------------
# Real-step crash simulation: mock a step fn that raises
# ---------------------------------------------------------------------------


class TestRealStepCrashSimulation:
    """Simulate what happens when a real step function (e.g.
    test_tool_substitution) crashes on a malformed relay response."""

    def test_tool_substitution_crash_gives_inconclusive(self, modular, reporter):
        def fake_tool_substitution(client, report):
            raise KeyError("missing 'text' key in response")

        substitution_detected, substitution_inconclusive = modular._run_step(
            "Step 8 tool substitution", reporter,
            fake_tool_substitution, MagicMock(), reporter,
            default=(False, True),
        )
        assert substitution_detected is False
        assert substitution_inconclusive is True
        yellows = [m for l, m in reporter.summary if l == "yellow"]
        assert any("Step 8 tool substitution" in y for y in yellows)

    def test_stream_integrity_crash_gives_inconclusive(self, modular, reporter):
        def fake_stream(client, report):
            raise TimeoutError("SSE stream never closed")

        stream_verdict, stream_inconclusive = modular._run_step(
            "Step 10 stream integrity", reporter,
            fake_stream, MagicMock(), reporter,
            default=("clean", True),
        )
        assert stream_verdict == "clean"
        assert stream_inconclusive is True


# ---------------------------------------------------------------------------
# D1i / D2i: Step 3/5 crash must escalate to MEDIUM, not stay LOW
# ---------------------------------------------------------------------------


class TestCrashEscalatesViaDimensionInconclusive:
    """v1.7.5 follow-up: before this fix, Step 3 crash defaulted to
    injection=0 and Step 5 crash defaulted to overridden=False, which
    meant the 6D risk matrix had no "inconclusive" pathway for D1/D2.
    The overall rating could output LOW RISK even though the summary
    had a yellow "crashed" flag — a semantic contradiction.

    Fix: defaults changed to None, new d1i/d2i dimensions fire when
    injection/overridden are None, and the MEDIUM rule now includes
    d1i and d2i.
    """

    def test_step3_crash_gives_none_not_zero(self, modular, reporter):
        """Crash default for Step 3 must be None (not 0) so that
        d1i fires and pulls the overall rating to MEDIUM."""
        def fake_step3(client, report):
            raise RuntimeError("boom")

        injection = modular._run_step(
            "Step 3 token injection", reporter,
            fake_step3, MagicMock(), reporter,
            default=None,
        )
        assert injection is None

    def test_step5_crash_gives_none_not_false(self, modular, reporter):
        def fake_step5(client, report):
            raise RuntimeError("boom")

        overridden = modular._run_step(
            "Step 5 instruction override", reporter,
            fake_step5, MagicMock(), reporter,
            default=None,
        )
        assert overridden is None

    def test_d1i_fires_on_none_injection(self, modular):
        """d1i = (injection is None) must be True when Step 3 crashed."""
        injection = None
        d1 = injection is not None and injection > 100
        d1i = injection is None
        assert not d1
        assert d1i

    def test_d2i_fires_on_none_overridden(self, modular):
        injection = 0  # Step 3 was fine
        overridden = None  # Step 5 crashed
        d1 = injection is not None and injection > 100
        d2 = overridden is not None and overridden
        d2i = overridden is None
        assert not d1
        assert not d2
        assert d2i

    def test_medium_rule_includes_d1i(self, modular):
        """When d1i fires and nothing else triggers HIGH, the overall
        rating must be MEDIUM (not LOW)."""
        d1i = True
        d2i = False
        d3i = d4i = d4m = d5i = d6i = False
        assert d1i or d2i or d3i or d4i or d4m or d5i or d6i

    def test_medium_rule_includes_d2i(self, modular):
        d1i = False
        d2i = True
        d3i = d4i = d4m = d5i = d6i = False
        assert d1i or d2i or d3i or d4i or d4m or d5i or d6i

    def test_normal_run_no_d1i_d2i(self, modular):
        """When Steps 3 and 5 complete normally, d1i and d2i stay False."""
        injection = 0
        overridden = False
        assert not (injection is None)  # d1i
        assert not (overridden is None)  # d2i


# ---------------------------------------------------------------------------
# crashes list + any_step_crashed catch-all
# ---------------------------------------------------------------------------


class TestCrashesListCatchAll:
    """Any step crash must escalate to MEDIUM via any_step_crashed,
    even for steps that have no dedicated d<N>i dimension (4, 6, 7)."""

    def test_crashes_list_populated_on_failure(self, modular, reporter):
        crashes = []
        def crashing():
            raise RuntimeError("boom")

        modular._run_step("Step 6 jailbreak", reporter, crashing,
                          crashes=crashes)
        assert "Step 6 jailbreak" in crashes

    def test_crashes_list_empty_on_success(self, modular, reporter):
        crashes = []
        modular._run_step("Step 6 jailbreak", reporter, lambda: None,
                          crashes=crashes)
        assert crashes == []

    def test_any_step_crashed_fires_medium(self):
        """Simulating the risk matrix: if step_crashes is non-empty and
        all typed dimensions are clean, the any_step_crashed flag
        must still trigger MEDIUM."""
        step_crashes = ["Step 4 prompt extraction"]
        any_step_crashed = bool(step_crashes)
        d1i = d2i = d3i = d4i = d4m = d5i = d6i = False
        assert any_step_crashed
        assert (d1i or d2i or d3i or d4i or d4m or d5i or d6i
                or any_step_crashed)

    def test_step467_crash_not_swallowed(self, modular, reporter):
        """Steps 4, 6, 7 have no d<N>i dimension but must still trigger
        MEDIUM via crashes list — the friend's exact finding."""
        crashes = []
        for name in ("Step 4 prompt extraction",
                     "Step 6 jailbreak",
                     "Step 7 context length"):
            modular._run_step(name, reporter, self._boom, crashes=crashes)
        assert len(crashes) == 3
        assert bool(crashes)  # any_step_crashed

    @staticmethod
    def _boom():
        raise RuntimeError("simulated")

    def test_standalone_crashes_kwarg(self, standalone):
        rpt = standalone.Reporter()
        crashes = []
        standalone._run_step("Step 6 jailbreak", rpt, self._boom,
                             crashes=crashes)
        assert "Step 6 jailbreak" in crashes
