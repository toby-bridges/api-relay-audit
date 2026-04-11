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
