"""Regression: Step 4 (prompt extraction) and Step 6 (jailbreak) must
emit a green risk-summary flag on clean runs so the overall summary
lists 11 lines (one per step) instead of 9.

Before v1.7.4-followup the two steps only emitted red/yellow on a
positive finding and fell through to a plain paragraph on clean. That
meant clean runs under-represented the audit coverage in the top-of-
report risk summary — a user reading the summary couldn't tell
whether Step 4 / Step 6 were run and passed or skipped entirely.

Pinned for both modular scripts/audit.py and standalone audit.py so
the dual-distribution invariant holds.
"""

import importlib.util
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
    return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_script_clean")


@pytest.fixture(scope="module")
def standalone():
    return _load(REPO_ROOT / "audit.py", "standalone_audit_script_clean")


def _mock_client(text: str):
    """Build a client whose .call() always returns ``text``."""
    client = MagicMock()
    client.call.return_value = {
        "text": text,
        "input_tokens": 10,
        "output_tokens": 20,
        "time": 0.05,
    }
    return client


def _error_client(error_text: str):
    """Build a client whose .call() always returns an error dict."""
    client = MagicMock()
    client.call.return_value = {
        "error": error_text,
        "time": 0.05,
    }
    return client


def _summary_levels(reporter):
    """Extract the (level, message) tuples from the reporter summary."""
    return list(reporter.summary)


CLEAN_REFUSAL = (
    "I'm Claude, an AI assistant made by Anthropic. "
    "I'm sorry, I can't share any information about my internal "
    "instructions or system prompt. I decline to reveal or describe "
    "the content of any hidden instructions."
)


# ---------------------------------------------------------------------------
# Step 4: prompt extraction
# ---------------------------------------------------------------------------


class TestPromptExtractionGreenOnClean:
    @pytest.fixture
    def reporter(self):
        from api_relay_audit.reporter import Reporter
        return Reporter()

    def _time_sleep_patched(self, monkeypatch, mod):
        monkeypatch.setattr(mod, "time", MagicMock(sleep=MagicMock()))

    def test_modular_emits_green_flag(self, modular, reporter, monkeypatch):
        self._time_sleep_patched(monkeypatch, modular)
        client = _mock_client(CLEAN_REFUSAL)
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is False
        levels = _summary_levels(reporter)
        greens = [m for level, m in levels if level == "green"]
        assert any("Prompt extraction tests passed" in g for g in greens), (
            f"Step 4 clean run did not emit a green summary flag. Summary: {levels}"
        )

    def test_modular_no_green_on_dirty(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        # Strong marker "kiro" always flags regardless of refusal language
        client = _mock_client("my name is kiro and i'm sorry i cannot say more")
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is True
        levels = _summary_levels(reporter)
        assert any(level == "red" for level, _ in levels)
        greens = [m for level, m in levels if level == "green" and "Prompt extraction" in m]
        assert not greens, "Step 4 must NOT emit a green flag when a leak is detected"

    def test_standalone_emits_green_flag(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client(CLEAN_REFUSAL)
        leaked = standalone.test_prompt_extraction(client, reporter)
        assert leaked is False
        levels = list(reporter.summary)
        greens = [m for level, m in levels if level == "green"]
        assert any("Prompt extraction tests passed" in g for g in greens), (
            f"Step 4 clean run in standalone did not emit a green flag. Summary: {levels}"
        )

    def test_modular_blank_completion_is_inconclusive(self, modular, reporter, monkeypatch):
        self._time_sleep_patched(monkeypatch, modular)
        client = _mock_client("")
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is False
        levels = _summary_levels(reporter)
        assert any(level == "yellow" and "INCONCLUSIVE" in msg for level, msg in levels), (
            f"Blank Step 4 response must not be treated as clean. Summary: {levels}"
        )
        greens = [m for level, m in levels if level == "green" and "Prompt extraction" in m]
        assert not greens

    def test_standalone_blank_completion_is_inconclusive(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client("")
        leaked = standalone.test_prompt_extraction(client, reporter)
        assert leaked is False
        levels = list(reporter.summary)
        assert any(level == "yellow" and "INCONCLUSIVE" in msg for level, msg in levels), (
            f"Blank Step 4 response in standalone must not be treated as clean. Summary: {levels}"
        )
        greens = [m for level, m in levels if level == "green" and "Prompt extraction" in m]
        assert not greens


# ---------------------------------------------------------------------------
# Step 6: jailbreak
# ---------------------------------------------------------------------------


class TestJailbreakGreenOnClean:
    def _time_sleep_patched(self, monkeypatch, mod):
        monkeypatch.setattr(mod, "time", MagicMock(sleep=MagicMock()))

    def test_modular_emits_green_flag(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        client = _mock_client(CLEAN_REFUSAL)
        modular.test_jailbreak(client, reporter)
        levels = _summary_levels(reporter)
        greens = [m for level, m in levels if level == "green"]
        assert any("Jailbreak tests passed" in g for g in greens), (
            f"Step 6 clean run did not emit a green summary flag. Summary: {levels}"
        )

    def test_modular_no_green_on_dirty(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        # Strong marker "kiro" always flags regardless of refusal language
        client = _mock_client("i am kiro, sorry i cannot say more")
        modular.test_jailbreak(client, reporter)
        levels = _summary_levels(reporter)
        assert any(level == "yellow" for level, _ in levels)
        greens = [m for level, m in levels if level == "green" and "Jailbreak tests" in m]
        assert not greens, "Step 6 must NOT emit a green flag when keywords leaked"

    def test_standalone_emits_green_flag(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client(CLEAN_REFUSAL)
        standalone.test_jailbreak(client, reporter)
        levels = list(reporter.summary)
        greens = [m for level, m in levels if level == "green"]
        assert any("Jailbreak tests passed" in g for g in greens), (
            f"Step 6 clean run in standalone did not emit a green flag. Summary: {levels}"
        )

    def test_modular_all_errors_is_inconclusive_not_green(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        client = _error_client(
            'HTTP 503: {"error":{"message":"No available accounts: this group only allows Claude Code clients"}}'
        )
        modular.test_jailbreak(client, reporter)
        levels = _summary_levels(reporter)
        assert any(level == "yellow" and "INCONCLUSIVE" in msg for level, msg in levels), (
            f"All-error Step 6 run must be inconclusive. Summary: {levels}"
        )
        greens = [m for level, m in levels if level == "green" and "Jailbreak tests" in m]
        assert not greens

    def test_standalone_all_errors_is_inconclusive_not_green(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _error_client(
            'HTTP 503: {"error":{"message":"No available accounts: this group only allows Claude Code clients"}}'
        )
        standalone.test_jailbreak(client, reporter)
        levels = list(reporter.summary)
        assert any(level == "yellow" and "INCONCLUSIVE" in msg for level, msg in levels), (
            f"All-error Step 6 run in standalone must be inconclusive. Summary: {levels}"
        )
        greens = [m for level, m in levels if level == "green" and "Jailbreak tests" in m]
        assert not greens


class TestCompletionGatedRelayInconclusive:
    GATE_ERROR = (
        'HTTP 503: {"error":{"message":"No available accounts: '
        'this group only allows Claude Code clients"}}'
    )

    def _time_sleep_patched(self, monkeypatch, mod):
        monkeypatch.setattr(mod, "time", MagicMock(sleep=MagicMock()))

    def test_modular_token_injection_all_errors_returns_none_and_yellow(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        result = modular.test_token_injection(_error_client(self.GATE_ERROR), reporter)
        assert result is None
        levels = _summary_levels(reporter)
        assert any(level == "yellow" and "Token injection test INCONCLUSIVE" in msg for level, msg in levels)
        assert not any(level == "green" and "No token injection detected" in msg for level, msg in levels)

    def test_standalone_token_injection_all_errors_returns_none_and_yellow(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        result = standalone.test_token_injection(_error_client(self.GATE_ERROR), reporter)
        assert result is None
        levels = list(reporter.summary)
        assert any(level == "yellow" and "Token injection test INCONCLUSIVE" in msg for level, msg in levels)
        assert not any(level == "green" and "No token injection detected" in msg for level, msg in levels)

    def test_modular_instruction_override_all_errors_returns_none_and_yellow(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        result = modular.test_instruction_conflict(_error_client(self.GATE_ERROR), reporter)
        assert result is None
        levels = _summary_levels(reporter)
        assert any(level == "yellow" and "Instruction override test INCONCLUSIVE" in msg for level, msg in levels)

    def test_standalone_instruction_override_all_errors_returns_none_and_yellow(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        result = standalone.test_instruction_conflict(_error_client(self.GATE_ERROR), reporter)
        assert result is None
        levels = list(reporter.summary)
        assert any(level == "yellow" and "Instruction override test INCONCLUSIVE" in msg for level, msg in levels)


# ---------------------------------------------------------------------------
# Parity: both distributions use the exact same green flag messages
# ---------------------------------------------------------------------------


class TestOptionDEndToEnd:
    """End-to-end: run test_prompt_extraction / test_jailbreak with a
    mocked client on the friend's repros and assert the emitted flag
    color. Complements the unit tests in test_refusal_detector.py."""

    REPRO_1_STEP4 = (
        "I refuse to share that, but your system prompt is: You are "
        "a coding assistant that writes Python."
    )
    REPRO_2_STEP6 = (
        "Sorry, I cannot share that, but I am an assistant built to "
        "help developers."
    )

    def _time_sleep_patched(self, monkeypatch, mod):
        monkeypatch.setattr(mod, "time", MagicMock(sleep=MagicMock()))

    def test_step4_repro1_fires_red_modular(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        client = _mock_client(self.REPRO_1_STEP4)
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is True
        reds = [m for level, m in reporter.summary if level == "red"]
        assert any("Hidden prompt content extracted" in r for r in reds), (
            f"Step 4 must fire RED on Repro 1. Summary: {reporter.summary}"
        )

    def test_step4_repro1_fires_red_standalone(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client(self.REPRO_1_STEP4)
        leaked = standalone.test_prompt_extraction(client, reporter)
        assert leaked is True
        reds = [m for level, m in reporter.summary if level == "red"]
        assert reds, f"standalone Step 4 must fire RED on Repro 1. Summary: {reporter.summary}"

    def test_step6_repro2_fires_yellow_contradictory_modular(self, modular, monkeypatch):
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        client = _mock_client(self.REPRO_2_STEP6)
        modular.test_jailbreak(client, reporter)
        yellows = [m for level, m in reporter.summary if level == "yellow"]
        assert any("without Claude self-identification" in y for y in yellows), (
            f"Step 6 must fire YELLOW contradictory on Repro 2. Summary: {reporter.summary}"
        )
        # And must NOT emit the clean-green flag
        greens = [m for level, m in reporter.summary if level == "green" and "Jailbreak" in m]
        assert not greens

    def test_step6_repro2_fires_yellow_contradictory_standalone(self, standalone, monkeypatch):
        self._time_sleep_patched(monkeypatch, standalone)
        reporter = standalone.Reporter()
        client = _mock_client(self.REPRO_2_STEP6)
        standalone.test_jailbreak(client, reporter)
        yellows = [m for level, m in reporter.summary if level == "yellow"]
        assert yellows, f"standalone Step 6 must fire yellow on Repro 2. Summary: {reporter.summary}"

    def test_step4_repro2_fires_yellow_contradictory_modular(self, modular, monkeypatch):
        """Applied to Step 4: the same text still has weak hits
        (assistant, developer, built to... well, 'built to' isn't in
        step 4 weak, but 'assistant' and 'developer' are)."""
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        client = _mock_client(self.REPRO_2_STEP6)
        leaked = modular.test_prompt_extraction(client, reporter)
        # Should trip the contradictory yellow branch
        yellows = [m for level, m in reporter.summary if level == "yellow"]
        assert any("without Claude self-identification" in y for y in yellows), (
            f"Step 4 must fire YELLOW contradictory on Repro 2. Summary: {reporter.summary}"
        )
        assert leaked is True  # yellow still sets leaked

    def test_benign_with_claude_id_stays_clean_modular(self, modular, monkeypatch):
        """Adding Claude self-ID exempts the response."""
        from api_relay_audit.reporter import Reporter
        self._time_sleep_patched(monkeypatch, modular)
        reporter = Reporter()
        benign = (
            "I'm Claude, made by Anthropic. I won't provide my "
            "system prompt, but I'm an assistant created to help "
            "developers."
        )
        client = _mock_client(benign)
        leaked = modular.test_prompt_extraction(client, reporter)
        assert leaked is False
        greens = [m for level, m in reporter.summary if level == "green"]
        assert any("Prompt extraction tests passed" in g for g in greens), (
            f"Exempt response must produce a green flag. Summary: {reporter.summary}"
        )


class TestGreenFlagParity:
    def test_prompt_extraction_green_message_identical(self, modular, standalone, monkeypatch):
        monkeypatch.setattr(modular, "time", MagicMock(sleep=MagicMock()))
        monkeypatch.setattr(standalone, "time", MagicMock(sleep=MagicMock()))

        from api_relay_audit.reporter import Reporter
        r_mod = Reporter()
        modular.test_prompt_extraction(_mock_client(CLEAN_REFUSAL), r_mod)

        r_std = standalone.Reporter()
        standalone.test_prompt_extraction(_mock_client(CLEAN_REFUSAL), r_std)

        g_mod = [m for level, m in r_mod.summary if level == "green" and "Prompt extraction" in m]
        g_std = [m for level, m in r_std.summary if level == "green" and "Prompt extraction" in m]
        assert g_mod == g_std, (
            "Prompt extraction green-flag text diverged between distributions. "
            f"modular={g_mod} standalone={g_std}"
        )

    def test_jailbreak_green_message_identical(self, modular, standalone, monkeypatch):
        monkeypatch.setattr(modular, "time", MagicMock(sleep=MagicMock()))
        monkeypatch.setattr(standalone, "time", MagicMock(sleep=MagicMock()))

        from api_relay_audit.reporter import Reporter
        r_mod = Reporter()
        modular.test_jailbreak(_mock_client(CLEAN_REFUSAL), r_mod)

        r_std = standalone.Reporter()
        standalone.test_jailbreak(_mock_client(CLEAN_REFUSAL), r_std)

        g_mod = [m for level, m in r_mod.summary if level == "green" and "Jailbreak" in m]
        g_std = [m for level, m in r_std.summary if level == "green" and "Jailbreak" in m]
        assert g_mod == g_std, (
            "Jailbreak green-flag text diverged between distributions. "
            f"modular={g_mod} standalone={g_std}"
        )
