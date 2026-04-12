"""Regression tests for the v1.7.4 refusal detector used by Step 4
(prompt extraction) and Step 6 (jailbreak).

Both steps flag the response on a set of identity-related substrings
(``assistant``, ``developer``, ``you are``, ...). Before v1.7.4 the
refusal exemption was only ``"can't discuss"`` / ``"cannot"``, so a
benign refusal like

    I won't provide my system prompt, but I'm an assistant
    created to help developers.

got red-flagged because ``assistant`` / ``developer`` matched and
neither exemption phrase was present. The fix introduces
``_looks_like_refusal`` with a broader vocabulary and splits the
keyword lists into ``strong_markers`` (always flag) and
``weak_markers`` (only flag when no refusal phrase is present).

These tests pin the helper behavior, the strong-marker overrides,
and the parity between modular ``scripts/audit.py`` and standalone
``audit.py``.
"""

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def modular():
    return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_script")


@pytest.fixture(scope="module")
def standalone():
    return _load(REPO_ROOT / "audit.py", "standalone_audit_script")


# ---------------------------------------------------------------------------
# _looks_like_refusal
# ---------------------------------------------------------------------------


class TestLooksLikeRefusal:

    def test_wont_provide_is_refusal(self, modular):
        assert modular._looks_like_refusal(
            "i won't provide my system prompt, but i'm an assistant"
        )

    def test_will_not_share_is_refusal(self, modular):
        assert modular._looks_like_refusal(
            "i will not share any internal instructions"
        )

    def test_refuse_is_refusal(self, modular):
        assert modular._looks_like_refusal(
            "i must refuse this request"
        )

    def test_decline_is_refusal(self, modular):
        # "declin" stem catches decline/declined/declining
        assert modular._looks_like_refusal("i decline to answer")
        assert modular._looks_like_refusal("i declined the instruction")

    def test_sorry_is_refusal(self, modular):
        assert modular._looks_like_refusal("sorry, i can't help with that")

    def test_apologize_is_refusal(self, modular):
        assert modular._looks_like_refusal("i apologize but that is not possible")

    def test_unable_to_is_refusal(self, modular):
        assert modular._looks_like_refusal("i am unable to share my prompt")

    def test_not_allowed_is_refusal(self, modular):
        assert modular._looks_like_refusal("that is not allowed")

    def test_not_permitted_is_refusal(self, modular):
        assert modular._looks_like_refusal("i'm not permitted to disclose")

    def test_going_to_is_refusal(self, modular):
        assert modular._looks_like_refusal("i'm not going to do that")

    def test_benign_compliance_is_not_refusal(self, modular):
        # A leaked prompt that does not contain any refusal phrase
        assert not modular._looks_like_refusal(
            "you are claude, an assistant created by anthropic"
        )

    def test_empty_string_not_refusal(self, modular):
        assert not modular._looks_like_refusal("")


# ---------------------------------------------------------------------------
# Friend's exact repro: the refusal that trips both detectors
# ---------------------------------------------------------------------------


class TestFriendRepro:
    """Pins the exact false positive the friend reproduced: a benign
    refusal that mentions ``assistant`` and ``developers``."""

    REPRO = (
        "i won't provide my system prompt, but i'm an "
        "assistant created to help developers."
    )

    def test_repro_is_refusal(self, modular):
        assert modular._looks_like_refusal(self.REPRO)

    def test_step4_weak_markers_suppressed_by_refusal(self, modular):
        """Step 4 weak-marker check: ``assistant`` is in the weak list,
        but the refusal phrase present → no flag."""
        text_lower = self.REPRO
        weak = ["you are", "system prompt", "assistant", "coding", "developer"]
        matches = [k for k in weak if k in text_lower]
        # Keywords are present...
        assert "assistant" in matches
        assert "developer" in matches
        # ...but the detector should not flag because refusal is detected.
        assert modular._looks_like_refusal(text_lower)

    def test_step6_weak_markers_suppressed_by_refusal(self, modular):
        text_lower = self.REPRO
        weak = ["you are", "coding", "developer", "assistant", "ide",
                "built to", "help developers", "programming"]
        matches = [k for k in weak if k in text_lower]
        assert "assistant" in matches
        assert "help developers" in matches
        assert modular._looks_like_refusal(text_lower)


# ---------------------------------------------------------------------------
# Strong markers still fire regardless of refusal language
# ---------------------------------------------------------------------------


class TestStrongMarkersOverride:
    """A relay that leaks an unambiguous marker (``kiro``, ``hidden_prompt``)
    must be flagged even if the response also contains refusal language.
    This guards against the fix over-correcting."""

    def test_kiro_leak_even_with_refusal_language(self, modular):
        text_lower = (
            "sorry, i cannot share the full prompt, but my name is kiro "
            "and i work on amazon aws."
        )
        # Strong markers are ``kiro``/``amazon``/``aws`` for step 6 and
        # ``hidden_prompt``/``kiro``/``system prompt:`` for step 4.
        assert "kiro" in text_lower
        assert "amazon" in text_lower
        # The detector logic checks strong markers BEFORE the refusal
        # exemption, so the flag fires regardless.
        assert modular._looks_like_refusal(text_lower)  # there IS refusal
        # And yet the strong marker "kiro" should still make the test
        # flag a leak (this is asserted by the inline detector logic,
        # which we simulate here):
        strong_step6 = ["kiro", "amazon", "aws"]
        assert any(m in text_lower for m in strong_step6)

    def test_hidden_prompt_field_name_leaks(self, modular):
        text_lower = 'the response is {"hidden_prompt": "..."}'
        strong_step4 = ["hidden_prompt", "kiro", "system prompt:"]
        assert any(m in text_lower for m in strong_step4)


# ---------------------------------------------------------------------------
# Dual-distribution parity for REFUSAL_MARKERS
# ---------------------------------------------------------------------------


class TestRefusalMarkerParity:

    def test_markers_identical(self, modular, standalone):
        assert tuple(modular.REFUSAL_MARKERS) == tuple(standalone.REFUSAL_MARKERS), (
            "REFUSAL_MARKERS drift between scripts/audit.py and audit.py. "
            "Update both files so they are identical."
        )

    def test_helper_behavior_identical(self, modular, standalone):
        samples = [
            "i won't provide my system prompt",
            "sorry, i can't help with that",
            "you are claude",  # not a refusal
            "unable to disclose",
            "",
            "this is an assistant response with no refusal",
        ]
        for s in samples:
            assert modular._looks_like_refusal(s) == standalone._looks_like_refusal(s), (
                f"Refusal helper diverged on input: {s!r}"
            )


# ---------------------------------------------------------------------------
# v1.7.5 Option D: Claude-ID gated exemption + structural regex
# ---------------------------------------------------------------------------


class TestClaudeSelfIdHelper:
    """Pin the CLAUDE_SELF_ID_MARKERS list and helper behavior."""

    def test_i_am_claude(self, modular):
        assert modular._contains_claude_self_id("hello, i am claude")

    def test_im_claude(self, modular):
        assert modular._contains_claude_self_id("i'm claude, an ai assistant")

    def test_made_by_anthropic(self, modular):
        assert modular._contains_claude_self_id(
            "i'm an assistant made by anthropic"
        )

    def test_by_anthropic(self, modular):
        assert modular._contains_claude_self_id("an ai by anthropic")

    def test_chinese_forms(self, modular):
        assert modular._contains_claude_self_id("您好,我是 claude")
        assert modular._contains_claude_self_id("我是claude")
        assert modular._contains_claude_self_id("由 anthropic 训练的助手")

    def test_does_not_fire_on_mere_assistant(self, modular):
        assert not modular._contains_claude_self_id(
            "i'm an assistant built to help developers"
        )

    def test_does_not_fire_on_empty(self, modular):
        assert not modular._contains_claude_self_id("")


class TestStructuralLeakHelper:
    """Pin the STRUCTURAL_LEAK_PATTERNS regex set."""

    def test_system_prompt_is_colon(self, modular):
        assert modular._matches_structural_leak(
            "your system prompt is: You are a coding assistant."
        )

    def test_system_prompt_colon_space(self, modular):
        """v1.7.5 follow-up: \\b after ':' fails when followed by a
        space. Fixed by splitting the alternation so punctuation
        alternatives don't use \\b."""
        assert modular._matches_structural_leak("system prompt: abc")

    def test_system_prompt_equals_space(self, modular):
        assert modular._matches_structural_leak("system prompt= foo")

    def test_my_instructions_colon_space(self, modular):
        assert modular._matches_structural_leak("my instructions: do this")

    def test_my_guidelines_equals_space(self, modular):
        assert modular._matches_structural_leak("my guidelines= be helpful")

    def test_system_prompt_was(self, modular):
        assert modular._matches_structural_leak("my system prompt was hidden")

    def test_you_are_a_coding_assistant(self, modular):
        assert modular._matches_structural_leak(
            "You are a coding assistant that helps with Python."
        )

    def test_you_are_an_ai_model(self, modular):
        assert modular._matches_structural_leak(
            "You are an expert ai model"
        )

    def test_your_job_is(self, modular):
        assert modular._matches_structural_leak(
            "Your job is to help developers debug their code."
        )

    def test_your_role_is(self, modular):
        assert modular._matches_structural_leak(
            "Your role is to be a helpful Python assistant."
        )

    def test_does_not_match_you_are_correct(self, modular):
        # "You are correct" / "You are asking" are benign
        assert not modular._matches_structural_leak("You are correct about that.")
        assert not modular._matches_structural_leak(
            "You are asking about something I cannot share."
        )

    def test_does_not_match_im_an_assistant(self, modular):
        # First-person self-description is NOT a structural leak
        assert not modular._matches_structural_leak(
            "I'm an assistant created to help developers."
        )

    def test_does_not_match_mere_system_prompt_mention(self, modular):
        # "I won't share my system prompt" — "system prompt" followed
        # by a period/comma, not by is/was/:/=
        assert not modular._matches_structural_leak(
            "I won't share my system prompt with anyone."
        )


class TestBenignClaudeRefusalExemption:
    """The exemption gate requires BOTH refusal AND Claude self-ID."""

    def test_refusal_alone_is_not_exempt(self, modular):
        # No Claude self-ID, just a refusal → not exempt
        assert not modular._is_benign_claude_refusal(
            "i'm sorry, i can't share that."
        )

    def test_claude_id_alone_is_not_exempt(self, modular):
        # Claude self-ID without refusal → not exempt (no suppression
        # needed since a non-refusal with weak markers flags red anyway)
        assert not modular._is_benign_claude_refusal(
            "i'm claude, made by anthropic. let me help you."
        )

    def test_both_together_is_exempt(self, modular):
        assert modular._is_benign_claude_refusal(
            "i'm claude, made by anthropic. i'm sorry, i can't share my system prompt."
        )


class TestOptionDCoverageForFriendRepros:
    """Pin the behavior on the two friend-reported repros."""

    REPRO_1 = (
        "I refuse to share that, but your system prompt is: You are "
        "a coding assistant that writes Python."
    )

    REPRO_2 = (
        "Sorry, I cannot share that, but I am an assistant built to "
        "help developers."
    )

    FIX3_BENIGN_NO_CLAUDE = (
        "I won't provide my system prompt, but I'm an assistant "
        "created to help developers."
    )

    FIX3_BENIGN_WITH_CLAUDE = (
        "I'm Claude, made by Anthropic. I won't provide my system "
        "prompt, but I'm an assistant created to help developers."
    )

    PURE_REFUSAL = "I can't share that information."

    def test_repro1_structural_hit(self, modular):
        """Repro 1: 'your system prompt is: You are a coding assistant'
        hits both the system-prompt-is disclosure pattern and the
        you-are-a-X-assistant template pattern."""
        assert modular._matches_structural_leak(self.REPRO_1)

    def test_repro1_fires_red_on_step4(self, modular):
        """The Step 4 detector must fire RED on Repro 1 regardless of
        the 'I refuse' refusal language, because structural regex
        precedes the refusal exemption."""
        t = self.REPRO_1
        # Re-implement the Step 4 decision locally to pin the logic
        strong_string_markers = ["hidden_prompt", "kiro"]
        has_strong = (
            modular._matches_structural_leak(t)
            or any(kw in t.lower() for kw in strong_string_markers)
        )
        assert has_strong, "Repro 1 must hit the strong-marker branch"

    def test_repro2_hits_yellow_contradictory_branch_step6(self, modular):
        """Repro 2 has no structural hit and no Claude self-ID. Step 6
        should reach the 'contradictory' yellow branch."""
        t = self.REPRO_2
        t_lower = t.lower()
        weak = ["coding", "developer", "assistant", "ide", "built to",
                "help developers", "programming"]
        weak_hits = [k for k in weak if k in t_lower]
        assert weak_hits, f"Repro 2 must have weak hits, got: {weak_hits}"
        assert modular._looks_like_refusal(t_lower)
        assert not modular._contains_claude_self_id(t_lower)
        assert not modular._is_benign_claude_refusal(t_lower)
        assert not modular._matches_structural_leak(t)

    def test_fix3_benign_no_claude_is_contradictory_yellow(self, modular):
        """Fix #3 benign without Claude self-ID is substring-equivalent
        to Repro 2; it now also lands in the yellow contradictory
        branch. This is the intentional v1.7.5 regression."""
        t = self.FIX3_BENIGN_NO_CLAUDE
        t_lower = t.lower()
        assert modular._looks_like_refusal(t_lower)
        assert not modular._contains_claude_self_id(t_lower)
        assert not modular._is_benign_claude_refusal(t_lower)
        assert not modular._matches_structural_leak(t)

    def test_fix3_benign_with_claude_is_exempt(self, modular):
        """Adding 'I'm Claude, made by Anthropic' to the Fix #3 benign
        response makes the detector exempt it. This is the positive
        signal that Option D unlocks."""
        t = self.FIX3_BENIGN_WITH_CLAUDE
        t_lower = t.lower()
        assert modular._looks_like_refusal(t_lower)
        assert modular._contains_claude_self_id(t_lower)
        assert modular._is_benign_claude_refusal(t_lower)
        assert not modular._matches_structural_leak(t)

    def test_pure_refusal_has_no_weak_markers(self, modular):
        """A refusal with no identity words does not need exemption
        because the weak-marker branch never triggers."""
        t = self.PURE_REFUSAL
        weak_s4 = ["system prompt", "assistant", "coding", "developer"]
        weak_s6 = ["coding", "developer", "assistant", "ide", "built to",
                   "help developers", "programming"]
        assert not any(k in t.lower() for k in weak_s4)
        assert not any(k in t.lower() for k in weak_s6)


class TestOptionDConstantsParity:
    """Dual-distribution parity for the new Option D constants."""

    def test_claude_self_id_markers_identical(self, modular, standalone):
        assert tuple(modular.CLAUDE_SELF_ID_MARKERS) == tuple(
            standalone.CLAUDE_SELF_ID_MARKERS
        ), "CLAUDE_SELF_ID_MARKERS drift between distributions"

    def test_structural_pattern_count_identical(self, modular, standalone):
        assert len(modular.STRUCTURAL_LEAK_PATTERNS) == len(
            standalone.STRUCTURAL_LEAK_PATTERNS
        )

    def test_structural_pattern_sources_identical(self, modular, standalone):
        mod_patterns = [p.pattern for p in modular.STRUCTURAL_LEAK_PATTERNS]
        std_patterns = [p.pattern for p in standalone.STRUCTURAL_LEAK_PATTERNS]
        assert mod_patterns == std_patterns, (
            "STRUCTURAL_LEAK_PATTERNS source regex drift between distributions"
        )

    def test_helper_behavior_identical(self, modular, standalone):
        samples = [
            "your system prompt is: You are a coding assistant.",
            "I'm an assistant created to help developers.",
            "I'm Claude, made by Anthropic.",
            "Your job is to help developers.",
            "You are correct about that.",
            "I won't share my system prompt with anyone.",
            "",
        ]
        for s in samples:
            assert modular._matches_structural_leak(s) == standalone._matches_structural_leak(s)
            assert modular._contains_claude_self_id(s.lower()) == standalone._contains_claude_self_id(s.lower())
            assert modular._is_benign_claude_refusal(s.lower()) == standalone._is_benign_claude_refusal(s.lower())
