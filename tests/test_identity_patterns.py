"""Tests for api_relay_audit.identity_patterns (v1.6 Step 5 helper)."""

import api_relay_audit.identity_patterns as identity_module
from api_relay_audit.identity_patterns import (
    NON_CLAUDE_IDENTITY_KEYWORDS,
    find_non_claude_identities,
)


# ---------------------------------------------------------------------------
# NON_CLAUDE_IDENTITY_KEYWORDS content
# ---------------------------------------------------------------------------

class TestNonClaudeIdentityKeywords:
    def test_legacy_v21_keywords_present(self):
        """v2.1 keywords (Amazon/Kiro/AWS) must not be removed by the
        v1.6 port — they catch specific historical substitution cases."""
        for kw in ("amazon", "kiro", "aws"):
            assert kw in NON_CLAUDE_IDENTITY_KEYWORDS, (
                f"Legacy keyword {kw!r} missing from port"
            )

    def test_hvoy_ai_ascii_patterns_ported(self):
        """All 7 ASCII patterns verified from hvoy.ai's
        claude_detector.py IDENTITY_NEGATIVE_PATTERNS must be present.
        v1.6.1 fix: added explicit coverage for `z.ai` which was in
        the tuple but had no specific test (Codex NIT finding)."""
        for kw in (
            "glm",
            "z.ai",      # v1.6.1: Codex NIT, was missing
            "deepseek",
            "qwen",
            "minimax",
            "grok",
            "gpt",
        ):
            assert kw in NON_CLAUDE_IDENTITY_KEYWORDS

    def test_sub2api_antigravity_keywords_present(self):
        """v1.7.5: sub2api Antigravity relay identity keywords.
        Source-verified from Wei-Shaw/sub2api request_transformer.go."""
        for kw in ("antigravity", "deepmind"):
            assert kw in NON_CLAUDE_IDENTITY_KEYWORDS

    def test_extended_ascii_patterns_present(self):
        """Our v1.6 additions beyond hvoy.ai's set: brand aliases and
        Chinese-market substitutes hvoy.ai did not cover. v1.6.1 fix:
        added explicit coverage for `tongyi` (Codex NIT finding)."""
        for kw in (
            "zhipu",     # GLM parent
            "tongyi",    # v1.6.1: Codex NIT, was missing
            "ernie",
            "doubao",
            "moonshot",
            "kimi",
        ):
            assert kw in NON_CLAUDE_IDENTITY_KEYWORDS

    def test_chinese_brand_names_present(self):
        """Chinese brand names (for catching Chinese-language responses)
        must be present — this is our v1.6 extension beyond hvoy.ai."""
        for kw in ("通义", "千问", "智谱", "豆包", "文心"):
            assert kw in NON_CLAUDE_IDENTITY_KEYWORDS

    def test_keywords_are_all_lowercase_ascii_or_cjk(self):
        """Invariant: ASCII keywords must be lowercase (for consistent
        substring match against lowered text). Non-ASCII keywords are
        allowed as-is because str.lower() is a no-op on CJK."""
        for kw in NON_CLAUDE_IDENTITY_KEYWORDS:
            if kw.isascii():
                assert kw == kw.lower(), f"ASCII keyword {kw!r} is not lowercase"

    def test_no_duplicate_keywords(self):
        """No duplicates in the tuple."""
        assert len(NON_CLAUDE_IDENTITY_KEYWORDS) == len(set(NON_CLAUDE_IDENTITY_KEYWORDS))

    def test_keyword_rules_are_single_source_for_derived_sets(self):
        rules = identity_module._IDENTITY_KEYWORD_RULES
        assert len(rules) == len({kw for kw, _strategy in rules})
        assert tuple(kw for kw, _strategy in rules) == NON_CLAUDE_IDENTITY_KEYWORDS

        allowed_strategies = {
            identity_module._MATCH_LAX,
            identity_module._MATCH_STRICT,
            identity_module._MATCH_CONTEXT_STRICT,
        }
        assert {strategy for _kw, strategy in rules} <= allowed_strategies

        rule_map = dict(rules)
        assert identity_module._STRICT_ASCII_KEYWORDS == frozenset(
            kw for kw, strategy in rule_map.items()
            if strategy == identity_module._MATCH_STRICT
        )
        assert identity_module._CONTEXT_STRICT_KEYWORDS == frozenset(
            kw for kw, strategy in rule_map.items()
            if strategy == identity_module._MATCH_CONTEXT_STRICT
        )


# ---------------------------------------------------------------------------
# find_non_claude_identities
# ---------------------------------------------------------------------------

class TestFindNonClaudeIdentities:
    def test_empty_text_returns_empty(self):
        assert find_non_claude_identities("") == []

    def test_none_returns_empty(self):
        assert find_non_claude_identities(None) == []

    def test_claude_response_no_match(self):
        """A clean Claude response must not trigger any non-Claude keyword."""
        text = "I am Claude, an AI assistant made by Anthropic."
        assert find_non_claude_identities(text) == []

    def test_chinese_claude_response_no_match(self):
        """A clean Chinese Claude response must also not trigger."""
        text = "我是 Claude,由 Anthropic 公司创建的 AI 助手。"
        assert find_non_claude_identities(text) == []

    def test_deepseek_substitution_caught(self):
        text = "I'm DeepSeek-V3, a large language model built by DeepSeek Inc."
        matches = find_non_claude_identities(text)
        assert "deepseek" in matches

    def test_case_insensitive_matching(self):
        """DEEPSEEK in caps still matches."""
        text = "I am DEEPSEEK, not Claude."
        assert "deepseek" in find_non_claude_identities(text)

    def test_glm_with_zhipu_brand(self):
        """A GLM response often mentions Zhipu — both should be caught."""
        text = "I'm GLM-4.6, made by Zhipu AI."
        matches = find_non_claude_identities(text)
        assert "glm" in matches
        assert "zhipu" in matches

    def test_chinese_brand_qwen_tongyi(self):
        """Chinese response using 通义千问 brand must be caught."""
        text = "我是通义千问,由阿里巴巴集团创建。"
        matches = find_non_claude_identities(text)
        assert "通义" in matches
        assert "千问" in matches

    def test_multiple_matches_are_sorted(self):
        """Multiple matches must be returned sorted for deterministic
        report output. v1.7.2: 'gpt' is a STRICT keyword that needs an
        identity anchor — 'not GPT' no longer triggers. The lax
        keywords (deepseek, qwen, glm) still match because 'I am
        DeepSeek' is an identity anchor that matches via the strict
        path too, and qwen/glm use word-boundary lax matching."""
        text = "I am DeepSeek, not Qwen, GLM, or GPT."
        matches = find_non_claude_identities(text)
        assert matches == sorted(matches)
        assert "deepseek" in matches
        # qwen and glm are lax patterns — match anywhere they appear
        # as standalone words (word-boundary + non-letter lookahead)
        assert "qwen" in matches
        assert "glm" in matches
        # v1.7.2: gpt is a strict keyword; "not GPT" after a comma is
        # no longer matched because "I am" is followed by "DeepSeek",
        # not "GPT". This is the intended anchor refinement fix.
        assert "gpt" not in matches

    def test_legacy_amazon_still_caught(self):
        """v2.1 regression: the legacy Amazon pattern must still fire."""
        text = "I'm an AI assistant made by Amazon for AWS developers."
        matches = find_non_claude_identities(text)
        assert "amazon" in matches
        assert "aws" in matches

    def test_moonshot_kimi_both_caught(self):
        """Moonshot's model is called Kimi — both keywords should fire."""
        text = "I am Kimi, built by Moonshot AI."
        matches = find_non_claude_identities(text)
        assert "moonshot" in matches
        assert "kimi" in matches

    def test_no_false_positive_on_claude_mentioning_others(self):
        """v1.7.2 fix: Claude saying 'I am Claude, not GPT' no longer
        triggers 'gpt' because gpt is a strict keyword that requires
        an identity anchor phrase to IMMEDIATELY precede it (modulo
        0-4 filler words). The anchor 'I am' is followed by 'Claude',
        then ', not GPT' — the comma interrupts \\w+\\s+ so the filler
        cannot bridge to GPT. Regression guard for the v1.7.2 fix."""
        text = "I am Claude, not GPT, made by Anthropic."
        matches = find_non_claude_identities(text)
        assert "gpt" not in matches

    def test_strict_keyword_matched_with_direct_anchor(self):
        """v1.7.2 regression: a legitimate 'I am GPT-5' still matches."""
        matches = find_non_claude_identities("I am GPT-5 by OpenAI.")
        assert "gpt" in matches

    def test_strict_keyword_matched_with_article_filler(self):
        """v1.7.2 regression: 'I am a GPT-4 model' matches because the
        0-4 filler words slot allows 'a' between anchor and keyword."""
        matches = find_non_claude_identities("I am a GPT-4 model from OpenAI.")
        assert "gpt" in matches

    def test_strict_keyword_matched_with_chinese_anchor(self):
        """v1.7.2: Chinese anchor '我是' followed by strict keyword."""
        matches = find_non_claude_identities("我是 GPT-5, 由 OpenAI 创建")
        assert "gpt" in matches

    def test_grok_as_english_verb_not_matched(self):
        """v1.7.2 fix: 'I grok your question' (verb 'to grok') no longer
        triggers the grok keyword because it lacks an identity anchor."""
        matches = find_non_claude_identities(
            "I grok your question. Let me think about it."
        )
        assert "grok" not in matches

    def test_grok_as_model_still_matched(self):
        """v1.7.2 regression: 'I am Grok' still matches (anchor + keyword)."""
        matches = find_non_claude_identities("I am Grok, made by xAI.")
        assert "grok" in matches

    def test_aws_in_prose_not_matched(self):
        """v1.7.2: 'AWS infrastructure is cheaper' — not an identity
        claim, no anchor, no match."""
        matches = find_non_claude_identities(
            "AWS infrastructure is cheaper than GCP these days."
        )
        assert "aws" not in matches

    def test_aws_with_made_by_anchor_matched(self):
        """v1.7.2: 'made by AWS' — identity anchor, matches."""
        matches = find_non_claude_identities(
            "I am a language model made by AWS."
        )
        assert "aws" in matches

    def test_kimi_as_name_not_matched(self):
        """v1.7.2: 'Kimi is my friend' — Kimi as a person's name with
        no identity anchor. No match."""
        matches = find_non_claude_identities("Kimi is my friend from college.")
        assert "kimi" not in matches

    def test_kimi_as_model_matched(self):
        """v1.7.2: 'I am Kimi by Moonshot' — anchor + keyword, match."""
        matches = find_non_claude_identities("I am Kimi by Moonshot AI.")
        assert "kimi" in matches

    def test_not_without_comma_still_rejected_v173(self):
        """v1.7.3 Codex Round 6 LOW fix: 'I am Claude not GPT' (without
        a comma) must ALSO be rejected. Previously the `not` word was
        counted as a filler, so the 0-4 filler window bridged to GPT.
        The fix adds a negative lookahead `(?!not\\s|isn't\\s|...)` to
        the filler pattern."""
        text = "I am Claude not GPT, just Claude."
        matches = find_non_claude_identities(text)
        assert "gpt" not in matches, (
            "v1.7.3 regression: 'not' as filler word should block the "
            "strict keyword match"
        )

    def test_unlike_also_rejected_v173(self):
        """v1.7.3: 'unlike' as a filler word also blocks the match."""
        text = "I am a model unlike GPT in that it has a knowledge cutoff"
        matches = find_non_claude_identities(text)
        assert "gpt" not in matches

    # ----- v1.6.1 word-boundary matching (Codex LOW finding) -----

    def test_aws_not_matched_inside_laws(self):
        """v1.6.1 Codex LOW fix: 'laws' must NOT match 'aws'. Under
        v1.6 substring matching, 'I comply with all local laws' would
        incorrectly trip the aws keyword. Word-boundary regex fixes this."""
        matches = find_non_claude_identities("I comply with all local laws.")
        assert "aws" not in matches

    def test_aws_standalone_word_still_caught(self):
        """v1.6.1 regression guard: word-boundary must not break legitimate
        AWS detection when 'AWS' appears as a standalone token."""
        matches = find_non_claude_identities("I am AWS Bedrock Claude.")
        assert "aws" in matches

    def test_grok_inside_compound_word_not_matched(self):
        """v1.6.1: 'grokking' (English verb form) must not trip 'grok'
        because word boundary requires the match to END at a non-word char."""
        matches = find_non_claude_identities("I'm grokking your question.")
        assert "grok" not in matches

    def test_glm_inside_longer_word_not_matched(self):
        """v1.6.1: 'glmrules' must not trip 'glm'."""
        matches = find_non_claude_identities("I follow glmrules.txt")
        assert "glm" not in matches

    def test_kiro_inside_longer_word_not_matched(self):
        """v1.6.1: 'kirosaki' (a surname) must not trip 'kiro'."""
        matches = find_non_claude_identities("My doctor's name is Kirosaki.")
        assert "kiro" not in matches

    def test_zai_matched_case_insensitive(self):
        """v1.6.1 Codex NIT: explicit coverage for z.ai keyword matching.
        Both lowercase and uppercase forms must work."""
        for text in (
            "I am a Z.AI model.",
            "Built by z.ai for enterprise use.",
            "Z.ai Inc. operates this service.",
        ):
            matches = find_non_claude_identities(text)
            assert "z.ai" in matches, f"Expected z.ai to match in {text!r}"

    def test_zai_not_matched_when_embedded(self):
        """v1.6.1: z.ai must not match when embedded in a longer token
        like 'abcz.ai' (e.g. a URL slug)."""
        matches = find_non_claude_identities("host=abcz.ai port=443")
        assert "z.ai" not in matches

    def test_tongyi_matched_case_insensitive(self):
        """v1.6.1 Codex NIT: explicit coverage for tongyi keyword."""
        for text in (
            "I am Tongyi Qianwen, made by Alibaba.",
            "Powered by TONGYI large language model.",
        ):
            matches = find_non_claude_identities(text)
            assert "tongyi" in matches, f"Expected tongyi to match in {text!r}"

    def test_cjk_substring_match_unchanged(self):
        """v1.6.1 sanity: CJK keywords still use substring match because
        Python re has no meaningful word boundaries for CJK scripts."""
        matches = find_non_claude_identities("我是通义千问,由阿里巴巴创建。")
        assert "通义" in matches
        assert "千问" in matches

    # ----- v1.6.2 trailing lookahead (Codex MEDIUM finding) -----

    def test_qwen_with_version_suffix_matches(self):
        """v1.6.2 Codex finding: version-suffixed Qwen should match with
        trailing non-letter lookahead (fixes Qwen2.5 false negatives)."""
        text = "I am Qwen2.5-72B, a large language model."
        matches = find_non_claude_identities(text)
        assert "qwen" in matches

    def test_glm_with_digit_suffix_matches(self):
        """v1.6.2 Codex finding: GLM4.6 must match despite digit suffix,
        and Zhipu brand mention should still be caught."""
        text = "I am GLM4.6 made by Zhipu AI."
        matches = find_non_claude_identities(text)
        assert "glm" in matches
        assert "zhipu" in matches

    def test_gpt_with_digit_suffix_matches(self):
        """v1.6.2 Codex finding: GPT4 must match despite digit suffix."""
        text = "I am GPT4 by OpenAI."
        matches = find_non_claude_identities(text)
        assert "gpt" in matches

    def test_underscore_separator_matches_glm(self):
        """v1.6.2 Codex finding: underscores are non-letters so glm_large
        must still match the glm keyword."""
        text = "I use glm_large from the model hub."
        matches = find_non_claude_identities(text)
        assert "glm" in matches

    def test_version_suffix_preserves_substring_safety(self):
        """v1.6.2 Codex finding: loosening the trailing boundary must not
        reintroduce v1.6 substring false positives."""
        for text in (
            "I comply with all local laws.",
            "I follow glmrules.txt",
            "I'm grokking your question.",
        ):
            assert find_non_claude_identities(text) == []

    def test_sub2api_antigravity_identity_caught(self):
        """v1.7.5: sub2api's Antigravity mode injects 'You are
        Antigravity, a powerful agentic AI coding assistant designed
        by the Google Deepmind team'. Both keywords must fire."""
        text = (
            "I am Antigravity, a powerful agentic AI coding assistant "
            "designed by the Google Deepmind team."
        )
        matches = find_non_claude_identities(text)
        assert "antigravity" in matches
        assert "deepmind" in matches

    def test_antigravity_case_insensitive(self):
        text = "I'm ANTIGRAVITY, built by DeepMind."
        matches = find_non_claude_identities(text)
        assert "antigravity" in matches
        assert "deepmind" in matches

    def test_deepmind_alone_caught(self):
        """A relay might mention only Deepmind without Antigravity."""
        text = "I was developed by Google DeepMind researchers."
        matches = find_non_claude_identities(text)
        assert "deepmind" in matches

    def test_antigravity_no_false_positive_on_gravity(self):
        """The word 'gravity' must not trigger 'antigravity'."""
        text = "Gravity is a fundamental force of nature."
        assert find_non_claude_identities(text) == []


# ---------------------------------------------------------------------------
# v1.7.6: Warp / Windsurf reverse-proxy dev-tool channels (cctest.ai FAQ)
#
# Unlike sub2api's Antigravity injection, these platforms do NOT inject
# a literal identity phrase. The brand label only occasionally bleeds
# through. Classified as strict-tier because both are common English
# words that must not false-match in ordinary prose.
# ---------------------------------------------------------------------------

class TestWarpWindsurfChannels:
    def test_warp_windsurf_keywords_present(self):
        for kw in ("warp", "windsurf"):
            assert kw in NON_CLAUDE_IDENTITY_KEYWORDS

    def test_warp_with_identity_anchor_matched(self):
        text = "I am a Warp assistant, made by Warp Inc."
        assert "warp" in find_non_claude_identities(text)

    def test_warp_identity_with_comma(self):
        """'I am Warp, ...' — keyword followed by comma → identity."""
        assert "warp" in find_non_claude_identities("I am Warp, an AI assistant.")

    def test_warp_identity_with_period(self):
        """'I'm Warp.' — keyword followed by period → identity."""
        assert "warp" in find_non_claude_identities("I'm Warp.")

    def test_warp_as_prose_not_matched(self):
        for text in (
            "Engage warp speed, Captain.",
            "The canvas has a slight warp.",
            "I can help you with time warp calculations.",
        ):
            assert find_non_claude_identities(text) == []

    def test_warp_with_anchor_but_non_identity_context(self):
        """v1.7.7 Codex fix: 'I am in warp speed mode' has anchor 'I am'
        and keyword 'warp', but 'speed' is not an identity suffix — this
        is a false positive that the context-strict pattern must reject."""
        assert find_non_claude_identities("I am in warp speed mode.") == []

    def test_windsurf_with_identity_anchor_matched(self):
        text = "I'm Windsurf, an AI coding assistant."
        assert "windsurf" in find_non_claude_identities(text)

    def test_windsurf_identity_with_by(self):
        """'I am Windsurf by ...' — 'by' is an identity suffix."""
        assert "windsurf" in find_non_claude_identities(
            "I am Windsurf by Codeium.")

    def test_windsurf_as_prose_not_matched(self):
        text = "My hobby is windsurf and sailing on weekends."
        assert find_non_claude_identities(text) == []

    def test_windsurf_with_anchor_but_non_identity_context(self):
        """v1.7.7 Codex fix: 'I am a windsurf instructor' — anchor
        'I am a' + keyword 'windsurf' + 'instructor' (not identity
        suffix) → must NOT match."""
        assert find_non_claude_identities("I am a windsurf instructor.") == []

    def test_claude_mentioning_warp_windsurf_not_matched(self):
        text = (
            "I am Claude, made by Anthropic. I can compare with other "
            "coding tools like Warp and Windsurf if you want."
        )
        assert find_non_claude_identities(text) == []

    def test_warp_with_ai_suffix_matched(self):
        """'call me Warp AI' — 'AI' is an identity suffix → match."""
        assert "warp" in find_non_claude_identities("You can call me Warp AI.")


# ---------------------------------------------------------------------------
# v1.7.7: CJK no-whitespace fix (ROADMAP residual #1)
#
# Chinese has no whitespace convention between words. "我是GPT-5"
# (zero spaces between CJK anchor and ASCII keyword) must match.
# ---------------------------------------------------------------------------

class TestCJKNoWhitespace:
    def test_chinese_anchor_no_space_gpt(self):
        """我是GPT-5 (zero space) must match gpt."""
        assert "gpt" in find_non_claude_identities("我是GPT-5")

    def test_chinese_anchor_with_space_still_works(self):
        """我是 GPT-5 (with space) must still match — regression guard."""
        assert "gpt" in find_non_claude_identities("我是 GPT-5, 由 OpenAI 创建")

    def test_chinese_anchor_no_space_kiro(self):
        """我是Kiro (zero space) must match kiro."""
        assert "kiro" in find_non_claude_identities("我是Kiro，一个AI助手。")

    def test_chinese_anchor_no_space_warp(self):
        """我叫Warp (zero space) must match warp."""
        assert "warp" in find_non_claude_identities("我叫Warp，很高兴为你服务。")

    def test_chinese_anchor_no_space_aws(self):
        """我是AWS Bedrock的模型 must match aws."""
        assert "aws" in find_non_claude_identities("我是AWS Bedrock的Claude模型。")

    def test_chinese_anchor_no_space_grok(self):
        """我是Grok must match grok."""
        assert "grok" in find_non_claude_identities("我是Grok，由xAI开发。")

    def test_chinese_no_space_does_not_affect_english(self):
        """English 'I amGPT' (no space, typo) should NOT match because
        \\b fails between two ASCII word chars."""
        assert find_non_claude_identities("I amGPT model") == []

    def test_chinese_prose_warp_no_false_positive(self):
        """Chinese prose mentioning warp without identity anchor: no match."""
        assert find_non_claude_identities("曲速warp引擎是科幻概念。") == []

    def test_chinese_anchor_warp_speed_no_false_positive(self):
        """v1.7.7 Codex fix: CJK path must also enforce context-strict
        identity suffix. '我是warp speed模式' has CJK anchor + keyword
        but 'speed' is not an identity suffix."""
        assert find_non_claude_identities("我是warp speed模式。") == []

    def test_chinese_anchor_windsurf_instructor_no_false_positive(self):
        """v1.7.7 Codex fix: '我叫windsurf instructor' must not match."""
        assert find_non_claude_identities("我叫windsurf instructor。") == []

    def test_chinese_anchor_warp_with_identity_suffix(self):
        """CJK context-strict: '我是Warp，' (comma after) → match."""
        assert "warp" in find_non_claude_identities("我是Warp，一个AI助手。")


# ---------------------------------------------------------------------------
# v1.7.7: Filler cap expansion {0,4} → {0,6} (ROADMAP residual #2)
#
# Verbose self-identification with 5-6 filler words between anchor and
# keyword must now be caught.
# ---------------------------------------------------------------------------

class TestFillerCapExpansion:
    def test_five_filler_words_now_matched(self):
        """'I'm an advanced conversational AI system called GPT-5'
        has 5 filler words — was missed with {0,4}, now caught."""
        text = "I'm an advanced conversational AI system called GPT-5."
        assert "gpt" in find_non_claude_identities(text)

    def test_six_filler_words_now_matched(self):
        """6 filler words — edge of new cap."""
        text = "I am a very large advanced language model called GPT-5."
        assert "gpt" in find_non_claude_identities(text)

    def test_seven_filler_words_not_matched(self):
        """7 filler words — exceeds {0,6}, should NOT match via this
        anchor (may still match via backup anchors in text)."""
        text = "I'm a really very extremely large advanced conversational system GPT-5."
        # "I'm" anchor + 7 fillers before GPT → too many
        # No backup anchor in this text → no match
        assert "gpt" not in find_non_claude_identities(text)

    def test_four_filler_still_works(self):
        """Regression: 4 filler words (previous cap) still works."""
        text = "I am a large language model GPT-5."
        assert "gpt" in find_non_claude_identities(text)

    def test_negation_still_blocked_with_new_cap(self):
        """Raising the cap must not break negation filtering."""
        text = "I am Claude not a replacement for GPT."
        assert "gpt" not in find_non_claude_identities(text)

    def test_backup_anchor_still_catches_very_verbose(self):
        """Even with >6 fillers from 'I'm', a backup anchor like
        'fine-tuned by' catches the keyword within its own window."""
        text = (
            "I'm an advanced conversational AI system "
            "fine-tuned by OpenAI called GPT-5."
        )
        assert "gpt" in find_non_claude_identities(text)
