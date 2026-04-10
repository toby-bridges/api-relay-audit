"""Tests for api_relay_audit.identity_patterns (v1.6 Step 5 helper)."""

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
        report output."""
        text = "I am DeepSeek, not Qwen, GLM, or GPT."
        matches = find_non_claude_identities(text)
        assert matches == sorted(matches)
        assert "deepseek" in matches
        assert "qwen" in matches
        assert "glm" in matches
        assert "gpt" in matches

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
        """Documented residual false positive: Claude saying 'I am Claude,
        not GPT' WILL trigger because 'GPT' appears as a standalone word
        (between commas, matching \\bgpt\\b). v1.6.1 word-boundary
        matching does not fix this specific case because the keyword IS
        a whole word in the input. Future work in v1.7+ could add
        identity-phrase anchors (e.g. only match after 'I am' / 'made by')
        to eliminate this. Regression guard."""
        text = "I am Claude, not GPT, made by Anthropic."
        matches = find_non_claude_identities(text)
        assert "gpt" in matches

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
