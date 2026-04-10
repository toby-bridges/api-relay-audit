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
        """The 7 ASCII patterns verified from hvoy.ai's
        claude_detector.py IDENTITY_NEGATIVE_PATTERNS must be present."""
        for kw in ("glm", "deepseek", "qwen", "minimax", "grok", "gpt"):
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
        """Edge case: Claude saying 'I am Claude, not GPT' WILL trigger
        because 'gpt' is a substring. This test documents the known
        false-positive and is a regression guard if we change the
        matching strategy to be more context-aware in v1.7+."""
        text = "I am Claude, not GPT, made by Anthropic."
        matches = find_non_claude_identities(text)
        # Currently fires — document the known behavior
        assert "gpt" in matches
