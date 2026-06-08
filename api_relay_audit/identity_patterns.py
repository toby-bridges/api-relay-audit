"""Non-Claude identity keywords for relay substitution detection.

Used by Step 5 (Instruction Override tests) to flag responses that
self-identify as a non-Claude model despite a ``"You are Claude by
Anthropic"`` system prompt. When a relay routes your request to a
cheaper domestic substitute (GLM, DeepSeek, Qwen, etc.) instead of
the advertised Claude model, the substitute model's own identity
bleeds through in the response — and we can detect it cheaply by
checking for a known list of non-Claude model / brand names.

## Matching strategy (v1.6.1)

ASCII keywords use a **leading word-boundary regex** (``\\b<kw>``,
case-insensitive) to avoid substring collisions with common English
words. For example, under the v1.6 substring approach, ``"aws"``
would spuriously match ``"laws"`` / ``"paws"`` / ``"draws"``; the
v1.6.1 word-boundary approach only matches ``aws`` as a standalone
token. Codex review finding, 2026-04-11.

v1.6.2 note: the trailing ``\\b`` was loosened to a negative-letter
lookahead (``(?![a-zA-Z])``) so version-suffixed model names like
``Qwen2.5``, ``GPT4``, or ``GLM4.6`` still match while alphabetic
continuations (``grokking``, ``glmrules``) remain blocked. Codex
review round 3, 2026-04-11.

CJK keywords (Chinese brand names) use plain substring matching
because CJK scripts have no word-boundary concept in Python's ``re``
engine. CJK tokens are distinctive enough that false positives on
random prose are extremely rare.

## Residual false positives (documented)

Word-boundary matching still trips on standalone-word false positives
such as ``"I grok your question"`` (where ``grok`` is a legitimate
English verb), ``"Kimi is my friend"`` (as a person's name), or
``"I am Claude, not GPT"`` (documented in the regression test).
These are rare in a 200-token answer to "Who are you? Who made you?"
and we accept the residual noise in exchange for implementation
simplicity. Future work (v1.7+) could require identity-phrase anchors
(``"I am X"`` / ``"made by X"``) to eliminate these.

## Attribution

The identity-substitution detection *concept* is inspired by hvoy.ai
(`https://hvoy.ai/`) and its backing repo
`github.com/zzsting88/relayAPI` `claude_detector.py`
``IDENTITY_NEGATIVE_PATTERNS``. The repo has no explicit LICENSE file,
so this module is an **independent reimplementation** of the concept
(not a code copy):

- We use a plain tuple of keyword literals + a compiled regex cache,
  not hvoy.ai's per-pattern regex list.
- The keyword set extends theirs (glm / z.ai / deepseek / minimax /
  grok / qwen / gpt) with additional Chinese-market substitutes
  (Zhipu / Tongyi / ERNIE / Doubao / Moonshot / Kimi) and Chinese
  brand names (通义 / 千问 / 智谱 / 豆包 / 文心 / 月之暗面) for
  catching responses in Chinese.
- The matching function is our own.

Verified against hvoy.ai's source on 2026-04-11. See the
``reference_hvoy_relayapi`` memory file for the full review of what
their tool does and does not detect.
"""

import re


# Keyword literals that, if present in a response to "Who are you?
# Who made you?", indicate that the response is self-identifying as
# something other than Claude/Anthropic. See module docstring for the
# evidence boundary: this is an identity-consistency signal, not
# standalone attribution proof.
#
# Groups (not enforced by code, just for readability):
#   1. Legacy (v2.1)        — Amazon / AWS brand leakage from earlier audits
#   2. hvoy.ai verified     — ASCII model names from hvoy.ai's exact
#                              IDENTITY_NEGATIVE_PATTERNS regex list
#   3. Extended ASCII       — our additions (Zhipu / Tongyi brand aliases
#                              for hvoy.ai's glm / qwen + Chinese-market
#                              substitutes hvoy.ai did not cover)
#   4. ZenMux calibration   — current frontier-vendor aliases observed in
#                              ZenMux Arena's 2026-06-01 "Who Are You?" run
#   5. Chinese brand names  — CJK literals for catching Chinese-language
#                              responses that use the Chinese brand instead
#                              of the ASCII model name
NON_CLAUDE_IDENTITY_KEYWORDS = (
    # 1. Legacy (v2.1)
    "amazon",
    "kiro",
    "aws",
    # 2. hvoy.ai verified ASCII substitutes (exact regex list from
    #    claude_detector.py IDENTITY_NEGATIVE_PATTERNS, verified 2026-04-11)
    "glm",
    "z.ai",
    "deepseek",
    "qwen",
    "minimax",
    "grok",
    "gpt",
    # 3. sub2api / Antigravity relay identity (v1.7.5, source-verified
    #    from Wei-Shaw/sub2api request_transformer.go:179-186)
    "antigravity",  # sub2api injected identity: "You are Antigravity"
    "deepmind",     # sub2api injected identity: "designed by the Google Deepmind team"
    # 4. Reverse-proxy dev-tool platforms (v1.7.6, sourced from cctest.ai
    #    FAQ 2026-04-13). Unlike sub2api's Antigravity injection, these
    #    platforms do NOT inject a literal identity phrase; the channel
    #    label only occasionally bleeds through — classified as strict
    #    (anchor-required) because both are common English words.
    "warp",       # "warp speed", "time warp" in prose
    "windsurf",   # the watersport
    # 5. Extended ASCII (our additions — aliases and Chinese-market
    #    substitutes not in hvoy.ai's set)
    "zhipu",     # Zhipu AI, parent of GLM
    "tongyi",    # Alibaba Tongyi, parent of Qwen
    "ernie",     # Baidu ERNIE
    "doubao",    # ByteDance Doubao
    "moonshot",  # Moonshot AI
    "kimi",      # Moonshot's Kimi product
    # 6. Current frontier-vendor aliases from ZenMux Arena identity data
    #    (2026-06-01 mix). These broaden Step 5 from a China-substitute
    #    keyword set into a natural-language identity consistency signal.
    "openai",
    "chatgpt",
    "chat gpt",
    "google",
    "gemini",
    "x-ai",
    "x.ai",
    "xai",
    "baidu",
    "xiaomi",
    "tencent",
    "hunyuan",
    "stepfun",
    "step fun",
    "kwai",
    "kuaishou",
    "kat-coder",
    "kat coder",
    "katcoder",
    "inclusionai",
    "inclusion ai",
    "mistral",
    "microsoft",
    # 7. Chinese brand names (catch Chinese-language responses)
    "通义",
    "千问",
    "智谱",
    "豆包",
    "文心",
    "月之暗面",
    "百度",
    "小米",
    "腾讯",
    "混元",
    "阶跃",
    "阶跃星辰",
    "快手",
    "可灵",
    "百灵",
)


# v1.7.2 two-tier matching: short / common English-word keywords need
# an identity-phrase anchor to avoid false positives like "I am Claude,
# not GPT" or "I grok your question". Distinctive keywords like
# "deepseek" / "qwen" / "minimax" don't need anchors because they can't
# appear in ordinary English prose.
_STRICT_ASCII_KEYWORDS = frozenset({
    # Legacy short v2.1 keywords
    "amazon",
    "kiro",
    "aws",
    # Short/common ASCII words from hvoy.ai and our extensions
    "grok",   # English slang verb "to grok"
    "gpt",    # "unlike GPT" / "not GPT" prose
    "ernie",  # common given name (Sesame Street)
    "kimi",   # common given name
    # ZenMux-calibrated current vendor names that are high-signal only
    # when used as an identity claim, not as ordinary product references.
    "openai",
    "chatgpt",
    "chat gpt",
    "google",
    "gemini",
    "x-ai",
    "x.ai",
    "xai",
    "baidu",
    "xiaomi",
    "tencent",
    "hunyuan",
    "stepfun",
    "step fun",
    "kwai",
    "kuaishou",
    "kat-coder",
    "kat coder",
    "katcoder",
    "inclusionai",
    "inclusion ai",
    "mistral",
    "microsoft",
})

# v1.7.7: context-strict keywords require BOTH an identity anchor AND
# a post-keyword identity signal (punctuation or role word like
# "assistant" / "AI" / "model"). This eliminates false positives like
# "I am in warp speed mode" or "I am a windsurf instructor" where the
# keyword is used as a common noun, not a brand identity claim.
_CONTEXT_STRICT_KEYWORDS = frozenset({
    "warp",       # "warp speed" / "time warp" in prose
    "windsurf",   # the watersport
})

# Identity anchor phrases that must immediately precede (up to ~4 filler
# words of distance) a strict keyword for it to count as a model
# self-identification claim. Covers English and Chinese forms.
_IDENTITY_ANCHOR_ALTERNATION = (
    r"i am|i'm|i am a|i'm a|i am an|i'm an|i am the|i'm the|"
    r"i was made|i was created|i was developed|i was built|i was trained|"
    r"i was released|i was fine[- ]?tuned|"
    r"made by|created by|developed by|built by|trained by|powered by|"
    r"released by|fine[- ]?tuned by|"
    r"my name is|my name's|call me|you can call me|"
    r"we are|we're|"
    # Chinese anchors
    r"我是|我叫|本人是|我的名字|我是一个|我是个|本 ?ai"
)


def _build_strict_pattern(keyword):
    """Build an anchored regex for a strict keyword.

    Matches only when the keyword appears after an identity anchor
    phrase, optionally separated by 0-6 filler words (articles,
    adjectives, ``called``, ``named``, etc.).

    **v1.7.3 Codex fix**: the filler pattern now uses
    ``(?!not\\s|isn't\\s|aren't\\s)`` to exclude negation words.
    This prevents false positives like ``"I am Claude not GPT"``
    (without a comma) which v1.7.2 still matched because "Claude not"
    counted as two filler words bridging the anchor to the keyword.

    The trailing ``(?![a-zA-Z])`` preserves the v1.6.2 version-suffix
    fix so ``GPT4`` still matches.

    **v1.7.7 fix**: filler cap raised from ``{0,4}`` to ``{0,6}`` to
    catch verbose self-IDs like ``"I'm an advanced conversational AI
    system called GPT-5"`` (5 filler words). ROADMAP residual #2.
    """
    return re.compile(
        r"(?:" + _IDENTITY_ANCHOR_ALTERNATION + r")"
        r"\s+(?:(?!not\s|isn'?t\s|aren'?t\s|wasn'?t\s|weren'?t\s|unlike\s)\w+\s+){0,6}?"
        r"\b" + re.escape(keyword) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    )


# v1.7.7: post-keyword identity signal for context-strict keywords.
# Requires that the keyword is followed by punctuation (comma, period,
# etc.), an identity-role word (assistant, AI, model, ...), or end-of-
# string. This prevents "I am in warp speed" or "I am a windsurf
# instructor" from matching while "I am Warp, an AI assistant" still does.
_IDENTITY_SUFFIX_PATTERN = (
    r"(?:"
    r"\s*[,.:;!?)\-—，。！？；）]"   # half-width + CJK full-width punctuation
    r"|\s+(?:assistant|ai|model|bot|chatbot|agent|by|from|made|created|"
    r"developed|built|designed|trained|powered|an?\s)"
    r"|\s*$"
    r")"
)


def _build_context_strict_pattern(keyword):
    """Build a context-strict pattern for keywords like ``warp`` / ``windsurf``.

    Same as :func:`_build_strict_pattern` but with an additional
    post-keyword identity-signal requirement. See
    ``_IDENTITY_SUFFIX_PATTERN`` for the allowed suffixes.
    """
    return re.compile(
        r"(?:" + _IDENTITY_ANCHOR_ALTERNATION + r")"
        r"\s+(?:(?!not\s|isn'?t\s|aren'?t\s|wasn'?t\s|weren'?t\s|unlike\s)\w+\s+){0,6}?"
        r"\b" + re.escape(keyword) + r"(?![a-zA-Z])"
        + _IDENTITY_SUFFIX_PATTERN,
        re.IGNORECASE,
    )


# Precompile patterns. Strict keywords use anchor-gated regex; lax
# (distinctive) keywords use the v1.6.2 word-boundary + non-letter
# lookahead. CJK keywords stay on substring matching.
_STRICT_ASCII_PATTERNS = tuple(
    (kw, _build_strict_pattern(kw))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _STRICT_ASCII_KEYWORDS
)
_CONTEXT_STRICT_PATTERNS = tuple(
    (kw, _build_context_strict_pattern(kw))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _CONTEXT_STRICT_KEYWORDS
)
_LAX_ASCII_PATTERNS = tuple(
    (kw, re.compile(r"\b" + re.escape(kw) + r"(?![a-zA-Z])", re.IGNORECASE))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw.isascii() and kw not in _STRICT_ASCII_KEYWORDS
    and kw not in _CONTEXT_STRICT_KEYWORDS
)
_CJK_KEYWORDS = tuple(
    kw for kw in NON_CLAUDE_IDENTITY_KEYWORDS if not kw.isascii()
)

# v1.7.7: CJK-anchor supplementary patterns for strict keywords.
# Chinese has no whitespace convention between words, so "我是GPT-5"
# (zero spaces) must also match. The main _STRICT_ASCII_PATTERNS regex
# requires \s+ after the anchor and \b before the keyword — both fail
# when a CJK character directly precedes an ASCII keyword. These
# supplementary patterns use CJK-only anchors + \s* (zero-or-more
# whitespace) and drop \b (unnecessary after a CJK char). ROADMAP
# residual #1.
_CJK_ANCHOR_ALTERNATION = (
    r"我是|我叫|本人是|我的名字是?|我是一个|我是个|本 ?ai"
)
# Regular strict keywords: CJK anchor + keyword (no suffix needed).
_CJK_STRICT_PATTERNS = tuple(
    (kw, re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(kw) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    ))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _STRICT_ASCII_KEYWORDS
)
# Context-strict keywords: CJK anchor + keyword + identity suffix.
# Without the suffix, "我是warp speed模式" would false-positive.
_CJK_CONTEXT_STRICT_PATTERNS = tuple(
    (kw, re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(kw) + r"(?![a-zA-Z])"
        + _IDENTITY_SUFFIX_PATTERN,
        re.IGNORECASE,
    ))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _CONTEXT_STRICT_KEYWORDS
)

# v1.7.8: CJK-anchor supplementary patterns for lax ASCII keywords.
# The normal lax regex starts with \b, but Python treats CJK letters as
# word characters, so "我是DeepSeek" has no word boundary before D and
# used to be missed. Keep this path anchor-gated so ordinary prose such
# as "讨论DeepSeek发布节奏" does not become a match solely because a CJK
# character precedes an ASCII model name.
_CJK_LAX_ASCII_PATTERNS = tuple(
    (kw, re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(kw) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    ))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw.isascii() and kw not in _STRICT_ASCII_KEYWORDS
    and kw not in _CONTEXT_STRICT_KEYWORDS
)


def find_non_claude_identities(text: str) -> list:
    """Return a sorted list of non-Claude identity keywords found in text.

    v1.7.2 two-tier matching:

    - **Strict** keywords (``amazon``, ``kiro``, ``aws``, ``grok``,
      ``gpt``, ``ernie``, ``kimi``) must appear after an identity
      anchor phrase (``"I am"`` / ``"made by"`` / ``"我是"`` / ...).
      Eliminates false positives like ``"I am Claude, not GPT"``
      and ``"I grok your question"``.
    - **Lax** keywords (``deepseek``, ``glm``, ``qwen``, ``minimax``,
      etc.) use word-boundary + non-letter lookahead because these
      distinctive tokens don't appear in ordinary prose.
    - **CJK** keywords (``通义``, ``千问``, ...) use substring match
      because Python's ``re`` engine has no useful word-boundary
      semantics for CJK scripts.

    Args:
        text: The model response text to scan. Empty / None returns [].

    Returns:
        Sorted list of matched keywords (in their canonical form
        from ``NON_CLAUDE_IDENTITY_KEYWORDS``). Empty if no match.

    Examples:
        >>> find_non_claude_identities("I am Claude, made by Anthropic.")
        []
        >>> find_non_claude_identities("I am Claude, not GPT, made by Anthropic.")
        []
        >>> find_non_claude_identities("I am GPT-5 by OpenAI.")
        ['gpt']
        >>> find_non_claude_identities("I'm DeepSeek-V3, an assistant.")
        ['deepseek']
        >>> find_non_claude_identities("我是通义千问,由阿里巴巴创建。")
        ['千问', '通义']
        >>> find_non_claude_identities("I comply with local laws.")
        []
    """
    if not text:
        return []
    matched = []
    for keyword, pattern in _STRICT_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    # v1.7.7: context-strict keywords (warp, windsurf) need both anchor
    # AND post-keyword identity signal.
    for keyword, pattern in _CONTEXT_STRICT_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    # v1.7.7: CJK-anchor supplementary check for strict keywords.
    for keyword, pattern in _CJK_STRICT_PATTERNS:
        if keyword not in matched and pattern.search(text):
            matched.append(keyword)
    # v1.7.7: CJK-anchor + identity suffix for context-strict keywords.
    for keyword, pattern in _CJK_CONTEXT_STRICT_PATTERNS:
        if keyword not in matched and pattern.search(text):
            matched.append(keyword)
    # v1.7.8: CJK-anchor + no-whitespace path for distinctive lax
    # ASCII model/vendor names such as "我是DeepSeek".
    for keyword, pattern in _CJK_LAX_ASCII_PATTERNS:
        if keyword not in matched and pattern.search(text):
            matched.append(keyword)
    for keyword, pattern in _LAX_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    for keyword in _CJK_KEYWORDS:
        if keyword in text:
            matched.append(keyword)
    return sorted(matched)
