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


# Matching strategies for keyword rules. Keep these string values simple:
# tests and standalone parity inspect the derived structures directly.
_MATCH_LAX = "lax"
_MATCH_STRICT = "strict"
_MATCH_CONTEXT_STRICT = "context_strict"


# Keyword rules that, if matched in a response to "Who are you? Who made
# you?", indicate that the relay is routing to a non-Claude substitute
# model. This table is the single source of truth for both the public
# keyword tuple and the compiled pattern caches below.
#
# Groups (not enforced by code, just for readability):
#   1. Legacy (v2.1)        — Amazon / AWS brand leakage from earlier audits
#   2. hvoy.ai verified     — ASCII model names from hvoy.ai's exact
#                              IDENTITY_NEGATIVE_PATTERNS regex list
#   3. Extended ASCII       — our additions (Zhipu / Tongyi brand aliases
#                              for hvoy.ai's glm / qwen + Chinese-market
#                              substitutes hvoy.ai did not cover)
#   4. Chinese brand names  — CJK literals for catching Chinese-language
#                              responses that use the Chinese brand instead
#                              of the ASCII model name
_IDENTITY_KEYWORD_RULES = (
    # 1. Legacy (v2.1)
    ("amazon", _MATCH_STRICT),
    ("kiro", _MATCH_STRICT),
    ("aws", _MATCH_STRICT),
    # 2. hvoy.ai verified ASCII substitutes (exact regex list from
    #    claude_detector.py IDENTITY_NEGATIVE_PATTERNS, verified 2026-04-11)
    ("glm", _MATCH_LAX),
    ("z.ai", _MATCH_LAX),
    ("deepseek", _MATCH_LAX),
    ("qwen", _MATCH_LAX),
    ("minimax", _MATCH_LAX),
    ("grok", _MATCH_STRICT),
    ("gpt", _MATCH_STRICT),
    # 3. sub2api / Antigravity relay identity (v1.7.5, source-verified
    #    from Wei-Shaw/sub2api request_transformer.go:179-186)
    ("antigravity", _MATCH_LAX),  # sub2api injected identity: "You are Antigravity"
    ("deepmind", _MATCH_LAX),     # sub2api injected identity: "designed by the Google Deepmind team"
    # 4. Reverse-proxy dev-tool platforms (v1.7.6, sourced from cctest.ai
    #    FAQ 2026-04-13). Unlike sub2api's Antigravity injection, these
    #    platforms do NOT inject a literal identity phrase; the channel
    #    label only occasionally bleeds through — classified as strict
    #    (anchor-required) because both are common English words.
    ("warp", _MATCH_CONTEXT_STRICT),       # "warp speed", "time warp" in prose
    ("windsurf", _MATCH_CONTEXT_STRICT),   # the watersport
    # 5. Extended ASCII (our additions — aliases and Chinese-market
    #    substitutes not in hvoy.ai's set)
    ("zhipu", _MATCH_LAX),     # Zhipu AI, parent of GLM
    ("tongyi", _MATCH_LAX),    # Alibaba Tongyi, parent of Qwen
    ("ernie", _MATCH_STRICT),  # Baidu ERNIE; also a common given name
    ("doubao", _MATCH_LAX),    # ByteDance Doubao
    ("moonshot", _MATCH_LAX),  # Moonshot AI
    ("kimi", _MATCH_STRICT),   # Moonshot's Kimi product; also a common given name
    # 6. Chinese brand names (catch Chinese-language responses)
    ("通义", _MATCH_LAX),
    ("千问", _MATCH_LAX),
    ("智谱", _MATCH_LAX),
    ("豆包", _MATCH_LAX),
    ("文心", _MATCH_LAX),
    ("月之暗面", _MATCH_LAX),
)


NON_CLAUDE_IDENTITY_KEYWORDS = tuple(
    keyword for keyword, _strategy in _IDENTITY_KEYWORD_RULES
)


# v1.7.2 two-tier matching: short / common English-word keywords need
# an identity-phrase anchor to avoid false positives like "I am Claude,
# not GPT" or "I grok your question". Distinctive keywords like
# "deepseek" / "qwen" / "minimax" don't need anchors because they can't
# appear in ordinary English prose.
_STRICT_ASCII_KEYWORDS = frozenset(
    keyword for keyword, strategy in _IDENTITY_KEYWORD_RULES
    if strategy == _MATCH_STRICT
)

# v1.7.7: context-strict keywords require BOTH an identity anchor AND
# a post-keyword identity signal (punctuation or role word like
# "assistant" / "AI" / "model"). This eliminates false positives like
# "I am in warp speed mode" or "I am a windsurf instructor" where the
# keyword is used as a common noun, not a brand identity claim.
_CONTEXT_STRICT_KEYWORDS = frozenset(
    keyword for keyword, strategy in _IDENTITY_KEYWORD_RULES
    if strategy == _MATCH_CONTEXT_STRICT
)

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


def _build_cjk_strict_pattern(keyword):
    """Build the CJK-anchor supplement for a strict ASCII keyword."""
    return re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(keyword) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    )


def _build_cjk_context_strict_pattern(keyword):
    """Build the CJK-anchor supplement for a context-strict ASCII keyword."""
    return re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(keyword) + r"(?![a-zA-Z])"
        + _IDENTITY_SUFFIX_PATTERN,
        re.IGNORECASE,
    )


def _compile_identity_rule_patterns():
    """Compile all identity pattern caches from ``_IDENTITY_KEYWORD_RULES``."""
    strict_ascii = []
    context_strict = []
    lax_ascii = []
    cjk_keywords = []
    cjk_strict = []
    cjk_context_strict = []

    for keyword, strategy in _IDENTITY_KEYWORD_RULES:
        if not keyword.isascii():
            cjk_keywords.append(keyword)
            continue
        if strategy == _MATCH_STRICT:
            strict_ascii.append((keyword, _build_strict_pattern(keyword)))
            cjk_strict.append((keyword, _build_cjk_strict_pattern(keyword)))
        elif strategy == _MATCH_CONTEXT_STRICT:
            context_strict.append((keyword, _build_context_strict_pattern(keyword)))
            cjk_context_strict.append(
                (keyword, _build_cjk_context_strict_pattern(keyword))
            )
        else:
            lax_ascii.append((
                keyword,
                re.compile(
                    r"\b" + re.escape(keyword) + r"(?![a-zA-Z])",
                    re.IGNORECASE,
                ),
            ))

    return (
        tuple(strict_ascii),
        tuple(context_strict),
        tuple(lax_ascii),
        tuple(cjk_keywords),
        tuple(cjk_strict),
        tuple(cjk_context_strict),
    )


(
    _STRICT_ASCII_PATTERNS,
    _CONTEXT_STRICT_PATTERNS,
    _LAX_ASCII_PATTERNS,
    _CJK_KEYWORDS,
    _CJK_STRICT_PATTERNS,
    _CJK_CONTEXT_STRICT_PATTERNS,
) = _compile_identity_rule_patterns()


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
    for keyword, pattern in _LAX_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    for keyword in _CJK_KEYWORDS:
        if keyword in text:
            matched.append(keyword)
    return sorted(matched)
