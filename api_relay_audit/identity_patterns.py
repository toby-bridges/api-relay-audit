"""Non-Claude identity keywords for relay substitution detection.

Used by Step 5 (Instruction Override tests) to flag responses that
self-identify as a non-Claude model despite a ``"You are Claude by
Anthropic"`` system prompt. When a relay routes your request to a
cheaper domestic substitute (GLM, DeepSeek, Qwen, etc.) instead of
the advertised Claude model, the substitute model's own identity
bleeds through in the response — and we can detect it cheaply by
checking for a known list of non-Claude model / brand names.

## Matching strategy (v1.6.1)

ASCII keywords use **word-boundary regex** (``\\b<kw>\\b``,
case-insensitive) to avoid substring collisions with common English
words. For example, under the v1.6 substring approach, ``"aws"``
would spuriously match ``"laws"`` / ``"paws"`` / ``"draws"``; the
v1.6.1 word-boundary approach only matches ``aws`` as a standalone
token. Codex review finding, 2026-04-11.

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
# Who made you?", indicate that the relay is routing to a non-Claude
# substitute model. See module docstring for matching strategy.
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
    # 3. Extended ASCII (our additions — aliases and Chinese-market
    #    substitutes not in hvoy.ai's set)
    "zhipu",     # Zhipu AI, parent of GLM
    "tongyi",    # Alibaba Tongyi, parent of Qwen
    "ernie",     # Baidu ERNIE
    "doubao",    # ByteDance Doubao
    "moonshot",  # Moonshot AI
    "kimi",      # Moonshot's Kimi product
    # 4. Chinese brand names (catch Chinese-language responses)
    "通义",
    "千问",
    "智谱",
    "豆包",
    "文心",
    "月之暗面",
)


# Precompile word-bounded regex for ASCII keywords. CJK keywords stay
# as plain substrings because \b has no useful definition for CJK in
# Python's re engine.
_ASCII_KEYWORD_PATTERNS = tuple(
    (kw, re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw.isascii()
)
_CJK_KEYWORDS = tuple(
    kw for kw in NON_CLAUDE_IDENTITY_KEYWORDS if not kw.isascii()
)


def find_non_claude_identities(text: str) -> list:
    """Return a sorted list of non-Claude identity keywords found in text.

    ASCII keywords match only as whole words (word-bounded regex,
    case-insensitive). CJK keywords match as plain substrings because
    Python's ``re`` engine has no meaningful word-boundary semantics
    for CJK scripts.

    Args:
        text: The model response text to scan. Empty string, None, or
            anything falsy returns an empty list.

    Returns:
        A sorted list of matched keywords (in their original form as
        defined in ``NON_CLAUDE_IDENTITY_KEYWORDS``). An empty list
        means no non-Claude identity was detected.

    Examples:
        >>> find_non_claude_identities("I am Claude, made by Anthropic.")
        []
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
    for keyword, pattern in _ASCII_KEYWORD_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    for keyword in _CJK_KEYWORDS:
        if keyword in text:
            matched.append(keyword)
    return sorted(matched)
