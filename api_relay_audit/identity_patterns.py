"""Non-Claude identity keywords for relay substitution detection.

Used by Step 5 (Instruction Override tests) to flag responses that
self-identify as a non-Claude model despite a ``"You are Claude by
Anthropic"`` system prompt. When a relay routes your request to a
cheaper domestic substitute (GLM, DeepSeek, Qwen, etc.) instead of
the advertised Claude model, the substitute model's own identity
bleeds through in the response — and we can detect it cheaply by
substring matching on a known list of non-Claude model / brand names.

## Attribution

The identity-substitution detection *concept* is inspired by hvoy.ai
(`https://hvoy.ai/`) and its backing repo
`github.com/zzsting88/relayAPI` `claude_detector.py`
``IDENTITY_NEGATIVE_PATTERNS``. The repo has no explicit LICENSE file,
so this module is an **independent reimplementation** of the concept
(not a code copy):

- We use a plain tuple of case-insensitive substrings, not regexes.
- The keyword set extends theirs with additional Chinese-market
  substitutes (Baidu ERNIE, ByteDance Doubao, Moonshot Kimi) and
  Chinese brand names (通义 / 千问 / 智谱 / 豆包 / 文心 / 月之暗面)
  for catching responses in Chinese.
- The matching function is our own.

Verified against hvoy.ai's source on 2026-04-11. See the
``reference_hvoy_relayapi`` memory file for the full review of what
their tool does and does not detect.
"""


# Substring keywords that, if present in a response to
# "Who are you? Who made you?", indicate that the relay is routing to
# a non-Claude substitute model. Case-insensitive substring match.
#
# Groups (not enforced by code, just for readability):
#   1. Legacy (v2.1)         — Amazon / AWS brand leakage from earlier audits
#   2. hvoy.ai verified      — ASCII model names from their probe set
#   3. Extended ASCII        — common Chinese-market substitutes not in hvoy.ai
#   4. Chinese brand names   — catch Chinese-language responses that use the
#                               Chinese brand instead of the ASCII model name
NON_CLAUDE_IDENTITY_KEYWORDS = (
    # 1. Legacy (v2.1)
    "amazon",
    "kiro",
    "aws",
    # 2. hvoy.ai verified ASCII substitutes
    "glm",
    "zhipu",
    "z.ai",
    "deepseek",
    "qwen",
    "tongyi",
    "minimax",
    "grok",
    "gpt",
    # 3. Extended ASCII (our additions — common Chinese-market substitutes)
    "ernie",
    "doubao",
    "moonshot",
    "kimi",
    # 4. Chinese brand names (catch Chinese-language responses)
    "通义",
    "千问",
    "智谱",
    "豆包",
    "文心",
    "月之暗面",
)


def find_non_claude_identities(text: str) -> list:
    """Return a sorted list of non-Claude identity keywords found in text.

    Performs a case-insensitive substring search against
    :data:`NON_CLAUDE_IDENTITY_KEYWORDS`. ASCII keywords are lowered for
    matching; Chinese keywords are matched as-is (Chinese has no case).

    Args:
        text: The model response text to scan. Empty string, None, or
            anything falsy returns an empty list.

    Returns:
        A sorted list of matched keywords (in their original form as
        defined in ``NON_CLAUDE_IDENTITY_KEYWORDS``). An empty list means
        no non-Claude identity was detected.

    Examples:
        >>> find_non_claude_identities("I am Claude, made by Anthropic.")
        []
        >>> find_non_claude_identities("I'm DeepSeek-V3, an assistant.")
        ['deepseek']
        >>> find_non_claude_identities("我是通义千问,由阿里巴巴创建。")
        ['千问', '通义']
    """
    if not text:
        return []
    lower = text.lower()
    matched = []
    for keyword in NON_CLAUDE_IDENTITY_KEYWORDS:
        # Chinese keywords are already case-insensitive; ASCII ones need
        # lowering. We lowered `text` once above, so for ASCII keywords
        # we can search directly; for Chinese keywords, `lower` still
        # contains them verbatim (str.lower() is a no-op on CJK chars).
        if keyword in lower:
            matched.append(keyword)
    return sorted(matched)
