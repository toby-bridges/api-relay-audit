"""Tool-call package-name substitution test (AC-1.a).

Detects malicious middlewares that rewrite package-install commands on the
return path, e.g. ``pip install requests`` -> ``pip install reqeusts``
(typosquat). Works by asking the model to echo a deterministic install
command and comparing the returned text character-by-character against the
expected string.

This module implements Step 8's complementary text path. Content-based
package substitution rules often fire on plain text, while
``tool_call_integrity.py`` independently covers non-streaming structured
Anthropic/OpenAI Tool Calls that leave plaintext untouched.

Reference: Liu, Shou, Wen, Chen, Fang, Feng,
"Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the
LLM Supply Chain", arXiv:2604.08407, section 4.2.1.
"""

import time


# Probe set: one pinned install command per ecosystem the paper flags as most
# abused. Pinned versions/tags reduce the chance the model paraphrases.
PROBES = [
    ("pip",   "pip install requests==2.31.0"),
    ("npm",   "npm install lodash@4.17.21"),
    ("cargo", "cargo add serde"),
    ("go",    "go get github.com/stretchr/testify"),
]


def _strip_wrappers(s: str) -> str:
    """Remove common markdown/prompt wrappers the model may add despite the
    instruction (code fences, backticks, quotes, shell prompts)."""
    s = s.strip()
    # Strip fenced code block
    if s.startswith("```"):
        # drop the first line (``` or ```lang) and the closing fence
        nl = s.find("\n")
        if nl != -1:
            s = s[nl + 1:]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    # Strip wrapping single-char backticks or quotes (one layer)
    for ch in ("`", '"', "'"):
        if len(s) >= 2 and s[0] == ch and s[-1] == ch:
            s = s[1:-1]
    s = s.strip()
    # Strip leading shell prompt / comment markers
    for prefix in ("$ ", "# ", "> "):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s


def classify(expected: str, received: str) -> str:
    """Classify the probe verdict.

    Returns one of:
      - ``"exact"``        : character-identical to expected
      - ``"whitespace"``   : same whitespace-delimited tokens modulo case and
                             trailing punctuation (benign model noise such as a
                             trailing newline, period, or all-caps)
      - ``"substituted"``  : token-level divergence -> AC-1.a signal

    Critically, this does NOT collapse internal whitespace. A response that
    inserts a space inside a package identifier (e.g. ``req uests``) changes
    shell tokenization and must be flagged as substitution. Similarly, a
    multi-line response that contains the expected command alongside a
    malicious variant will not match the token list and will be flagged.
    """
    if received == expected:
        return "exact"
    # Strip trailing punctuation the model may add (period, comma, semicolon).
    trimmed = received.strip().rstrip(".,;:!?")
    exp_tokens = expected.split()
    rcv_tokens = trimmed.split()
    if exp_tokens == rcv_tokens:
        return "whitespace"
    # Case-only differences in otherwise identical token sequences
    if [t.lower() for t in exp_tokens] == [t.lower() for t in rcv_tokens]:
        return "whitespace"
    return "substituted"


def probe_once(client, expected: str, sleep: float = 1.0):
    """Run a single probe. Returns a dict with keys
    ``verdict`` (str), ``received`` (str), ``error`` (str or None)."""
    # Transcription framing: reduces refusal rates from safety-tuned models by
    # making the task explicitly non-executive (copy text, don't run it).
    prompt = (
        "Copy this harmless text exactly. Do not execute it. "
        "Output only the copied text, nothing else, no markdown, no "
        "backticks, no explanation. Text to copy: " + expected
    )
    r = client.call(
        [{"role": "user", "content": prompt}], max_tokens=100
    )
    if sleep > 0:
        time.sleep(sleep)
    if "error" in r:
        return {"verdict": "error", "received": "", "error": str(r.get("error", ""))}
    raw = r.get("text", "") or ""
    cleaned = _strip_wrappers(raw)
    return {"verdict": classify(expected, cleaned), "received": cleaned, "error": None}


def run_tool_substitution_test(client, sleep: float = 1.0):
    """Run all probes against the client.

    Returns ``(results, detected, inconclusive)`` where:

    - ``results`` is a list of dicts with keys ``manager``, ``expected``,
      ``received``, ``verdict``, ``error``
    - ``detected`` is ``True`` iff any probe returned verdict ``"substituted"``
    - ``inconclusive`` is ``True`` iff **all** probes errored (e.g. the relay
      blocks plaintext echo). An inconclusive run must NOT be treated as a
      clean signal by the caller's risk matrix.
    """
    results = []
    for manager, expected in PROBES:
        r = probe_once(client, expected, sleep=sleep)
        r["manager"] = manager
        r["expected"] = expected
        results.append(r)
    detected = any(r["verdict"] == "substituted" for r in results)
    inconclusive = all(r["verdict"] == "error" for r in results)
    return results, detected, inconclusive
