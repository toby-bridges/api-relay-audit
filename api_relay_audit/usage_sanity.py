"""Token usage sanity observation for Step 3 (informational only).

Concept inspired by canarybyte/veridrop token_usage.py (AGPL-3.0); reimplemented independently.

A relay bills by the ``usage`` block it returns. This module asks a narrow
question: do the reported counts hang together for a few controlled
requests? It is a relative self-consistency check, not a billing audit, and
it never counts tokens offline.

Step 3's "Say hi" request without a system prompt is the short baseline.
Three checks build on it:

A. Input delta: the same user message with ``USAGE_PAYLOAD_REPEATS`` copies
   of ``USAGE_PAYLOAD_WORD`` appended must raise input_tokens by an amount
   inside ``[USAGE_DELTA_MIN, USAGE_DELTA_MAX]``.
B. Output cap: that same long request is sent with
   ``max_tokens=USAGE_OUTPUT_MAX_TOKENS``; the reported output_tokens must
   not exceed the cap plus ``USAGE_OUTPUT_TOLERANCE``. Checks A and B share
   one request because input_tokens does not depend on max_tokens.
C. count_tokens reconciliation (Anthropic format only): POST
   ``/v1/messages/count_tokens`` with the baseline's model and messages must
   agree with the baseline's actual input_tokens within
   ``USAGE_COUNT_TOKENS_TOLERANCE``. Any answer other than HTTP 200 with an
   integer input_tokens (404, 400, unsupported route) is inconclusive.

This is a counting signal, distinct from Step 3's injection signal. Step 3
reads the idle level: a minimal prompt whose input_tokens sit well above the
expected count suggests a hidden prompt. Check A reads the increment after a
fixed payload is added; a hidden prefix adds the same tokens to both
requests and cancels out of the difference. Check C does not cancel it:
count_tokens does not see a prompt the relay injects into Messages requests,
so when Step 3 already reports injection (above
``USAGE_STEP3_INJECTION_THRESHOLD`` tokens) C is not sent and stays
inconclusive instead of reporting the same cause twice.

Readings that cannot be compared make a check inconclusive: a missing or
non-integer count, prompt caching (``cache_read_input_tokens`` /
``cache_creation_input_tokens``, which input_tokens excludes) for A and C,
and reported thinking tokens or an unexpected stop / finish reason for B.
A negative count is impossible and makes the check implausible. Relay error
text never reaches a note verbatim: HTTP errors keep only the status code
and anything else is redacted, then clipped.

Stream / non-stream usage parity lives in Step 10 and is not repeated here.
No sampling parameters are sent: current Messages API versions reject
temperature / top_p / top_k.

Each check returns "plausible", "implausible" or "inconclusive". The
combined verdict is "implausible" if any check is implausible, "plausible"
if at least one check is plausible and none is implausible, and
"inconclusive" otherwise. Nothing here is scored or fed to the risk matrix.
"""

import json
import re
import time

from api_relay_audit.error_leakage import redact_sensitive_text

USAGE_BASELINE_PROMPT = "Say hi"
USAGE_PAYLOAD_WORD = " apple"
USAGE_PAYLOAD_REPEATS = 80
# Provisional, uncalibrated; calibrate against a direct-upstream baseline.
USAGE_DELTA_MIN = 40
USAGE_DELTA_MAX = 240
USAGE_OUTPUT_MAX_TOKENS = 16
USAGE_OUTPUT_TOLERANCE = 4
USAGE_COUNT_TOKENS_TOLERANCE = 2
USAGE_COUNT_TOKENS_PATH = "/v1/messages/count_tokens"
# Step 3 reports injection above this many tokens (its yellow threshold).
USAGE_STEP3_INJECTION_THRESHOLD = 20
# Stop / finish reasons of a plain text reply that ended on its own or at
# max_tokens (Anthropic, then OpenAI-compatible). Anything else leaves B
# inconclusive.
USAGE_EXPECTED_STOP_REASONS = frozenset(
    {"end_turn", "max_tokens", "stop_sequence", "stop", "length"})
USAGE_CACHE_FIELDS = ("cache_read_input_tokens", "cache_creation_input_tokens")

USAGE_PLAUSIBLE = "plausible"
USAGE_IMPLAUSIBLE = "implausible"
USAGE_INCONCLUSIVE = "inconclusive"

_USAGE_TOKEN_KEYS = {
    "input": ("input_tokens", "prompt_tokens"),
    "output": ("output_tokens", "completion_tokens"),
}
_USAGE_HTTP_STATUS = re.compile(r"^\s*HTTP\s+(\d{3})\b")
_USAGE_THINKING_KEY = re.compile(r"reasoning|thinking|thought", re.IGNORECASE)


def usage_long_prompt(base_prompt=USAGE_BASELINE_PROMPT):
    """Return ``base_prompt`` with the fixed check-A payload appended."""
    return base_prompt + USAGE_PAYLOAD_WORD * USAGE_PAYLOAD_REPEATS


def _usage_is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _usage_clip(text, limit=160):
    """Collapse whitespace and pipes so a note stays on one Markdown line."""
    flat = " ".join(str(text).split()).replace("|", "/")
    return flat if len(flat) <= limit else flat[:limit - 3] + "..."


def usage_safe_error(error, api_key=""):
    """Return report-safe text for a relay or transport error.

    An HTTP error keeps only its status code, so no relay error body reaches
    the report. Any other text is redacted with ``redact_sensitive_text``
    first and clipped afterwards, so clipping cannot split a secret.
    """
    text = str(error)
    match = _USAGE_HTTP_STATUS.match(text)
    if match:
        return f"HTTP {match.group(1)}"
    return _usage_clip(redact_sensitive_text(text, api_key))


def _usage_raw_usage(result):
    """Return the raw usage dict of a successful ``call()`` result, or None."""
    if not isinstance(result, dict) or result.get("error"):
        return None
    raw = result.get("raw")
    if isinstance(raw, dict) and isinstance(raw.get("usage"), dict):
        return raw["usage"]
    return None


def usage_token_reading(result, kind, label, api_key=""):
    """Return ``(value, reason)`` for a count a ``client.call()`` result reported.

    ``kind`` is ``"input"`` or ``"output"``. ``value`` is the reported
    integer, negative values included so the checks can call them
    implausible, or None; ``reason`` then says why. The client normalizes a
    missing usage block to 0, so the raw response is read first; results
    that carry no ``raw`` dict fall back to the normalized field.
    """
    if not isinstance(result, dict):
        return None, f"{label} returned no result"
    if result.get("error"):
        return None, f"{label} failed: {usage_safe_error(result['error'], api_key)}"
    keys = _USAGE_TOKEN_KEYS[kind]
    raw = result.get("raw")
    if isinstance(raw, dict):
        usage = raw.get("usage")
        if not isinstance(usage, dict):
            return None, f"usage field missing from the {label} response"
    else:
        usage = {keys[0]: result.get(keys[0])}
    for key in keys:
        value = usage.get(key)
        if value is None:
            continue
        if not _usage_is_int(value):
            return None, f"{key} is not an integer in the {label} response"
        return value, None
    return None, f"{keys[0]} missing from the {label} response"


def usage_cache_note(result, label):
    """Return a note when prompt caching touched a reply, else None.

    Anthropic's input_tokens excludes cached tokens, so a non-zero
    ``cache_read_input_tokens`` or ``cache_creation_input_tokens`` makes
    input comparisons unreliable.
    """
    usage = _usage_raw_usage(result)
    if usage is None:
        return None
    active = [f"{field}={usage[field]}" for field in USAGE_CACHE_FIELDS
              if _usage_is_int(usage.get(field)) and usage[field] != 0]
    if not active:
        return None
    return (f"prompt caching touched the {label} ({', '.join(active)}); "
            "input_tokens excludes cached tokens")


def usage_thinking_note(result, label):
    """Return a note when a reply reports thinking / reasoning tokens, else None.

    Looks for positive integer counts under usage keys that mention
    reasoning, thinking or thought, one level deep (for example
    ``completion_tokens_details.reasoning_tokens``). Some upstreams do not
    cap thinking with max_tokens but still count it as output.
    """
    usage = _usage_raw_usage(result)
    if usage is None:
        return None
    hits = []
    for key, value in usage.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if (_USAGE_THINKING_KEY.search(str(sub_key))
                        and _usage_is_int(sub_value) and sub_value > 0):
                    hits.append(f"{key}.{sub_key}={sub_value}")
        elif (_USAGE_THINKING_KEY.search(str(key))
                and _usage_is_int(value) and value > 0):
            hits.append(f"{key}={value}")
    if not hits:
        return None
    return (f"the {label} reports thinking tokens ({', '.join(hits)}), which "
            "some upstreams do not cap with max_tokens")


def usage_stop_reason(result):
    """Return the stop / finish reason of a successful ``call()`` result."""
    if not isinstance(result, dict) or result.get("error"):
        return None
    raw = result.get("raw")
    if not isinstance(raw, dict):
        return None
    reason = raw.get("stop_reason")
    if reason is None:
        choices = raw.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            reason = choices[0].get("finish_reason")
    return reason if isinstance(reason, str) else None


def check_usage_input_delta(baseline_input, long_input, reason=None,
                            cache_note=None):
    """Check A: input_tokens increment after the fixed payload is appended."""
    check = {
        "check": "input_delta",
        "baseline_input_tokens": baseline_input,
        "long_input_tokens": long_input,
        "delta": None,
        "verdict": USAGE_INCONCLUSIVE,
        "note": reason,
    }
    if baseline_input is None or long_input is None:
        if check["note"] is None:
            check["note"] = "input_tokens not reported for both requests"
        return check
    if baseline_input < 0 or long_input < 0:
        check["verdict"] = USAGE_IMPLAUSIBLE
        check["note"] = (f"negative input_tokens reading (baseline "
                         f"{baseline_input}, long prompt {long_input})")
        return check
    if cache_note:
        check["note"] = cache_note
        return check
    delta = long_input - baseline_input
    check["delta"] = delta
    if USAGE_DELTA_MIN <= delta <= USAGE_DELTA_MAX:
        check["verdict"] = USAGE_PLAUSIBLE
    else:
        check["verdict"] = USAGE_IMPLAUSIBLE
        check["note"] = (
            f"appending {USAGE_PAYLOAD_REPEATS} x "
            f"'{USAGE_PAYLOAD_WORD.strip()}' changed input_tokens by "
            f"{delta:+d}, outside {USAGE_DELTA_MIN}..{USAGE_DELTA_MAX}"
        )
    return check


def check_usage_output_cap(output_tokens, reason=None, stop_reason=None,
                           thinking_note=None):
    """Check B: output_tokens of a max_tokens-capped reply stay under the cap."""
    limit = USAGE_OUTPUT_MAX_TOKENS + USAGE_OUTPUT_TOLERANCE
    check = {
        "check": "output_cap",
        "output_tokens": output_tokens,
        "max_tokens": USAGE_OUTPUT_MAX_TOKENS,
        "limit": limit,
        "stop_reason": stop_reason,
        "verdict": USAGE_INCONCLUSIVE,
        "note": reason,
    }
    if output_tokens is None:
        if check["note"] is None:
            check["note"] = "output_tokens not reported"
        return check
    if output_tokens < 0:
        check["verdict"] = USAGE_IMPLAUSIBLE
        check["note"] = f"negative output_tokens reading ({output_tokens})"
        return check
    if thinking_note:
        check["note"] = thinking_note
        return check
    if stop_reason is not None and stop_reason not in USAGE_EXPECTED_STOP_REASONS:
        check["note"] = (f"stop reason {_usage_clip(stop_reason, 40)!r} is "
                         "neither a natural stop nor the max_tokens cut")
        return check
    if output_tokens <= limit:
        check["verdict"] = USAGE_PLAUSIBLE
    else:
        check["verdict"] = USAGE_IMPLAUSIBLE
        check["note"] = (
            f"max_tokens={USAGE_OUTPUT_MAX_TOKENS} reply reported "
            f"{output_tokens} output_tokens, above {limit}"
        )
    return check


def check_usage_count_tokens(baseline_input, response, reason=None, api_key=""):
    """Check C: count_tokens against the baseline's actual input_tokens.

    ``response`` is a ``client.raw_request()`` dict, or None when the request
    was not sent. ``difference`` is actual minus counted, so a positive value
    means the Messages reply reported more tokens than count_tokens.
    """
    check = {
        "check": "count_tokens",
        "baseline_input_tokens": baseline_input,
        "count_tokens": None,
        "difference": None,
        "status": None,
        "verdict": USAGE_INCONCLUSIVE,
        "note": reason,
    }
    if not isinstance(response, dict):
        if check["note"] is None:
            check["note"] = "count_tokens not sent"
        return check
    status = response.get("status")
    check["status"] = status
    if status != 200:
        if status:
            check["note"] = f"count_tokens unavailable (HTTP {status})"
        else:
            check["note"] = "count_tokens request failed: " + usage_safe_error(
                response.get("error") or "no HTTP status", api_key)
        return check
    try:
        payload = json.loads(response.get("body") or "")
    except (TypeError, ValueError):
        payload = None
    counted = payload.get("input_tokens") if isinstance(payload, dict) else None
    if counted is None:
        check["note"] = "count_tokens answered HTTP 200 without input_tokens"
        return check
    if not _usage_is_int(counted):
        check["note"] = "count_tokens input_tokens is not an integer"
        return check
    check["count_tokens"] = counted
    if baseline_input is None:
        if check["note"] is None:
            check["note"] = "baseline input_tokens not reported"
        return check
    if baseline_input < 0 or counted < 0:
        check["verdict"] = USAGE_IMPLAUSIBLE
        check["note"] = (f"negative input_tokens reading (actual "
                         f"{baseline_input}, counted {counted})")
        return check
    difference = baseline_input - counted
    check["difference"] = difference
    if abs(difference) <= USAGE_COUNT_TOKENS_TOLERANCE:
        check["verdict"] = USAGE_PLAUSIBLE
    else:
        check["verdict"] = USAGE_IMPLAUSIBLE
        check["note"] = (
            f"count_tokens counted {counted} input_tokens, the "
            f"'{USAGE_BASELINE_PROMPT}' request reported {baseline_input}"
        )
    return check


def combine_usage_verdicts(verdicts):
    """Combine per-check verdicts into the observed usage sanity verdict."""
    verdicts = list(verdicts)
    if USAGE_IMPLAUSIBLE in verdicts:
        return USAGE_IMPLAUSIBLE
    if USAGE_PLAUSIBLE in verdicts:
        return USAGE_PLAUSIBLE
    return USAGE_INCONCLUSIVE


def _usage_result(checks, requests_sent):
    return {
        "verdict": combine_usage_verdicts(c["verdict"] for c in checks),
        "checks": checks,
        "requests_sent": requests_sent,
    }


def _usage_all_inconclusive(reason, requests_sent=0):
    return _usage_result([
        check_usage_input_delta(None, None, reason),
        check_usage_output_cap(None, reason),
        check_usage_count_tokens(None, None, reason),
    ], requests_sent)


def _usage_run(client, baseline, injection_size, sleep_fn, pause_seconds):
    api_key = getattr(client, "api_key", "")
    baseline_label = "'Say hi' baseline"
    baseline_input, baseline_reason = usage_token_reading(
        baseline, "input", baseline_label, api_key)
    if baseline_input is None:
        return _usage_all_inconclusive("not sent; " + baseline_reason)

    requests_sent = 0
    try:
        long_result = client.call(
            [{"role": "user", "content": usage_long_prompt()}],
            max_tokens=USAGE_OUTPUT_MAX_TOKENS,
        )
    except Exception as exc:  # client.call should not raise; stay safe
        long_result = {"error": f"{type(exc).__name__}: {exc}"}
    requests_sent += 1
    long_label = "long-prompt request"
    long_input, long_input_reason = usage_token_reading(
        long_result, "input", long_label, api_key)
    long_output, long_output_reason = usage_token_reading(
        long_result, "output", long_label, api_key)
    baseline_cache = usage_cache_note(baseline, baseline_label)
    checks = [
        check_usage_input_delta(
            baseline_input, long_input, long_input_reason,
            cache_note=baseline_cache or usage_cache_note(long_result, long_label)),
        check_usage_output_cap(
            long_output, long_output_reason,
            stop_reason=usage_stop_reason(long_result),
            thinking_note=usage_thinking_note(long_result, long_label)),
    ]

    detected_format = getattr(client, "detected_format", None)
    skip_reason = None
    if detected_format != "anthropic":
        skip_reason = ("not sent, because count_tokens is Anthropic-format "
                       f"only and the client format is {detected_format!r}")
    elif (_usage_is_int(injection_size)
            and injection_size > USAGE_STEP3_INJECTION_THRESHOLD):
        skip_reason = ("not sent; count_tokens cannot see injected content, "
                       "so the gap is already explained by Step 3's injection "
                       f"finding (~{injection_size} tokens)")
    elif baseline_cache:
        skip_reason = "not sent; " + baseline_cache
    if skip_reason:
        checks.append(check_usage_count_tokens(baseline_input, None, skip_reason))
        return _usage_result(checks, requests_sent)

    sleep_fn(pause_seconds)
    body = {
        "model": getattr(client, "model", ""),
        "messages": [{"role": "user", "content": USAGE_BASELINE_PROMPT}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    try:
        response = client.raw_request(
            "POST", USAGE_COUNT_TOKENS_PATH, headers,
            json.dumps(body).encode("utf-8"),
            content_type="application/json", timeout=30,
        )
    except Exception as exc:  # raw_request should not raise; stay safe
        response = {"status": 0, "headers": {}, "body": "",
                    "error": f"{type(exc).__name__}: {exc}"}
    requests_sent += 1
    checks.append(check_usage_count_tokens(baseline_input, response,
                                           api_key=api_key))
    return _usage_result(checks, requests_sent)


def run_usage_sanity(client, baseline, injection_size=None,
                     sleep_fn=time.sleep, pause_seconds=1.0):
    """Run checks A-C and return the observation. Never raises.

    Args:
        client: An ``APIClient`` (or compatible double) already used by
            Step 3, so ``detected_format`` is settled.
        baseline: Step 3's ``client.call()`` result for
            ``USAGE_BASELINE_PROMPT`` without a system prompt, or None.
            When it is missing or unusable, nothing is sent and every check
            is inconclusive.
        injection_size: Step 3's measured injection in tokens, or None.
            Above ``USAGE_STEP3_INJECTION_THRESHOLD`` check C is not sent.
        sleep_fn: Pause function, injectable so tests do not sleep.
        pause_seconds: Pause before the count_tokens request.

    Returns:
        ``{"verdict": str, "checks": [A, B, C], "requests_sent": int}``. At
        most two requests are sent: the long prompt shared by checks A and B,
        and one count_tokens call for Anthropic-format clients.
    """
    try:
        return _usage_run(client, baseline, injection_size, sleep_fn,
                          pause_seconds)
    except Exception as exc:  # observation must never break Step 3
        return _usage_all_inconclusive("usage sanity failed: " + usage_safe_error(
            f"{type(exc).__name__}: {exc}", getattr(client, "api_key", "")))
