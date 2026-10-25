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
count_tokens does not see a prompt the relay injects into Messages
requests, so a gap in C can also come from Step 3's hidden prompt.

Stream / non-stream usage parity lives in Step 10 and is not repeated here.
No sampling parameters are sent: current Messages API versions reject
temperature / top_p / top_k.

Each check returns "plausible", "implausible" or "inconclusive". The
combined verdict is "implausible" if any check is implausible, "plausible"
if at least one check is plausible and none is implausible, and
"inconclusive" otherwise. Nothing here is scored or fed to the risk matrix.
"""

import json
import time

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

USAGE_PLAUSIBLE = "plausible"
USAGE_IMPLAUSIBLE = "implausible"
USAGE_INCONCLUSIVE = "inconclusive"

_USAGE_TOKEN_KEYS = {
    "input": ("input_tokens", "prompt_tokens"),
    "output": ("output_tokens", "completion_tokens"),
}


def usage_long_prompt(base_prompt=USAGE_BASELINE_PROMPT):
    """Return ``base_prompt`` with the fixed check-A payload appended."""
    return base_prompt + USAGE_PAYLOAD_WORD * USAGE_PAYLOAD_REPEATS


def _usage_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _usage_clip(text, limit=160):
    """Collapse whitespace and pipes so a note stays on one Markdown line."""
    flat = " ".join(str(text).split()).replace("|", "/")
    return flat if len(flat) <= limit else flat[:limit - 3] + "..."


def usage_reported_tokens(result, kind):
    """Return the token count a ``client.call()`` result reported, or None.

    ``kind`` is ``"input"`` or ``"output"``. The client normalizes a missing
    usage block to 0, so the raw response is read first: a reply without
    usage counts as "not reported" instead of a zero reading. Results that
    carry no ``raw`` dict fall back to the normalized field.
    """
    if not isinstance(result, dict) or result.get("error"):
        return None
    keys = _USAGE_TOKEN_KEYS[kind]
    raw = result.get("raw")
    if isinstance(raw, dict):
        usage = raw.get("usage")
        if not isinstance(usage, dict):
            return None
        for key in keys:
            value = _usage_int(usage.get(key))
            if value is not None:
                return value
        return None
    return _usage_int(result.get(keys[0]))


def _usage_missing_reason(result, label):
    if not isinstance(result, dict):
        return f"{label} returned no result"
    if result.get("error"):
        return f"{label} failed: {_usage_clip(result['error'])}"
    return f"usage field missing from the {label} response"


def check_usage_input_delta(baseline_input, long_input, reason=None):
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


def check_usage_output_cap(output_tokens, reason=None):
    """Check B: output_tokens of a max_tokens-capped reply stay under the cap."""
    limit = USAGE_OUTPUT_MAX_TOKENS + USAGE_OUTPUT_TOLERANCE
    check = {
        "check": "output_cap",
        "output_tokens": output_tokens,
        "max_tokens": USAGE_OUTPUT_MAX_TOKENS,
        "limit": limit,
        "verdict": USAGE_INCONCLUSIVE,
        "note": reason,
    }
    if output_tokens is None:
        if check["note"] is None:
            check["note"] = "output_tokens not reported"
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


def check_usage_count_tokens(baseline_input, response, reason=None):
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
            check["note"] = (
                "count_tokens request failed: "
                + _usage_clip(response.get("error") or "no HTTP status")
            )
        return check
    try:
        payload = json.loads(response.get("body") or "")
    except (TypeError, ValueError):
        payload = None
    counted = None
    if isinstance(payload, dict):
        counted = _usage_int(payload.get("input_tokens"))
    if counted is None:
        check["note"] = ("count_tokens answered HTTP 200 without an integer "
                         "input_tokens")
        return check
    check["count_tokens"] = counted
    if baseline_input is None:
        if check["note"] is None:
            check["note"] = "baseline input_tokens not reported"
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


def _usage_run(client, baseline, sleep_fn, pause_seconds):
    baseline_input = usage_reported_tokens(baseline, "input")
    if baseline_input is None:
        return _usage_all_inconclusive(
            "not sent; "
            + _usage_missing_reason(baseline, "'Say hi' baseline"))

    requests_sent = 0
    try:
        long_result = client.call(
            [{"role": "user", "content": usage_long_prompt()}],
            max_tokens=USAGE_OUTPUT_MAX_TOKENS,
        )
    except Exception as exc:  # client.call should not raise; stay safe
        long_result = {"error": f"{type(exc).__name__}: {exc}"}
    requests_sent += 1
    long_input = usage_reported_tokens(long_result, "input")
    long_output = usage_reported_tokens(long_result, "output")
    long_label = "long-prompt request"
    checks = [
        check_usage_input_delta(
            baseline_input, long_input,
            None if long_input is not None
            else _usage_missing_reason(long_result, long_label)),
        check_usage_output_cap(
            long_output,
            None if long_output is not None
            else _usage_missing_reason(long_result, long_label)),
    ]

    detected_format = getattr(client, "detected_format", None)
    if detected_format != "anthropic":
        checks.append(check_usage_count_tokens(
            baseline_input, None,
            "not sent, because count_tokens is Anthropic-format only and the "
            f"client format is {detected_format!r}"))
        return _usage_result(checks, requests_sent)

    sleep_fn(pause_seconds)
    body = {
        "model": getattr(client, "model", ""),
        "messages": [{"role": "user", "content": USAGE_BASELINE_PROMPT}],
    }
    headers = {
        "x-api-key": getattr(client, "api_key", ""),
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
    checks.append(check_usage_count_tokens(baseline_input, response))
    return _usage_result(checks, requests_sent)


def run_usage_sanity(client, baseline, sleep_fn=time.sleep, pause_seconds=1.0):
    """Run checks A-C and return the observation. Never raises.

    Args:
        client: An ``APIClient`` (or compatible double) already used by
            Step 3, so ``detected_format`` is settled.
        baseline: Step 3's ``client.call()`` result for
            ``USAGE_BASELINE_PROMPT`` without a system prompt, or None.
            When it is missing or failed, nothing is sent and every check
            is inconclusive.
        sleep_fn: Pause function, injectable so tests do not sleep.
        pause_seconds: Pause before the count_tokens request.

    Returns:
        ``{"verdict": str, "checks": [A, B, C], "requests_sent": int}``. At
        most two requests are sent: the long prompt shared by checks A and B,
        and one count_tokens call for Anthropic-format clients.
    """
    try:
        return _usage_run(client, baseline, sleep_fn, pause_seconds)
    except Exception as exc:  # observation must never break Step 3
        return _usage_all_inconclusive(
            _usage_clip(f"usage sanity failed: {type(exc).__name__}: {exc}"))
