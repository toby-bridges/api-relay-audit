"""Latency variance fingerprinting (Step 13, v1.8).

Probes the relay with N identical minimal requests and measures
per-request end-to-end latency. Computes descriptive statistics
(min, median, max, stdev, coefficient of variation) and a simple
bimodality heuristic.

Rationale: a legitimate, direct upstream-provider connection shows
relatively stable latency across identical low-output requests.
A relay that silently A/B tests (routing some requests to the
advertised Claude and some to a cheaper quantized model or an
unrelated provider) produces BIMODAL latency: two distinct clusters
of response times. Similarly, a relay that multiplexes requests
through a shared batch queue shows multi-modal patterns.

This is a **weak signal** in v1.8 -- informational only, does NOT
feed into the 6D risk matrix. Legitimate network jitter, provider-
side warming, and regional failovers can all produce high variance
on honest relays. A clear bimodal distribution is still worth
flagging to the operator as a prompt for deeper investigation
(e.g. run Step 12 again, capture body hashes, diff model claims).

Paired with Step 12 Infrastructure Fingerprint, this section forms
v1.8's "Infrastructure Audit Layer".

## Classification rules

Given ``count`` successful samples:

  count < 3                 -> "inconclusive"
  bimodality detected       -> "bimodal"
  CV < 0.25                 -> "stable"
  0.25 <= CV < 0.5          -> "variable"
  CV >= 0.5                 -> "high-variance"

Bimodality heuristic: after sorting samples, find the largest gap
between consecutive values. If that gap divided by the median is
greater than ``BIMODAL_GAP_THRESHOLD`` (default 0.5), the distribution
has a visible cluster break and is flagged bimodal. Requires at least
4 samples to be meaningful.
"""

import statistics
import time


DEFAULT_PROBE_COUNT = 10
DEFAULT_PROBE_PROMPT = "Reply with the single word: ok"
DEFAULT_PROBE_MAX_TOKENS = 8
DEFAULT_INTER_PROBE_SLEEP = 0.2

# Ratio of largest-inter-sample-gap to median above which the sample
# is flagged bimodal. 0.5 means the gap has to be at least half the
# median -- a conservative cutoff that avoids flagging typical jitter
# while still catching clearly-split distributions.
BIMODAL_GAP_THRESHOLD = 0.5

# Coefficient-of-variation cutoffs for the non-bimodal branches.
CV_STABLE_CUTOFF = 0.25
CV_VARIABLE_CUTOFF = 0.5


def summarize_latencies(latencies):
    """Compute descriptive statistics for a list of latencies (seconds).

    Returns dict with keys ``count``, ``min``, ``median``, ``max``,
    ``mean``, ``stdev``, ``cv``. ``stdev`` and ``cv`` are 0.0 when
    there are fewer than 2 samples (``statistics.stdev`` requires >=2).
    Returns an empty dict for an empty input.
    """
    if not latencies:
        return {}
    n = len(latencies)
    result = {
        "count": n,
        "min": min(latencies),
        "max": max(latencies),
        "mean": statistics.mean(latencies),
        "median": statistics.median(latencies),
    }
    if n >= 2:
        result["stdev"] = statistics.stdev(latencies)
        result["cv"] = (
            result["stdev"] / result["mean"] if result["mean"] > 0 else 0.0
        )
    else:
        result["stdev"] = 0.0
        result["cv"] = 0.0
    return result


def detect_bimodality(latencies):
    """Return ``(is_bimodal, gap_ratio)``.

    ``gap_ratio`` is largest_gap / median. If it exceeds
    ``BIMODAL_GAP_THRESHOLD``, the sample is flagged bimodal.

    Requires at least 4 samples; returns ``(False, 0.0)`` otherwise.
    Also returns ``(False, 0.0)`` when the median is zero (all
    latencies zero, which would mean mocked or broken measurements).
    """
    if len(latencies) < 4:
        return False, 0.0
    sorted_lats = sorted(latencies)
    gaps = [sorted_lats[i + 1] - sorted_lats[i]
            for i in range(len(sorted_lats) - 1)]
    largest_gap = max(gaps)
    median = statistics.median(latencies)
    if median <= 0:
        return False, 0.0
    ratio = largest_gap / median
    return ratio > BIMODAL_GAP_THRESHOLD, ratio


def classify_variance(stats, is_bimodal):
    """Return verdict: ``stable`` / ``variable`` / ``high-variance`` /
    ``bimodal`` / ``inconclusive``.
    """
    if not stats or stats.get("count", 0) < 3:
        return "inconclusive"
    if is_bimodal:
        return "bimodal"
    cv = stats.get("cv", 0.0)
    if cv < CV_STABLE_CUTOFF:
        return "stable"
    if cv < CV_VARIABLE_CUTOFF:
        return "variable"
    return "high-variance"


def run_latency_variance(client, count=DEFAULT_PROBE_COUNT,
                         prompt=DEFAULT_PROBE_PROMPT,
                         max_tokens=DEFAULT_PROBE_MAX_TOKENS,
                         sleep=DEFAULT_INTER_PROBE_SLEEP):
    """Fire ``count`` identical minimal requests and measure latency.

    Each call is an ordinary :meth:`APIClient.call` with a tiny
    ``max_tokens`` cap so the audit does not incur meaningful
    metered-billing cost even on pay-as-you-go relays.

    Returns a dict with keys:
        ``latencies``  -- list of successful probe latencies (seconds)
        ``errors``     -- list of error strings for failed probes
        ``stats``      -- dict from :func:`summarize_latencies`
        ``bimodal``    -- bool (from :func:`detect_bimodality`)
        ``gap_ratio``  -- float (largest_gap / median)
        ``verdict``    -- str (from :func:`classify_variance`)
    """
    latencies = []
    errors = []
    for i in range(count):
        t0 = time.time()
        r = client.call(
            [{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )
        elapsed = time.time() - t0
        if "error" in r:
            errors.append(r["error"])
        else:
            latencies.append(elapsed)
        if sleep > 0 and i < count - 1:
            time.sleep(sleep)

    stats = summarize_latencies(latencies)
    is_bimodal, gap_ratio = detect_bimodality(latencies)
    verdict = classify_variance(stats, is_bimodal)

    return {
        "latencies": latencies,
        "errors": errors,
        "stats": stats,
        "bimodal": is_bimodal,
        "gap_ratio": gap_ratio,
        "verdict": verdict,
    }
