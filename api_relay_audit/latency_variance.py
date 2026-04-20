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
between consecutive values *that splits the sample into two clusters
of at least 2 samples each*. If that gap divided by the median is
greater than ``BIMODAL_GAP_THRESHOLD`` (default 0.5), the distribution
has a visible cluster break and is flagged bimodal. The >=2-per-cluster
rule prevents a single outlier from being misclassified as a bimodal
distribution; requires at least 4 samples to be meaningful.
"""

import argparse
import statistics
import time


DEFAULT_PROBE_COUNT = 10
DEFAULT_PROBE_PROMPT = "Reply with the single word: ok"
DEFAULT_PROBE_MAX_TOKENS = 8
DEFAULT_INTER_PROBE_SLEEP = 0.2

# v1.8.1 Codex review #5 fix: bound ``--latency-probe-count`` so 0
# or negative values can't silently collapse Step 13 into "all 0
# probes failed", and absurd values can't linearly inflate billing.
# 3 is the minimum for ``classify_variance`` to fire; 4 is the
# minimum for bimodality detection; 50 is an arbitrary-but-
# generous upper bound.
LATENCY_PROBE_MIN = 3
LATENCY_PROBE_MAX = 50


def validate_probe_count(value):
    """argparse ``type=`` callable for ``--latency-probe-count``.

    Accepts an int-coercible value in ``[LATENCY_PROBE_MIN,
    LATENCY_PROBE_MAX]``; raises :class:`argparse.ArgumentTypeError`
    otherwise.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            f"--latency-probe-count must be an integer, got {value!r}"
        )
    if n < LATENCY_PROBE_MIN or n > LATENCY_PROBE_MAX:
        raise argparse.ArgumentTypeError(
            f"--latency-probe-count must be between {LATENCY_PROBE_MIN} "
            f"and {LATENCY_PROBE_MAX}, got {n}"
        )
    return n

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

    ``gap_ratio`` is the largest qualifying gap divided by the median,
    where a *qualifying* gap is one that splits the sorted sample into
    a left cluster of >=2 and a right cluster of >=2. A single outlier
    at either extreme therefore cannot produce a qualifying gap --
    without this rule, ``[1.0, 1.01, 1.02, 1.80]`` would report
    ``(True, 0.77)`` from one unlucky slow probe.

    If the ratio exceeds ``BIMODAL_GAP_THRESHOLD``, the sample is
    flagged bimodal.

    Requires at least 4 samples; returns ``(False, 0.0)`` otherwise.
    Also returns ``(False, 0.0)`` when the median is zero (all
    latencies zero, which would mean mocked or broken measurements).
    """
    n = len(latencies)
    if n < 4:
        return False, 0.0
    median = statistics.median(latencies)
    if median <= 0:
        return False, 0.0
    sorted_lats = sorted(latencies)
    # Gap at index i is between sorted_lats[i] and sorted_lats[i+1];
    # left cluster size = i+1, right cluster size = n-i-1. Require
    # both >= 2, so i ranges over [1, n-3] inclusive.
    best_ratio = 0.0
    for i in range(1, n - 2):
        gap = sorted_lats[i + 1] - sorted_lats[i]
        ratio = gap / median
        if ratio > best_ratio:
            best_ratio = ratio
    return best_ratio > BIMODAL_GAP_THRESHOLD, best_ratio


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
    # v1.8.1 Codex review #2 fix: trigger format detection *before*
    # starting the latency clock. If the caller hands us a fresh
    # APIClient whose ``_format`` is still None, the first ``call()``
    # silently costs 1 failing Anthropic probe + 1 successful OpenAI
    # request on OpenAI-compatible relays. That first "sample" then
    # contains TWO round-trips and inflates the measured variance,
    # or worse produces a fake bimodal distribution.
    if hasattr(client, "ensure_format"):
        client.ensure_format()

    latencies = []
    errors = []
    for i in range(count):
        # v1.8.1 Codex review #3 fix: use ``perf_counter`` (monotonic
        # high-resolution) rather than ``time.time`` (wall clock).
        # NTP adjustments / clock skew / virtualization jitter can
        # otherwise inject negative or spuriously large gaps into
        # the samples feeding CV and bimodality detection.
        t0 = time.perf_counter()
        r = client.call(
            [{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )
        elapsed = time.perf_counter() - t0
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
