"""Tests for api_relay_audit.latency_variance (Step 13, v1.8)."""

import argparse

import pytest
from unittest.mock import MagicMock

from api_relay_audit.latency_variance import (
    LATENCY_PROBE_MAX,
    LATENCY_PROBE_MIN,
    classify_variance,
    detect_bimodality,
    run_latency_variance,
    summarize_latencies,
    validate_probe_count,
)


# ---------------------------------------------------------------------------
# summarize_latencies
# ---------------------------------------------------------------------------

class TestSummarizeLatencies:
    def test_empty_input(self):
        assert summarize_latencies([]) == {}

    def test_single_sample(self):
        """statistics.stdev raises on n < 2; we must degrade gracefully."""
        stats = summarize_latencies([1.5])
        assert stats["count"] == 1
        assert stats["min"] == 1.5
        assert stats["max"] == 1.5
        assert stats["mean"] == 1.5
        assert stats["median"] == 1.5
        assert stats["stdev"] == 0.0
        assert stats["cv"] == 0.0

    def test_two_identical_samples(self):
        stats = summarize_latencies([1.0, 1.0])
        assert stats["count"] == 2
        assert stats["stdev"] == 0.0
        assert stats["cv"] == 0.0

    def test_five_samples_computes_cv(self):
        lats = [1.0, 1.1, 0.9, 1.05, 0.95]
        stats = summarize_latencies(lats)
        assert stats["count"] == 5
        assert abs(stats["mean"] - 1.0) < 1e-9
        assert stats["stdev"] > 0
        assert 0 < stats["cv"] < 0.1  # low variance sample

    def test_zero_mean_guard(self):
        """Guard against divide-by-zero when every latency is zero
        (mocked/broken measurements)."""
        stats = summarize_latencies([0.0, 0.0, 0.0])
        assert stats["mean"] == 0.0
        assert stats["cv"] == 0.0


# ---------------------------------------------------------------------------
# detect_bimodality
# ---------------------------------------------------------------------------

class TestDetectBimodality:
    def test_too_few_samples(self):
        """< 4 samples is not enough to claim bimodality."""
        assert detect_bimodality([1.0, 2.0, 3.0]) == (False, 0.0)
        assert detect_bimodality([]) == (False, 0.0)

    def test_stable_distribution_not_bimodal(self):
        lats = [1.0, 1.02, 0.98, 1.01, 0.99, 1.03, 0.97]
        is_bimodal, ratio = detect_bimodality(lats)
        assert is_bimodal is False
        assert ratio < 0.5

    def test_clearly_bimodal_distribution(self):
        """Two clusters: ~1s and ~5s. Largest gap (~4s) / median (3s)
        should be well above the 0.5 threshold."""
        lats = [1.0, 1.1, 0.95, 1.05, 5.0, 4.9, 5.1, 5.05]
        is_bimodal, ratio = detect_bimodality(lats)
        assert is_bimodal is True
        assert ratio > 0.5

    def test_zero_median_guard(self):
        """Divide-by-zero guard when every sample is zero."""
        is_bimodal, ratio = detect_bimodality([0.0, 0.0, 0.0, 0.0])
        assert is_bimodal is False
        assert ratio == 0.0

    def test_n4_single_outlier_not_bimodal(self):
        """Codex review 2026-04-18: a single slow probe among 3 fast
        ones must NOT be classified as bimodal. The exact case from
        the review: [1.00, 1.01, 1.02, 1.80] would report
        (True, ~0.77) under the old max-gap rule; under the
        cluster-size>=2 rule, only the middle split (i=1, 2+2) is
        considered, gap=0.01, ratio~0.01."""
        is_bimodal, ratio = detect_bimodality([1.00, 1.01, 1.02, 1.80])
        assert is_bimodal is False
        assert ratio < 0.5

    def test_n4_true_bimodal_still_detected(self):
        """A genuine 2+2 split at N=4 must still be caught.
        [1.00, 1.01, 1.80, 1.82] splits cleanly: left {1.00, 1.01},
        right {1.80, 1.82}, gap=0.79, median=1.405, ratio~0.56."""
        is_bimodal, ratio = detect_bimodality([1.00, 1.01, 1.80, 1.82])
        assert is_bimodal is True
        assert ratio > 0.5

    def test_n5_extreme_outlier_not_bimodal(self):
        """One slow sample at the top of 5 probes is high-variance,
        not bimodal. Legal gaps are at i=1 and i=2 only; the largest
        (extreme) gap at i=3 is excluded because it would leave a
        right cluster of size 1."""
        is_bimodal, ratio = detect_bimodality([1.0, 1.01, 1.02, 1.03, 5.0])
        assert is_bimodal is False
        assert ratio < 0.5

    def test_n6_outlier_at_extremes_not_bimodal(self):
        """Outliers at both ends (size-1 clusters on each side) do
        not satisfy the >=2-per-cluster rule; the middle is tight, so
        no legal gap crosses the threshold."""
        is_bimodal, ratio = detect_bimodality(
            [0.1, 1.00, 1.01, 1.02, 1.03, 10.0])
        assert is_bimodal is False
        assert ratio < 0.5


# ---------------------------------------------------------------------------
# classify_variance
# ---------------------------------------------------------------------------

class TestClassifyVariance:
    def test_empty_stats_inconclusive(self):
        assert classify_variance({}, False) == "inconclusive"

    def test_fewer_than_three_samples_inconclusive(self):
        stats = summarize_latencies([1.0, 1.1])
        assert classify_variance(stats, False) == "inconclusive"

    def test_bimodal_takes_precedence(self):
        """Even if the CV is below the stable cutoff, a detected
        bimodal distribution wins -- clustering is a stronger
        signal than simple CV."""
        stats = summarize_latencies([1.0, 1.01, 1.02, 1.03, 1.04])
        assert classify_variance(stats, True) == "bimodal"

    def test_stable_low_cv(self):
        stats = summarize_latencies([1.00, 1.01, 0.99, 1.02, 0.98])
        assert classify_variance(stats, False) == "stable"

    def test_variable_mid_cv(self):
        stats = summarize_latencies([1.0, 1.4, 0.8, 1.3, 0.7])
        # CV around 0.27
        assert classify_variance(stats, False) == "variable"

    def test_high_variance(self):
        stats = summarize_latencies([0.5, 2.0, 0.4, 2.5, 0.3])
        # CV around 0.8
        assert classify_variance(stats, False) == "high-variance"


# ---------------------------------------------------------------------------
# run_latency_variance
# ---------------------------------------------------------------------------

class TestRunLatencyVariance:
    def _make_client(self, n, response=None, errors_at=None):
        """Build a mock client whose ``call`` returns a simple response
        N times; if ``errors_at`` is provided, returns ``{"error": ...}``
        for those 0-indexed calls."""
        errors_at = errors_at or set()
        call_count = [0]
        response = response or {
            "text": "ok",
            "input_tokens": 5,
            "output_tokens": 1,
            "raw": {},
            "time": 0.1,
        }

        def side_effect(*args, **kwargs):
            i = call_count[0]
            call_count[0] += 1
            if i in errors_at:
                return {"error": "simulated failure"}
            return dict(response)

        client = MagicMock()
        client.call = MagicMock(side_effect=side_effect)
        return client

    def test_fires_exactly_count_probes(self):
        client = self._make_client(n=5)
        result = run_latency_variance(client, count=5, sleep=0)
        assert client.call.call_count == 5
        assert len(result["latencies"]) == 5
        assert result["errors"] == []

    def test_errors_collected_separately(self):
        client = self._make_client(n=5, errors_at={1, 3})
        result = run_latency_variance(client, count=5, sleep=0)
        assert len(result["latencies"]) == 3
        assert len(result["errors"]) == 2
        assert all(e == "simulated failure" for e in result["errors"])

    def test_all_errors_yields_inconclusive(self):
        client = self._make_client(n=5, errors_at={0, 1, 2, 3, 4})
        result = run_latency_variance(client, count=5, sleep=0)
        assert result["latencies"] == []
        assert result["verdict"] == "inconclusive"
        assert result["stats"] == {}

    def test_latencies_are_positive_floats(self):
        """Sanity: measured latencies must be >= 0. v1.8.1 Codex review
        #3 moved the clock from ``time.time`` (wall clock) to
        ``time.perf_counter`` (monotonic, high-resolution), so negative
        latencies from NTP adjustments are no longer possible."""
        client = self._make_client(n=3)
        result = run_latency_variance(client, count=3, sleep=0)
        for lat in result["latencies"]:
            assert isinstance(lat, float)
            assert lat >= 0.0

    def test_uses_minimal_max_tokens(self):
        """Contract: max_tokens default should be small (<= 16) so
        the audit is cheap to run on metered relays."""
        client = self._make_client(n=2)
        run_latency_variance(client, count=2, sleep=0)
        for call_args in client.call.call_args_list:
            kwargs = call_args.kwargs
            assert kwargs.get("max_tokens", 999) <= 16

    def test_ensure_format_called_before_timing(self):
        """v1.8.1 Codex review #2 fix: Step 13 must trigger format
        auto-detection via ``client.ensure_format()`` before the timing
        loop starts. Otherwise the first ``call()`` on a fresh
        OpenAI-compatible client silently pays for a failed Anthropic
        probe plus the successful OpenAI request and inflates the
        measured variance -- potentially even producing a fake
        bimodal verdict.
        """
        call_order = []

        client = MagicMock()
        client.ensure_format = MagicMock(
            side_effect=lambda: call_order.append("ensure_format"))
        client.call = MagicMock(
            side_effect=lambda *a, **kw: (
                call_order.append("call"),
                {"text": "ok", "input_tokens": 1, "output_tokens": 1,
                 "raw": {}, "time": 0.1},
            )[1])

        run_latency_variance(client, count=3, sleep=0)

        assert client.ensure_format.called, (
            "Step 13 must call client.ensure_format() before timing"
        )
        # ensure_format must precede the very first call()
        assert call_order[0] == "ensure_format"
        assert call_order.count("ensure_format") == 1
        assert call_order.count("call") == 3

    def test_works_without_ensure_format_method(self):
        """Older clients or test doubles may lack ``ensure_format``.
        Step 13 must degrade gracefully rather than crash with an
        AttributeError.
        """
        client = MagicMock(spec=["call"])  # no ensure_format on spec
        client.call = MagicMock(return_value={
            "text": "ok", "input_tokens": 1, "output_tokens": 1,
            "raw": {}, "time": 0.1,
        })

        # Must not raise.
        result = run_latency_variance(client, count=3, sleep=0)
        assert len(result["latencies"]) == 3

    def test_3_success_7_error_reaches_classified_verdict(self):
        """Partial-success scenario (Codex review 2026-04-18 LOW
        finding): 3 out of 10 probes succeed, 7 error out. Must
        still reach a classified verdict (stable/variable/
        high-variance/bimodal), not silently fall to inconclusive.

        Count == 3 is the minimum for classify_variance to fire;
        bimodality requires N>=4 so is_bimodal=False here, and the
        verdict resolves via CV. Tests the boundary where the
        verdict is just barely defensible."""
        # Errors at 7 of 10 indices, successes at 0/3/6
        client = self._make_client(n=10, errors_at={1, 2, 4, 5, 7, 8, 9})
        result = run_latency_variance(client, count=10, sleep=0)
        assert len(result["latencies"]) == 3
        assert len(result["errors"]) == 7
        assert result["verdict"] in (
            "stable", "variable", "high-variance"
        ), f"Expected CV-based verdict, got {result['verdict']!r}"
        # bimodal verdict requires N>=4 samples, so must not fire here
        assert result["bimodal"] is False


# ---------------------------------------------------------------------------
# validate_probe_count (v1.8.1 Codex review #5 fix)
# ---------------------------------------------------------------------------

class TestValidateProbeCount:
    """Guards on ``--latency-probe-count``. Without these, N=0 silently
    collapsed Step 13 into an "all 0 probes failed" inconclusive, and
    absurdly-large N linearly inflated metered billing."""

    def test_accepts_minimum(self):
        assert validate_probe_count(LATENCY_PROBE_MIN) == LATENCY_PROBE_MIN

    def test_accepts_maximum(self):
        assert validate_probe_count(LATENCY_PROBE_MAX) == LATENCY_PROBE_MAX

    def test_accepts_default(self):
        assert validate_probe_count(10) == 10

    def test_accepts_numeric_string(self):
        """argparse feeds us string values from the command line."""
        assert validate_probe_count("10") == 10

    def test_rejects_zero(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count(0)

    def test_rejects_negative(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count(-5)

    def test_rejects_below_minimum(self):
        """2 would allow classify_variance to fire but is below the
        conservative floor; reject explicitly so the CLI error is
        readable rather than silently producing a degenerate sample."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count(LATENCY_PROBE_MIN - 1)

    def test_rejects_above_maximum(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count(LATENCY_PROBE_MAX + 1)

    def test_rejects_huge_value(self):
        """A million probes would run for hours and rack up billing."""
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count(1_000_000)

    def test_rejects_non_numeric_string(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count("abc")

    def test_rejects_none(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_probe_count(None)
