"""Tests for api_relay_audit.latency_variance (Step 13, v1.8)."""

from unittest.mock import MagicMock

from api_relay_audit.latency_variance import (
    classify_variance,
    detect_bimodality,
    run_latency_variance,
    summarize_latencies,
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
        """Sanity: measured latencies must be >= 0 (monotonic clock
        via time.time is not guaranteed strictly monotonic, but we
        don't sleep between t0 and the mocked return, so this is
        essentially a type check)."""
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
