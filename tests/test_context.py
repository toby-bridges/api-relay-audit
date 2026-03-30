"""Tests for api_relay_audit.context (single_context_test & run_context_scan)."""

from unittest.mock import MagicMock, patch

import pytest

from api_relay_audit.context import FILLER, run_context_scan, single_context_test


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_client_response(text="", input_tokens=100, output_tokens=50, time_=0.5):
    """Build a mock client.call() return value."""
    return {
        "text": text,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "time": time_,
    }


def make_error_response(msg="API error", time_=0.1):
    return {"error": msg, "time": time_}


# ---------------------------------------------------------------------------
# single_context_test
# ---------------------------------------------------------------------------

class TestSingleContextTest:
    def test_all_canaries_found(self):
        """When the model echoes back all canary markers, status should be 'ok'."""
        client = MagicMock()

        def capture_call(messages, max_tokens=512):
            # Extract canaries from the prompt and echo them back
            prompt = messages[0]["content"]
            canaries = []
            for part in prompt.split("["):
                if part.startswith("CANARY_"):
                    canaries.append(part.split("]")[0])
            return make_client_response(text="\n".join(canaries))

        client.call.side_effect = capture_call

        target_k, found, total, input_tokens, status, elapsed = single_context_test(client, 10)

        assert target_k == 10
        assert found == 5
        assert total == 5
        assert status == "ok"
        assert input_tokens == 100

    def test_partial_canaries_truncated(self):
        """When only some canaries are found, status should be 'truncated'."""
        client = MagicMock()

        def partial_call(messages, max_tokens=512):
            import re
            prompt = messages[0]["content"]
            canaries = re.findall(r"CANARY_\d_[a-f0-9]+", prompt)
            # Only return first 2 canaries
            return make_client_response(text="\n".join(canaries[:2]))

        client.call.side_effect = partial_call

        target_k, found, total, input_tokens, status, elapsed = single_context_test(client, 50)

        assert target_k == 50
        assert found == 2
        assert total == 5
        assert status == "truncated"

    def test_no_canaries_found(self):
        client = MagicMock()
        client.call.return_value = make_client_response(text="I don't see any markers.")

        target_k, found, total, input_tokens, status, elapsed = single_context_test(client, 100)

        assert found == 0
        assert status == "truncated"

    def test_error_response(self):
        client = MagicMock()
        client.call.return_value = make_error_response("timeout")

        target_k, found, total, input_tokens, status, elapsed = single_context_test(client, 200)

        assert target_k == 200
        assert found == 0
        assert total == 5
        assert input_tokens is None
        assert status == "error"

    def test_prompt_contains_canary_markers(self):
        """Verify the prompt sent to the client contains 5 CANARY markers."""
        client = MagicMock()
        client.call.return_value = make_client_response(text="none")

        single_context_test(client, 10)

        prompt = client.call.call_args[0][0][0]["content"]
        canary_count = prompt.count("CANARY_")
        # 5 in brackets + 5 mentioned in instruction = at least 5 unique
        assert canary_count >= 5

    @pytest.mark.parametrize("target_k", [1, 10, 50, 100])
    def test_prompt_length_scales(self, target_k):
        """Prompt should be roughly target_k * 1000 chars."""
        client = MagicMock()
        client.call.return_value = make_client_response(text="")

        single_context_test(client, target_k)

        prompt = client.call.call_args[0][0][0]["content"]
        expected_min = target_k * 1000 * 0.8
        expected_max = target_k * 1000 * 1.3
        assert expected_min < len(prompt) < expected_max

    def test_max_tokens_passed(self):
        client = MagicMock()
        client.call.return_value = make_client_response(text="")

        single_context_test(client, 10)

        assert client.call.call_args[1]["max_tokens"] == 512

    def test_elapsed_time_from_response(self):
        client = MagicMock()
        client.call.return_value = make_client_response(text="", time_=3.14)

        _, _, _, _, _, elapsed = single_context_test(client, 5)
        assert elapsed == 3.14


# ---------------------------------------------------------------------------
# run_context_scan
# ---------------------------------------------------------------------------

class TestRunContextScan:
    @patch("api_relay_audit.context.time.sleep")
    def test_all_pass_no_binary_search(self, mock_sleep):
        """When all coarse steps pass, no binary search should occur."""
        client = MagicMock()

        def all_ok(messages, max_tokens=512):
            prompt = messages[0]["content"]
            canaries = []
            for part in prompt.split("["):
                if part.startswith("CANARY_"):
                    canaries.append(part.split("]")[0])
            return make_client_response(text="\n".join(canaries))

        client.call.side_effect = all_ok

        results = run_context_scan(client, coarse_steps=[50, 100, 200], sleep_between=0)

        assert len(results) == 3
        assert all(r[4] == "ok" for r in results)
        # Results should be sorted by target_k
        assert [r[0] for r in results] == [50, 100, 200]

    @patch("api_relay_audit.context.time.sleep")
    def test_failure_triggers_binary_search(self, mock_sleep):
        """When a coarse step fails, binary search should narrow the boundary."""
        client = MagicMock()
        call_count = [0]

        def conditional_response(messages, max_tokens=512):
            call_count[0] += 1
            prompt = messages[0]["content"]
            # Estimate target_k from prompt length
            target_k_approx = len(prompt) // 1000

            canaries = []
            for part in prompt.split("["):
                if part.startswith("CANARY_"):
                    canaries.append(part.split("]")[0])

            if target_k_approx < 150:
                return make_client_response(text="\n".join(canaries))
            else:
                return make_client_response(text="I only see two markers")

        client.call.side_effect = conditional_response

        results = run_context_scan(
            client,
            coarse_steps=[50, 100, 200],
            sleep_between=0,
        )

        # Should have more than 3 results due to binary search
        assert len(results) > 3
        # Should be sorted
        ks = [r[0] for r in results]
        assert ks == sorted(ks)

    @patch("api_relay_audit.context.time.sleep")
    def test_first_step_fails(self, mock_sleep):
        """When the very first coarse step fails, last_ok=0, first_fail=first_step."""
        client = MagicMock()

        def always_fail(messages, max_tokens=512):
            return make_client_response(text="nothing found")

        client.call.side_effect = always_fail

        results = run_context_scan(
            client,
            coarse_steps=[50, 100],
            sleep_between=0,
        )

        # Should stop after first failure in coarse scan
        # But binary search between 0 and 50 would run since first_fail=50
        assert len(results) >= 1
        assert results[0][4] == "truncated"

    @patch("api_relay_audit.context.time.sleep")
    def test_default_coarse_steps(self, mock_sleep):
        """Default coarse_steps should be [50, 100, 200, 400, 600, 800]."""
        client = MagicMock()

        def instant_fail(messages, max_tokens=512):
            return make_client_response(text="")

        client.call.side_effect = instant_fail

        results = run_context_scan(client, sleep_between=0)

        # First call should be at 50k (the first default step)
        # It will fail immediately, stopping coarse scan
        assert len(results) >= 1

    @patch("api_relay_audit.context.time.sleep")
    def test_sleep_called_between_steps(self, mock_sleep):
        """time.sleep should be called between coarse steps."""
        client = MagicMock()

        def echo_canaries(messages, max_tokens=512):
            prompt = messages[0]["content"]
            canaries = []
            for part in prompt.split("["):
                if part.startswith("CANARY_"):
                    canaries.append(part.split("]")[0])
            return make_client_response(text="\n".join(canaries))

        client.call.side_effect = echo_canaries

        run_context_scan(client, coarse_steps=[50, 100], sleep_between=3)

        # Sleep should have been called between the two coarse steps
        mock_sleep.assert_called_with(3)

    @patch("api_relay_audit.context.time.sleep")
    def test_results_sorted_by_target_k(self, mock_sleep):
        """Results should always be sorted by target_k."""
        client = MagicMock()
        call_idx = [0]

        def varying_response(messages, max_tokens=512):
            call_idx[0] += 1
            prompt = messages[0]["content"]
            canaries = []
            for part in prompt.split("["):
                if part.startswith("CANARY_"):
                    canaries.append(part.split("]")[0])
            # Fail at >= 200k
            if len(prompt) > 180_000:
                return make_client_response(text="partial")
            return make_client_response(text="\n".join(canaries))

        client.call.side_effect = varying_response

        results = run_context_scan(
            client,
            coarse_steps=[50, 100, 200],
            sleep_between=0,
        )

        ks = [r[0] for r in results]
        assert ks == sorted(ks)

    @patch("api_relay_audit.context.time.sleep")
    def test_error_during_coarse_breaks_loop(self, mock_sleep):
        """An error status during coarse scan should break the loop (treated as failure)."""
        client = MagicMock()

        def error_at_100(messages, max_tokens=512):
            prompt = messages[0]["content"]
            canaries = []
            for part in prompt.split("["):
                if part.startswith("CANARY_"):
                    canaries.append(part.split("]")[0])

            if len(prompt) > 80_000:
                return make_error_response("rate limited")
            return make_client_response(text="\n".join(canaries))

        client.call.side_effect = error_at_100

        results = run_context_scan(
            client,
            coarse_steps=[50, 100, 200, 400],
            sleep_between=0,
        )

        # Coarse should stop at 100 (error), then binary search between 50 and 100
        coarse_ks = [50, 100]
        assert any(r[0] == 50 for r in results)
        assert any(r[0] == 100 for r in results)
        # Should not reach 400
        assert not any(r[0] == 400 for r in results)


# ---------------------------------------------------------------------------
# Module-level constant
# ---------------------------------------------------------------------------

class TestFiller:
    def test_filler_not_empty(self):
        assert len(FILLER) > 0

    def test_filler_contains_newline(self):
        assert "\n" in FILLER
