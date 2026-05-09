"""Tests for api_relay_audit.infra_fingerprint (Step 12, v1.8)."""

from unittest.mock import MagicMock

from api_relay_audit.infra_fingerprint import (
    aggregate_framework,
    classify_framework,
    extract_informative_headers,
    run_infra_fingerprint,
)


# ---------------------------------------------------------------------------
# classify_framework
# ---------------------------------------------------------------------------

class TestClassifyFramework:
    def test_empty_inputs_no_match(self):
        framework, signals = classify_framework({}, "")
        assert framework is None
        assert signals == []

    def test_none_inputs_no_match(self):
        framework, signals = classify_framework(None, None)
        assert framework is None
        assert signals == []

    def test_one_api_body_match(self):
        body = '<html><title>One API</title></html>'
        framework, signals = classify_framework({}, body)
        assert framework == "one-api"
        assert any("one api" in sig[1].lower() for sig in signals)

    def test_new_api_takes_precedence_over_one_api(self):
        """New-API references include the string 'one-api' inside
        'calcium-ion/new-api' style URLs. The new-api branch must
        match first so operators don't get mis-classified as plain
        one-api.
        """
        body = "<script src='https://github.com/Calcium-Ion/new-api'></script>"
        framework, signals = classify_framework({}, body)
        assert framework == "new-api"

    def test_header_presence_signal(self):
        """``cf-ray`` header presence alone (no body marker) should
        classify as cloudflare."""
        framework, signals = classify_framework({"cf-ray": "abc123"}, "")
        assert framework == "cloudflare"

    def test_nginx_raw_from_server_header(self):
        framework, _ = classify_framework({"Server": "nginx/1.22.1"}, "")
        assert framework == "nginx-raw"

    def test_caddy_raw_from_server_header(self):
        framework, _ = classify_framework({"Server": "Caddy"}, "")
        assert framework == "caddy-raw"

    def test_case_insensitive_header_name(self):
        """Header names are case-insensitive per HTTP spec; our matcher
        must respect that."""
        framework, _ = classify_framework({"CF-RAY": "xyz"}, "")
        assert framework == "cloudflare"

    def test_case_insensitive_body_match(self):
        framework, _ = classify_framework({}, "ONE API welcome page")
        assert framework == "one-api"

    def test_unknown_framework_returns_none(self):
        framework, signals = classify_framework(
            {"server": "custom-proxy/9.9"}, "hello world"
        )
        assert framework is None
        assert signals == []

    def test_lone_next_js_header_does_not_classify_lobechat(self):
        """v1.8.1 Codex review #4 fix: ``x-powered-by: next.js`` is
        emitted by every Vercel site and every marketing Next.js
        frontend. Using it as a standalone signal for lobechat-relay
        produced confident misclassifications for operators that
        merely happen to deploy on Next.js. The signal was removed;
        this test locks in the new negative behavior.
        """
        framework, _ = classify_framework(
            {"x-powered-by": "Next.js"}, "<html><body>hi</body></html>"
        )
        assert framework is None, (
            "Lone next.js header must not classify as lobechat-relay"
        )

        # Body branding alone still wins.
        framework, _ = classify_framework(
            {"x-powered-by": "Next.js"},
            "<html><title>LobeChat</title></html>",
        )
        assert framework == "lobechat-relay"

    def test_body_scan_capped(self):
        """Body scan is capped at 8KB; branding buried past that should
        not match. This prevents slow scans on multi-MB landing pages."""
        # Stuff 20KB of filler, put marker AFTER the cap
        body = "A" * 20000 + "one api"
        framework, _ = classify_framework({}, body)
        assert framework is None

    # v1.9 header_prefix: signal tests ----------------------------------------

    def test_litellm_header_prefix_match(self):
        framework, signals = classify_framework(
            {"x-litellm-call-id": "abc123"}, ""
        )
        assert framework == "litellm"
        assert any("x-litellm-" in s[0] for s in signals)

    def test_helicone_header_prefix_match(self):
        framework, signals = classify_framework(
            {"helicone-id": "xyz"}, ""
        )
        assert framework == "helicone"
        assert any("helicone-" in s[0] for s in signals)

    def test_portkey_header_prefix_match(self):
        framework, signals = classify_framework(
            {"x-portkey-request-id": "xyz"}, ""
        )
        assert framework == "portkey"
        assert any("x-portkey-" in s[0] for s in signals)

    def test_kong_header_prefix_match(self):
        framework, signals = classify_framework(
            {"x-kong-upstream-latency": "12"}, ""
        )
        assert framework == "kong-gateway"
        assert any("x-kong-" in s[0] for s in signals)

    def test_dashscope_header_prefix_match(self):
        framework, signals = classify_framework(
            {"x-dashscope-request-id": "xyz"}, ""
        )
        assert framework == "alibaba-dashscope"
        assert any("x-dashscope-" in s[0] for s in signals)

    def test_azure_foundry_header_match(self):
        framework, signals = classify_framework(
            {"apim-request-id": "00000000-0000-0000-0000-000000000001"}, ""
        )
        assert framework == "azure-foundry"
        assert any("apim-request-id" in s[0] for s in signals)

    def test_header_prefix_beats_body_match(self):
        """header_prefix: entries appear before body-based entries in
        FRAMEWORK_SIGNATURES, so a LiteLLM header wins over new-api body text."""
        framework, _ = classify_framework(
            {"x-litellm-version": "1.0.0"},
            "<html>new api</html>",
        )
        assert framework == "litellm", (
            "header_prefix signal should win over body match when listed first"
        )

    def test_header_prefix_no_partial_key_match(self):
        """``x-litellm`` (no trailing dash) must not match the
        ``header_prefix:x-litellm-`` rule — the dash is load-bearing."""
        framework, _ = classify_framework(
            {"x-litellm": "some-value"}, ""
        )
        assert framework is None, (
            "Prefix x-litellm- must not match header key x-litellm (no dash)"
        )


# ---------------------------------------------------------------------------
# extract_informative_headers
# ---------------------------------------------------------------------------

class TestExtractInformativeHeaders:
    def test_empty_input(self):
        assert extract_informative_headers({}) == {}
        assert extract_informative_headers(None) == {}

    def test_preserves_original_casing(self):
        """Report renders these headers; preserve the original case so
        operators see 'CF-Ray' not 'cf-ray'."""
        headers = {"CF-Ray": "abc123", "X-Powered-By": "new-api"}
        out = extract_informative_headers(headers)
        assert "CF-Ray" in out
        assert "X-Powered-By" in out

    def test_filters_out_uninteresting_headers(self):
        headers = {
            "server": "nginx/1.22",
            "content-type": "application/json",
            "connection": "keep-alive",
        }
        out = extract_informative_headers(headers)
        assert "server" in out
        assert "content-type" not in out
        assert "connection" not in out


# ---------------------------------------------------------------------------
# aggregate_framework
# ---------------------------------------------------------------------------

class TestAggregateFramework:
    def test_empty_results_unknown(self):
        framework, confidence = aggregate_framework([])
        assert framework is None
        assert confidence == "unknown"

    def test_all_no_match_unknown(self):
        results = [
            {"framework": None},
            {"framework": None},
            {"framework": None},
        ]
        framework, confidence = aggregate_framework(results)
        assert framework is None
        assert confidence == "unknown"

    def test_single_hit_is_tentative(self):
        results = [
            {"framework": "one-api"},
            {"framework": None},
            {"framework": None},
        ]
        framework, confidence = aggregate_framework(results)
        assert framework == "one-api"
        assert confidence == "tentative"

    def test_two_hits_confirmed(self):
        results = [
            {"framework": "new-api"},
            {"framework": "new-api"},
            {"framework": None},
        ]
        framework, confidence = aggregate_framework(results)
        assert framework == "new-api"
        assert confidence == "confirmed"

    def test_all_three_hits_confirmed(self):
        results = [
            {"framework": "cloudflare"},
            {"framework": "cloudflare"},
            {"framework": "cloudflare"},
        ]
        framework, confidence = aggregate_framework(results)
        assert framework == "cloudflare"
        assert confidence == "confirmed"

    def test_split_vote_picks_mode(self):
        """If two different frameworks each fire once, the mode wins
        at tentative confidence.

        KNOWN LIMITATION (Codex review 2026-04-18, HIGH finding):
        pure majority vote means generic edge-layer signals
        (``Server: nginx``) can drown out app-layer hits when only
        one probe catches the app framework. v1.8.1 may split
        app-framework and edge-layer signals into separate fields;
        this test documents current behavior so any future change
        is explicit. See FOR_JOHN.md for the Pareto decision.
        """
        results = [
            {"framework": "one-api"},
            {"framework": "nginx-raw"},
            {"framework": "nginx-raw"},
        ]
        framework, confidence = aggregate_framework(results)
        assert framework == "nginx-raw"
        assert confidence == "confirmed"


# ---------------------------------------------------------------------------
# run_infra_fingerprint
# ---------------------------------------------------------------------------

class TestRunInfraFingerprint:
    def _make_client(self, responses):
        """Build a mock client whose ``raw_request`` returns the next
        entry in ``responses`` on each call, in probe order
        (landing / models / notfound).
        """
        client = MagicMock()
        client.raw_request = MagicMock(side_effect=responses)
        return client

    def test_fires_three_probes_in_order(self):
        responses = [
            {"status": 200, "headers": {}, "body": "", "error": None},
            {"status": 401, "headers": {}, "body": "", "error": None},
            {"status": 404, "headers": {}, "body": "", "error": None},
        ]
        client = self._make_client(responses)
        results = run_infra_fingerprint(client)
        assert len(results) == 3
        assert [r["probe"] for r in results] == ["landing", "models", "notfound"]
        assert [r["path"] for r in results] == [
            "/", "/v1/models", "/nonexistent-abc12345xyz"
        ]

    def test_classifies_one_api_landing(self):
        responses = [
            {"status": 200,
             "headers": {"server": "nginx/1.22"},
             "body": "<html><title>One API</title></html>",
             "error": None},
            {"status": 401,
             "headers": {"server": "nginx/1.22"},
             "body": "", "error": None},
            {"status": 404,
             "headers": {"server": "nginx/1.22"},
             "body": "{}", "error": None},
        ]
        client = self._make_client(responses)
        results = run_infra_fingerprint(client)
        # Landing page identified one-api; other two are plain nginx
        assert results[0]["framework"] == "one-api"
        # And informative headers are extracted on all probes
        assert "server" in results[0]["headers"]

    def test_transport_error_yields_null_classification(self):
        responses = [
            {"status": 0, "headers": {}, "body": "",
             "error": "Connection refused"},
            {"status": 0, "headers": {}, "body": "",
             "error": "Connection refused"},
            {"status": 0, "headers": {}, "body": "",
             "error": "Connection refused"},
        ]
        client = self._make_client(responses)
        results = run_infra_fingerprint(client)
        for r in results:
            assert r["framework"] is None
            assert r["error"] == "Connection refused"
        framework, confidence = aggregate_framework(results)
        assert confidence == "unknown"

    def test_body_preview_truncated(self):
        big_body = "X" * 5000
        responses = [
            {"status": 200, "headers": {}, "body": big_body, "error": None},
            {"status": 200, "headers": {}, "body": "", "error": None},
            {"status": 404, "headers": {}, "body": "", "error": None},
        ]
        client = self._make_client(responses)
        results = run_infra_fingerprint(client)
        assert len(results[0]["body_preview"]) == 200

    def test_one_api_behind_cloudflare_aggregates_as_cloudflare(self):
        """KNOWN LIMITATION (Codex review 2026-04-18, HIGH finding):
        Cloudflare-fronted one-api has ``cf-ray`` on every probe and
        one-api branding only on ``/``. Majority vote therefore
        classifies the whole thing as cloudflare ``confirmed``.

        The app-layer identity (one-api) is visible in the per-probe
        result and can still be recovered; only the aggregate loses
        it. v1.8.1 may separate app vs edge layers. This test locks
        in the current behavior so any change is deliberate.
        """
        one_api_body = '<html><title>One API</title></html>'
        responses = [
            {"status": 200,
             "headers": {"cf-ray": "abc-ord", "server": "cloudflare"},
             "body": one_api_body,
             "error": None},
            {"status": 401,
             "headers": {"cf-ray": "abc-ord", "server": "cloudflare"},
             "body": "", "error": None},
            {"status": 404,
             "headers": {"cf-ray": "abc-ord", "server": "cloudflare"},
             "body": "", "error": None},
        ]
        client = self._make_client(responses)
        results = run_infra_fingerprint(client)
        # Per-probe: landing still recognizes one-api before CF edge
        assert results[0]["framework"] == "one-api"
        assert results[1]["framework"] == "cloudflare"
        assert results[2]["framework"] == "cloudflare"
        # Aggregate: majority wins -> cloudflare confirmed
        framework, confidence = aggregate_framework(results)
        assert framework == "cloudflare"
        assert confidence == "confirmed"

    def test_new_api_behind_cloudflare_aggregates_as_cloudflare(self):
        """Same as above but with a new-api landing page. New-api is
        a popular OneAPI derivative per arXiv:2603.01919 Section 3.2;
        losing it to CF edge is the single costliest instance of the
        HIGH finding.
        """
        new_api_body = "<script src='https://github.com/Calcium-Ion/new-api'></script>"
        responses = [
            {"status": 200,
             "headers": {"cf-ray": "xyz-sjc"},
             "body": new_api_body,
             "error": None},
            {"status": 401,
             "headers": {"cf-ray": "xyz-sjc"}, "body": "", "error": None},
            {"status": 404,
             "headers": {"cf-ray": "xyz-sjc"}, "body": "", "error": None},
        ]
        client = self._make_client(responses)
        results = run_infra_fingerprint(client)
        assert results[0]["framework"] == "new-api"
        framework, confidence = aggregate_framework(results)
        assert framework == "cloudflare"
        assert confidence == "confirmed"
