"""Tests for api_relay_audit.error_leakage (Step 9 AC-2 adjacent detection)."""

import json
from unittest.mock import MagicMock

import pytest

from api_relay_audit.error_leakage import (
    _build_triggers,
    _highest_severity,
    _redact_api_key,
    run_error_leakage_test,
    scan_for_leaks,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_raw_response(status=400, body="", headers=None, error=None):
    return {
        "status": status,
        "body": body,
        "headers": headers or {},
        "error": error,
    }


API_KEY = "sk-test-abcdefgh12345678ijklmnop"  # 30 chars, first-8 = "sk-test-"


# ---------------------------------------------------------------------------
# scan_for_leaks
# ---------------------------------------------------------------------------

class TestScanForLeaks:
    def test_no_leak(self):
        """Clean error body with no credential / plumbing leaks returns []."""
        body = '{"error":{"type":"invalid_request","message":"bad request"}}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        assert hits == []

    def test_full_api_key_echo_in_body(self):
        body = f'{{"error":"Invalid auth: {API_KEY} is not valid"}}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        # Critical hit plus no follow-on partial hit on the same target
        crit = [h for h in hits if h["severity"] == "critical"]
        assert len(crit) == 1
        assert crit[0]["kind"] == "full_api_key_echo"
        assert crit[0]["where"] == "body"
        # Snippet must NOT contain the raw api key (redacted)
        assert API_KEY not in crit[0]["snippet"]
        assert "<REDACTED_API_KEY>" in crit[0]["snippet"]

    def test_full_api_key_echo_in_header(self):
        headers = {"x-upstream-auth-echo": f"Bearer {API_KEY}"}
        hits = scan_for_leaks("", headers, API_KEY, "https://relay.example.com")
        crit = [h for h in hits if h["severity"] == "critical"]
        assert len(crit) == 1
        assert crit[0]["where"].startswith("header: ")
        assert API_KEY not in crit[0]["snippet"]

    def test_api_key_prefix_high(self):
        """First-8 prefix alone (no full key) -> HIGH severity."""
        body = '{"error":"upstream returned 401 for key sk-test-... hello"}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        high = [h for h in hits if h["kind"] == "api_key_prefix"]
        assert len(high) == 1
        assert high[0]["severity"] == "high"
        assert "sk-test-" not in high[0]["snippet"]
        assert "<REDACTED_PREFIX>" in high[0]["snippet"]

    def test_upstream_host_leak(self):
        body = '{"error":"connect ECONNREFUSED api.anthropic.com:443"}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        upstream = [h for h in hits if h["kind"] == "upstream_host"]
        assert len(upstream) == 1
        assert upstream[0]["severity"] == "high"
        assert "api.anthropic.com" in upstream[0]["snippet"]

    def test_env_var_leak(self):
        body = 'KeyError: ANTHROPIC_API_KEY not set in process env'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        env = [h for h in hits if h["kind"] == "env_var"]
        assert len(env) == 1
        assert env[0]["severity"] == "high"

    def test_fs_path_medium(self):
        body = 'File "/app/relay/server.py", line 42: unhandled error'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        # Both fs_path and stack_trace markers exist; both should hit
        path_hits = [h for h in hits if h["kind"] == "fs_path"]
        stack_hits = [h for h in hits if h["kind"] == "stack_trace"]
        assert len(path_hits) == 1
        assert path_hits[0]["severity"] == "medium"
        assert len(stack_hits) == 1

    def test_stack_trace_medium_only(self):
        body = "Traceback (most recent call last):\n  ValueError: boom"
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        assert any(h["kind"] == "stack_trace" and h["severity"] == "medium" for h in hits)

    def test_multi_leak_ordering_preserved(self):
        """Body containing full key + upstream host + path -> at least 3 hits,
        with the full-key CRITICAL present."""
        body = (
            f'Traceback at /app/server.py: upstream api.openai.com returned '
            f'401 for key {API_KEY}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        severities = [h["severity"] for h in hits]
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities

    def test_snippet_always_redacted_for_path_hit(self):
        """Even a non-credential hit must scrub the api_key if it happens
        to fall inside the 80-char context window."""
        body = f'/home/user/.env: OPENAI_API_KEY={API_KEY}\n'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        for h in hits:
            assert API_KEY not in h["snippet"]


# ---------------------------------------------------------------------------
# LiteLLM-ported secret regex patterns (v1.5)
# ---------------------------------------------------------------------------

# A realistic-but-fake api_key distinct from our test API_KEY so the
# regex tests do not collide with the literal api_key_echo detection.
OTHER_SK_KEY = "sk-other-deadbeefcafebabef00dfeed1234"
OTHER_BEARER = "Bearer eyjZhVyaG53vK1aoB23L9qdT45Gp7Rj8HsD2"
OTHER_AWS = "AKIAIOSFODNN7EXAMPLE"
OTHER_GOOGLE = "AIzaSyBEV8h2Nc0x-fake_example_goog1eAp1key0"
OTHER_GCP = "ya29.a0ARrdaM9fake_token_with_enough_characters_to_match_minimum_length"
OTHER_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.S3cr3tPart"
OTHER_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
    "-----END RSA PRIVATE KEY-----"
)
OTHER_CONNSTRING = "postgres://admin:s3cretpass@db.internal:5432/prod"


class TestScanForLeaksRegex:
    """LiteLLM-ported regex patterns, v1.5.

    Each pattern gets a positive test (credential is found) and
    a negative check (we don't double-count with the literal api_key_echo).
    """

    def _assert_hit(self, hits, kind, severity="high"):
        matches = [h for h in hits if h["kind"] == kind]
        assert matches, f"Expected hit kind={kind} in {[h['kind'] for h in hits]}"
        for m in matches:
            assert m["severity"] == severity

    def _assert_no_hit(self, hits, kind):
        matches = [h for h in hits if h["kind"] == kind]
        assert not matches, f"Unexpected hit kind={kind}: {matches}"

    def test_sk_prefix_secret_positive(self):
        body = f'{{"error":"upstream says: {OTHER_SK_KEY} is invalid"}}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "sk_prefix_secret")

    def test_sk_prefix_secret_skipped_on_literal_overlap(self):
        """The api_key literal check already claimed the span — the sk-
        regex must NOT double-count."""
        body = f'{{"key_echoed":"{API_KEY}"}}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        # Should have ONE critical full_api_key_echo, NOT also an
        # sk_prefix_secret regex hit on the same span.
        assert any(h["kind"] == "full_api_key_echo" for h in hits)
        assert not any(h["kind"] == "sk_prefix_secret" for h in hits)

    def test_bearer_token_positive(self):
        body = f'Authorization: {OTHER_BEARER}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "bearer_token")

    def test_bearer_token_too_short_not_flagged(self):
        """Short bearer (< 20 chars after 'Bearer ') should not false-fire."""
        body = "Use Bearer <your_token>"  # placeholder, 13 chars
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_no_hit(hits, "bearer_token")

    def test_aws_access_key_positive(self):
        body = f'AWS ERROR: credential {OTHER_AWS} denied access'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "aws_access_key")

    def test_google_api_key_positive(self):
        body = f'GET /v1/generate?key={OTHER_GOOGLE} 403'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "google_api_key")

    def test_gcp_oauth_token_positive(self):
        body = f'access_token={OTHER_GCP}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "gcp_oauth_token")

    def test_jwt_token_positive(self):
        body = f'{{"token":"{OTHER_JWT}"}}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "jwt_token")

    def test_pem_private_key_positive(self):
        body = f'Error dumping config: key={OTHER_PEM}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "pem_private_key")

    def test_db_connstring_password_positive(self):
        body = f'Failed to connect: {OTHER_CONNSTRING}'
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        self._assert_hit(hits, "db_connstring_password")

    def test_no_false_positive_on_clean_json_error(self):
        """A standard OpenAI-style error with no credentials or PII
        should produce ZERO regex hits."""
        body = (
            '{"error":{"message":"field messages is required",'
            '"type":"invalid_request_error","param":null,"code":null}}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        regex_kinds = {
            "sk_prefix_secret", "bearer_token", "aws_access_key",
            "google_api_key", "gcp_oauth_token", "jwt_token",
            "pem_private_key", "db_connstring_password",
        }
        assert not any(h["kind"] in regex_kinds for h in hits)

    def test_multiple_regex_kinds_on_same_body(self):
        """A kitchen-sink leak with multiple credential types should
        yield one hit per kind."""
        body = (
            f'{{"aws":"{OTHER_AWS}","google":"{OTHER_GOOGLE}",'
            f'"sk":"{OTHER_SK_KEY}"}}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "aws_access_key" in kinds
        assert "google_api_key" in kinds
        assert "sk_prefix_secret" in kinds

    # ----- v1.5.1 additions sourced from LiteLLM issue tracker -----

    def test_google_key_url_param_positive(self):
        """LiteLLM #8075 / #15799: Gemini httpx wraps the full URL
        (including ?key=AIza...) into exception strings, which then
        propagate into proxy error responses."""
        body = (
            '{"error":"HTTPStatusError: 404 for url '
            "'https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-pro:streamGenerateContent?key=AIzaSyBEV8h2Nc0x-fake_example_goog1eAp1key0"
            "&alt=sse'\"}"
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "google_key_url_param" in kinds

    def test_google_key_url_param_requires_25_chars(self):
        """Short `?key=X` placeholder in docs should NOT trigger."""
        body = "example: use https://api.example.com/?key=your_key_here"
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "google_key_url_param" not in kinds


class TestLitellmInternalAndPiiLeaks:
    """v1.5.1: LiteLLM-internal field leak detection and provider-side
    PII echo detection. Both are MEDIUM severity (information disclosure,
    not direct credential echo) and sourced from verified LiteLLM bug
    reports. See reference_litellm_secret_regex memory for issue numbers."""

    def test_model_list_leak_medium(self):
        """LiteLLM #5762: router returned model_list with all
        deployments (including api_key + api_base) in an error body."""
        body = (
            '{"error":"no matching deployment","model_list":['
            '{"model_name":"gpt-4","litellm_params":{"api_key":"sk-upstream-redacted"}}]}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "litellm_internal_leak" in kinds
        # Confirm MEDIUM not HIGH (info disclosure tier)
        litellm_hit = next(h for h in hits if h["kind"] == "litellm_internal_leak")
        assert litellm_hit["severity"] == "medium"

    def test_previous_models_retry_leak_medium(self):
        """LiteLLM #13705: router.log_retry() dumped full kwargs into
        previous_models, including user_api_key hash and system prompts."""
        body = (
            '{"error":"retry exhausted","tags":{"previous_models":'
            '[{"model":"claude-3","kwargs":{"api_base":"https://upstream"}}]}}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "litellm_internal_leak" in kinds

    def test_user_api_key_auth_bridge_leak_medium(self):
        """LiteLLM #20419: Chat/Responses bridge spread litellm_params
        (including UserAPIKeyAuth object) into upstream request body,
        which then came back in the upstream 400 error."""
        body = (
            '{"error":{"message":"upstream rejected extra field",'
            '"details":{"UserAPIKeyAuth":{"user_api_key_user_email":"a@b.com",'
            '"requester_ip_address":"10.0.0.1"}}}}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "litellm_internal_leak" in kinds

    def test_pii_echo_bedrock_guardrail_medium(self):
        """LiteLLM #12152: Bedrock SensitiveInformationPolicyConfig
        echoes detected PII (SSN, phone, name) back to the client in the
        error body verbatim."""
        body = (
            '{"error":"guardrail intervention",'
            '"bedrock_guardrail_response":{"assessments":[{'
            '"sensitiveInformationPolicy":{"piiEntities":['
            '{"type":"US_SOCIAL_SECURITY_NUMBER","match":"123-45-6789"}]}}]}}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "pii_echo" in kinds
        pii_hit = next(h for h in hits if h["kind"] == "pii_echo")
        assert pii_hit["severity"] == "medium"

    def test_clean_body_triggers_no_v15_1_categories(self):
        """A standard clean error must NOT trigger any of the v1.5.1
        marker categories."""
        body = (
            '{"error":{"message":"field messages is required",'
            '"type":"invalid_request_error","param":null,"code":null}}'
        )
        hits = scan_for_leaks(body, {}, API_KEY, "https://relay.example.com")
        kinds = {h["kind"] for h in hits}
        assert "litellm_internal_leak" not in kinds
        assert "pii_echo" not in kinds
        assert "google_key_url_param" not in kinds


# ---------------------------------------------------------------------------
# _build_triggers
# ---------------------------------------------------------------------------

class TestBuildTriggers:
    def test_default_has_seven_triggers(self):
        """v1.5: 5 original shape-based triggers + 2 new
        upstream/auth probes = 7 total in default mode."""
        triggers = _build_triggers(aggressive=False)
        assert len(triggers) == 7
        names = [t[0] for t in triggers]
        assert "oversized_context" not in names
        assert set(names) == {
            "malformed_json", "invalid_model", "wrong_content_type",
            "missing_messages", "unknown_endpoint",
            "force_upstream_error", "auth_probe",
        }

    def test_aggressive_adds_oversized(self):
        """v1.5: aggressive adds oversized_context, so 7 + 1 = 8."""
        triggers = _build_triggers(aggressive=True)
        assert len(triggers) == 8
        names = [t[0] for t in triggers]
        assert "oversized_context" in names

    def test_oversized_body_is_256kb(self):
        """Billing-risk probe must be ~256 KB, NOT 10 MB."""
        triggers = _build_triggers(aggressive=True)
        oversized = next(t for t in triggers if t[0] == "oversized_context")
        body = oversized[3]
        # 256 KB filler + JSON overhead ~100 bytes. Assert size window.
        assert 256 * 1024 <= len(body) <= 256 * 1024 + 500

    def test_trigger_shape(self):
        """v1.5: Every trigger is a 6-tuple
        (name, method, path, body, content_type, header_override)."""
        triggers = _build_triggers(aggressive=True)
        for t in triggers:
            assert len(t) == 6
            name, method, path, body, content_type, header_override = t
            assert isinstance(name, str)
            assert method == "POST"
            assert path.startswith("/v1/")
            assert isinstance(body, bytes)
            assert isinstance(content_type, str)
            assert header_override is None or isinstance(header_override, dict)

    def test_only_auth_probe_sets_header_override(self):
        """v1.5 regression: header_override must be None for every trigger
        EXCEPT auth_probe. Otherwise unexpected triggers could silently
        alter the Authorization header."""
        triggers = _build_triggers(aggressive=True)
        for t in triggers:
            name = t[0]
            header_override = t[5]
            if name == "auth_probe":
                assert header_override is not None
                assert "Authorization" in header_override
                assert "Bearer " in header_override["Authorization"]
                # Must use a distinctive fake value, not a real bearer shape
                # that could be mistaken for a real leak
                assert "fake" in header_override["Authorization"].lower()
            else:
                assert header_override is None, (
                    f"Trigger {name} unexpectedly has a header_override"
                )

    def test_force_upstream_error_uses_massive_max_tokens(self):
        """v1.5 regression: force_upstream_error must use a max_tokens value
        large enough to be rejected by every major upstream provider."""
        triggers = _build_triggers(aggressive=False)
        force = next(t for t in triggers if t[0] == "force_upstream_error")
        body = force[3]
        body_str = body.decode("utf-8")
        assert "99999999" in body_str
        # Sanity: must still be a valid JSON body
        parsed = json.loads(body_str)
        assert parsed["max_tokens"] == 99999999
        assert "messages" in parsed


# ---------------------------------------------------------------------------
# _highest_severity
# ---------------------------------------------------------------------------

class TestHighestSeverity:
    def test_empty(self):
        assert _highest_severity([]) == "none"

    def test_only_medium(self):
        assert _highest_severity([{"severity": "medium"}]) == "medium"

    def test_mix_picks_highest(self):
        hits = [
            {"severity": "medium"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        assert _highest_severity(hits) == "high"

    def test_critical_beats_all(self):
        hits = [
            {"severity": "medium"},
            {"severity": "high"},
            {"severity": "critical"},
            {"severity": "high"},
        ]
        assert _highest_severity(hits) == "critical"


# ---------------------------------------------------------------------------
# _redact_api_key
# ---------------------------------------------------------------------------

class TestRedactApiKey:
    def test_full_and_prefix_replaced(self):
        text = f"key={API_KEY} and prefix sk-test-"
        out = _redact_api_key(text, API_KEY)
        assert API_KEY not in out
        assert "sk-test-" not in out
        assert "<REDACTED_API_KEY>" in out
        assert "<REDACTED_PREFIX>" in out

    def test_empty_text(self):
        assert _redact_api_key("", API_KEY) == ""

    def test_empty_key(self):
        assert _redact_api_key("hello", "") == "hello"


# ---------------------------------------------------------------------------
# run_error_leakage_test
# ---------------------------------------------------------------------------

def _make_client(response_map=None, default=None, error=None, header_sink=None):
    """Build a MagicMock client whose ``raw_request`` returns per-trigger
    responses looked up by trigger name (parsed from the path+body).

    If ``header_sink`` is a dict, every raw_request call appends
    ``{trigger: headers_dict}`` into it so tests can assert on the
    Authorization value passed per-trigger (used by the auth_probe test)."""
    client = MagicMock()
    if default is None:
        default = make_raw_response(status=400, body='{"error":"bad"}')
    calls = {"count": 0}

    def raw(method, path, headers, body, content_type, timeout):
        calls["count"] += 1
        if error:
            return make_raw_response(status=0, error=error)
        # Figure out which trigger this is from the body+path combination
        if b"{not json" == body:
            name = "malformed_json"
        elif b'{"model":"claude-opus-4-6","max_tokens":10}' == body:
            name = "missing_messages"
        elif path == "/v1/nonexistent-route":
            name = "unknown_endpoint"
        elif content_type == "text/plain":
            name = "wrong_content_type"
        elif b"nonexistent-xyz-999" in body:
            name = "invalid_model"
        elif b"99999999" in body:
            name = "force_upstream_error"
        elif len(body) > 10000:
            name = "oversized_context"
        elif headers.get("Authorization", "").startswith("Bearer nothing-fake-token"):
            name = "auth_probe"
        else:
            name = "unknown"
        if header_sink is not None:
            header_sink[name] = dict(headers)
        if response_map is None:
            return default
        return response_map.get(name, default)

    client.raw_request.side_effect = raw
    client._call_count = calls
    return client


class TestRunErrorLeakageTest:
    def test_clean_relay_returns_none(self):
        """All probes return well-formed JSON error with no leaks."""
        client = _make_client(default=make_raw_response(
            status=400,
            body='{"error":{"type":"invalid_request_error","message":"bad"}}',
        ))
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "none"
        assert inconclusive is False
        assert len(results) == 7  # v1.5: 5 legacy + 2 new triggers
        for r in results:
            assert r["hits"] == []
            assert r["severity"] == "none"

    def test_full_echo_returns_critical(self):
        """Any probe that echoes the full API key -> CRITICAL overall."""
        body = f'{{"error":"received api_key={API_KEY}"}}'
        client = _make_client(default=make_raw_response(status=400, body=body))
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "critical"
        assert inconclusive is False

    def test_highest_severity_wins_on_mixed(self):
        """One probe yields HIGH, one MEDIUM -> overall HIGH."""
        rmap = {
            "malformed_json": make_raw_response(
                status=400,
                body='{"error":"upstream api.anthropic.com 502"}',
            ),
            "invalid_model": make_raw_response(
                status=500, body='Traceback (most recent call last):\n  ValueError',
            ),
        }
        client = _make_client(
            response_map=rmap,
            default=make_raw_response(status=400, body='{"error":"bad"}'),
        )
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "high"
        assert inconclusive is False

    def test_all_200_inconclusive(self):
        """Every probe got 200 -> relay silently swallowed everything ->
        inconclusive. Must NOT be reported as clean by the caller."""
        client = _make_client(default=make_raw_response(status=200, body="ok"))
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "none"
        assert inconclusive is True

    def test_all_connection_errors_inconclusive(self):
        client = _make_client(error="ConnectError: refused")
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "none"
        assert inconclusive is True
        # Every result has an error string and status 0
        assert all(r["error"] is not None for r in results)
        assert all(r["status"] == 0 for r in results)

    def test_single_critical_probe(self):
        """One probe CRITICAL, rest clean -> overall CRITICAL, not inconclusive."""
        rmap = {
            "malformed_json": make_raw_response(
                status=400,
                body=f'{{"echoed_key":"{API_KEY}"}}',
            ),
        }
        client = _make_client(
            response_map=rmap,
            default=make_raw_response(status=400, body='{"error":"bad"}'),
        )
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "critical"
        assert inconclusive is False

    def test_only_medium_stays_medium(self):
        """Only medium-severity hits -> overall MEDIUM."""
        client = _make_client(default=make_raw_response(
            status=500,
            body='File "/var/www/relay/app.py", line 10: crash',
        ))
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "medium"
        assert inconclusive is False

    def test_aggressive_flag_adds_probe(self):
        """v1.5: Aggressive=True -> 8 probes, default -> 7 probes."""
        client_default = _make_client(default=make_raw_response(
            status=400, body='{"error":"bad"}'))
        results_d, _, _ = run_error_leakage_test(
            client_default, API_KEY, "https://relay.example.com", aggressive=False,
        )
        client_agg = _make_client(default=make_raw_response(
            status=400, body='{"error":"bad"}'))
        results_a, _, _ = run_error_leakage_test(
            client_agg, API_KEY, "https://relay.example.com", aggressive=True,
        )
        assert len(results_d) == 7
        assert len(results_a) == 8
        names = {r["trigger"] for r in results_a}
        assert "oversized_context" in names
        # v1.5: new triggers should be present in both modes
        assert "force_upstream_error" in names
        assert "auth_probe" in names

    def test_api_key_redacted_in_body_preview(self):
        """body_preview field must never contain the raw api_key."""
        client = _make_client(default=make_raw_response(
            status=400,
            body=f'here is the key: {API_KEY} and more text ' * 10,
        ))
        results, _, _ = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        for r in results:
            assert API_KEY not in r["body_preview"]

    def test_body_preview_truncated_to_400(self):
        """Long bodies must be truncated in body_preview to keep reports small."""
        long_body = "x" * 5000
        client = _make_client(default=make_raw_response(
            status=500, body=long_body,
        ))
        results, _, _ = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        for r in results:
            assert len(r["body_preview"]) <= 400

    def test_some_errors_not_inconclusive(self):
        """Some probes 400 (scanned), some connection errors -> NOT inconclusive
        as long as at least one probe returned a real HTTP response and
        at least one did not cleanly succeed."""
        rmap = {
            "malformed_json": make_raw_response(
                status=400, body='{"error":"bad json"}',
            ),
            "invalid_model": make_raw_response(
                status=0, error="ConnectError",
            ),
        }
        client = _make_client(
            response_map=rmap,
            default=make_raw_response(status=422, body='{"error":"unprocessable"}'),
        )
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        assert severity == "none"
        assert inconclusive is False

    def test_auth_probe_sends_fake_bearer(self):
        """v1.5 regression: the auth_probe trigger must send the fake
        bearer header, NOT the real api_key, so we can detect echo.
        All other triggers must continue to send the real api_key."""
        header_sink = {}
        client = _make_client(
            default=make_raw_response(status=400, body='{"error":"bad"}'),
            header_sink=header_sink,
        )
        run_error_leakage_test(client, API_KEY, "https://relay.example.com")

        assert "auth_probe" in header_sink
        auth_probe_auth = header_sink["auth_probe"]["Authorization"]
        assert API_KEY not in auth_probe_auth
        assert "nothing-fake-token" in auth_probe_auth

        # Every OTHER trigger must have sent the real api_key in Bearer
        for name, headers in header_sink.items():
            if name == "auth_probe":
                continue
            assert headers["Authorization"] == f"Bearer {API_KEY}", (
                f"Trigger {name} did not send real api_key"
            )

    def test_auth_probe_echo_detected_as_bearer_token(self):
        """End-to-end: when the relay echoes the fake bearer back in a
        401 body, scan_for_leaks should emit a bearer_token regex hit
        (but NOT a critical full_api_key_echo since the fake bearer is
        not our real key)."""
        fake_bearer = "nothing-fake-token-xyz-999-auth-probe"
        rmap = {
            "auth_probe": make_raw_response(
                status=401,
                body=f'{{"error":"invalid auth: Bearer {fake_bearer}"}}',
            ),
        }
        client = _make_client(
            response_map=rmap,
            default=make_raw_response(status=400, body='{"error":"bad"}'),
        )
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        auth_result = next(r for r in results if r["trigger"] == "auth_probe")
        kinds = {h["kind"] for h in auth_result["hits"]}
        assert "bearer_token" in kinds
        assert "full_api_key_echo" not in kinds  # fake != real api_key
        assert severity == "high"

    def test_force_upstream_error_sends_huge_max_tokens(self):
        """v1.5 regression: force_upstream_error must be recognisable
        by the fake-mock _make_client via its max_tokens=99999999 body."""
        rmap = {
            "force_upstream_error": make_raw_response(
                status=400,
                body='{"error":"upstream rejected: api.anthropic.com returned 400"}',
            ),
        }
        client = _make_client(
            response_map=rmap,
            default=make_raw_response(status=400, body='{"error":"bad"}'),
        )
        results, severity, inconclusive = run_error_leakage_test(
            client, API_KEY, "https://relay.example.com",
        )
        force_result = next(r for r in results if r["trigger"] == "force_upstream_error")
        # The mocked upstream error body mentions api.anthropic.com, which
        # triggers the existing upstream_host literal check.
        kinds = {h["kind"] for h in force_result["hits"]}
        assert "upstream_host" in kinds
        assert severity == "high"
