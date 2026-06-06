"""Tests for user-facing relay/API error diagnosis helpers."""

from api_relay_audit.error_diagnosis import diagnose_error, format_diagnosis


class TestDiagnoseError:
    def test_401_auth_failure(self):
        diagnosis = diagnose_error("HTTP 401: invalid api key")
        assert diagnosis["category"] == "auth"
        assert "Authentication failed" in diagnosis["summary"]
        assert "freshly copied key" in diagnosis["suggested_action"]

    def test_422_schema_rejection(self):
        diagnosis = diagnose_error("HTTP 422: unsupported system")
        assert diagnosis["category"] == "unprocessable"
        assert "unsupported system prompts" in diagnosis["likely_cause"]

    def test_429_rate_limit(self):
        diagnosis = diagnose_error("HTTP 429: too many requests")
        assert diagnosis["category"] == "rate-limit"
        assert "--latency-probe-count" in diagnosis["suggested_action"]

    def test_status_argument_takes_priority(self):
        diagnosis = diagnose_error("upstream body did not include status", status=403)
        assert diagnosis["category"] == "permission"

    def test_both_formats_failed(self):
        diagnosis = diagnose_error("Both formats failed")
        assert diagnosis["category"] == "format-detection"
        assert "Anthropic nor OpenAI" in diagnosis["summary"]

    def test_browser_cors(self):
        diagnosis = diagnose_error("TypeError: Failed to fetch because of CORS")
        assert diagnosis["category"] == "browser-cors"
        assert "terminal" in diagnosis["suggested_action"].lower()

    def test_network_connect_error(self):
        diagnosis = diagnose_error("ConnectError: connection refused")
        assert diagnosis["category"] == "network"

    def test_non_json_error(self):
        diagnosis = diagnose_error("Expecting value: line 1 column 1 (char 0)")
        assert diagnosis["category"] == "non-json"

    def test_format_diagnosis_markdown(self):
        rendered = format_diagnosis(diagnose_error("HTTP 404: missing"))
        assert rendered.startswith("**Diagnosis**:")
        assert "Endpoint not found" in rendered
        assert "Next step:" in rendered
