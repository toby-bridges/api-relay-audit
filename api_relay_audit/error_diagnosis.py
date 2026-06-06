"""User-facing diagnosis helpers for relay/API errors.

This module turns terse transport or HTTP errors into a stable, reportable
explanation. It is intentionally informational: diagnoses help users fix
connectivity/configuration problems but do not change any detector verdict or
overall risk-matrix branch.
"""

import re


_HTTP_STATUS_RE = re.compile(r"\bHTTP\s+(\d{3})\b", re.IGNORECASE)


def _coerce_status(status):
    if status is None:
        return None
    try:
        value = int(status)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _status_from_error(error):
    match = _HTTP_STATUS_RE.search(str(error or ""))
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _diagnosis(category, summary, likely_cause, suggested_action):
    return {
        "category": category,
        "summary": summary,
        "likely_cause": likely_cause,
        "suggested_action": suggested_action,
    }


def diagnose_error(error=None, status=None):
    """Return a structured diagnosis for an HTTP/transport error.

    Args:
        error: Error string from ``APIClient.call()``, ``raw_request()``, or a
            stream transport failure.
        status: Optional numeric HTTP status. When present, it takes priority
            over status text parsed from ``error``.

    Returns:
        Dict with ``category``, ``summary``, ``likely_cause``, and
        ``suggested_action``. The function never raises and never treats an
        error as safe; it only explains the most likely operational cause.
    """
    text = str(error or "").strip()
    text_lower = text.lower()
    status_code = _coerce_status(status) or _status_from_error(text)

    if status_code == 400:
        return _diagnosis(
            "bad-request",
            "Request shape rejected by the relay.",
            "The selected API format, model name, message schema, or content-type may not match this relay.",
            "Verify the base URL, model id, and whether the relay expects Anthropic messages or OpenAI chat completions.",
        )
    if status_code == 401:
        return _diagnosis(
            "auth",
            "Authentication failed.",
            "The API key is invalid, expired, copied with extra whitespace, or not accepted by this relay.",
            "Check the key in the provider dashboard and retry with a freshly copied key.",
        )
    if status_code == 403:
        return _diagnosis(
            "permission",
            "The relay rejected an authenticated request.",
            "The account may lack model access, have billing/credit problems, or be blocked from this API format.",
            "Check account balance, model permissions, regional restrictions, and relay-side allowlists.",
        )
    if status_code == 404:
        return _diagnosis(
            "endpoint",
            "Endpoint not found.",
            "The base URL may be missing or duplicating a /v1 prefix, or the relay may not expose this route.",
            "Try the relay's documented base URL and avoid appending /messages or /chat/completions manually.",
        )
    if status_code == 408:
        return _diagnosis(
            "timeout",
            "The relay timed out the request.",
            "The relay or upstream provider did not answer before the HTTP timeout.",
            "Retry once, then increase --timeout or run with slower steps skipped to isolate the failing probe.",
        )
    if status_code == 413:
        return _diagnosis(
            "payload-too-large",
            "Request body is too large for the relay.",
            "The relay may enforce a smaller payload/context limit than the advertised model.",
            "Retry with --fast-context or --skip-context, then run the full context test only if the relay supports it.",
        )
    if status_code == 422:
        return _diagnosis(
            "unprocessable",
            "Request schema was understood but rejected.",
            "Common causes are unsupported system prompts, unsupported model ids, or a relay-specific schema restriction.",
            "Verify model access and whether this relay accepts custom system prompts for the selected format.",
        )
    if status_code == 429:
        return _diagnosis(
            "rate-limit",
            "Rate limit or quota was hit.",
            "The relay or upstream provider is throttling this key, account, or model.",
            "Wait and retry with --skip-context or a lower --latency-probe-count, or upgrade the relay/provider quota.",
        )
    if status_code in (500, 502, 503, 504):
        return _diagnosis(
            "upstream-or-relay",
            "Relay or upstream provider error.",
            "The relay backend, gateway, or upstream model provider failed while handling the request.",
            "Retry later; if it repeats, share the redacted report with the relay operator and inspect Step 9 for leakage.",
        )
    if status_code is not None and status_code >= 400:
        return _diagnosis(
            "http-error",
            f"HTTP {status_code} error from the relay.",
            "The relay returned a non-success status that is not mapped to a more specific diagnosis.",
            "Check the raw response, relay documentation, selected model, and account state.",
        )

    if "both formats failed" in text_lower:
        return _diagnosis(
            "format-detection",
            "Neither Anthropic nor OpenAI chat format produced a usable response.",
            "The base URL may be wrong, the key may be invalid, or the relay may require a different API family.",
            "Run a minimal vendor curl command from the relay docs, then retry with the documented base URL and model id.",
        )
    if "cors" in text_lower or "failed to fetch" in text_lower:
        return _diagnosis(
            "browser-cors",
            "Browser access was blocked before a normal API response was available.",
            "The relay likely does not allow browser-origin requests or hides responses from frontend JavaScript.",
            "Run the generated curl command in a terminal; terminal requests are not subject to browser CORS.",
        )
    if "ssl" in text_lower or "certificate" in text_lower or "tls" in text_lower:
        return _diagnosis(
            "tls",
            "TLS/SSL connection failed.",
            "The relay certificate may be self-signed, expired, misconfigured, or blocked by the local trust store.",
            "Retry once; the audit client may fall back to curl, but treat persistent TLS failures as operator-quality evidence.",
        )
    if "timed out" in text_lower or "timeout" in text_lower:
        return _diagnosis(
            "timeout",
            "Request timed out before a response was received.",
            "The relay, upstream model, or local network path is too slow for the current timeout.",
            "Retry with --timeout increased, or skip long-running probes to determine whether only one step is slow.",
        )
    if (
        "connecterror" in text_lower
        or "connection refused" in text_lower
        or "connection reset" in text_lower
        or "name or service not known" in text_lower
        or "nodename nor servname" in text_lower
        or "could not resolve" in text_lower
        or "temporary failure in name resolution" in text_lower
    ):
        return _diagnosis(
            "network",
            "Network connection to the relay failed.",
            "DNS, firewall, proxy, VPN, or relay availability may be preventing any HTTP response.",
            "Check the base URL in a browser or with curl -I, then retry from the same network path.",
        )
    if "expecting value" in text_lower or "jsondecodeerror" in text_lower:
        return _diagnosis(
            "non-json",
            "Relay returned a non-JSON response where API JSON was expected.",
            "The endpoint may be an HTML landing page, reverse-proxy error page, or non-API route.",
            "Check the base URL and inspect the raw response with curl before running the full audit.",
        )
    if "empty curl output" in text_lower or "no header/body separator" in text_lower:
        return _diagnosis(
            "curl-output",
            "curl did not receive a parseable HTTP response.",
            "The relay closed the connection, returned malformed output, or an intermediary stripped the response.",
            "Retry with curl -i against the same URL and inspect whether any HTTP status line is present.",
        )
    if "curl failed" in text_lower:
        return _diagnosis(
            "curl",
            "curl transport failed.",
            "The fallback transport could not complete the request, often due to network, TLS, DNS, or proxy issues.",
            "Run curl --version and a minimal curl request to the relay, then retry the audit.",
        )

    return _diagnosis(
        "unknown",
        "Unmapped relay/API error.",
        "The audit received an error string that does not match a known operational bucket.",
        "Inspect the raw error, verify the key/base URL/model, and include the redacted report when asking the relay operator.",
    )


def format_diagnosis(diagnosis):
    """Render a diagnosis dict as one compact Markdown line."""
    return (
        f"**Diagnosis**: {diagnosis['summary']} "
        f"Likely cause: {diagnosis['likely_cause']} "
        f"Next step: {diagnosis['suggested_action']}"
    )
