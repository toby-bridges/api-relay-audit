"""Error response header leakage test (AC-2 adjacent, Step 9).

Detects the most common AC-2 credential-exfiltration failure mode on free
relays: the relay proxies its own error output back to the client and that
error body (or response header) echoes the Authorization header we sent,
the first-8 prefix of the API key, an upstream provider URL, an
environment variable name, a filesystem path, or a stack trace.

Figure 3 of Liu et al., *Your Agent Is Mine*, arXiv:2604.08407, reports
credential abuse at 4.25% of 400 free routers -- more than twice as common
as code-injection rewrites (2%). This module is the client-side audit for
the error-body subclass of AC-2: if the relay leaks something we gave it
back to us inside an error response, it is almost certainly leaking to
other parties under other conditions.

The test fires six deterministic "break me" requests (malformed JSON,
invalid model, wrong content-type, missing messages field, unknown
endpoint, and an optional 256 KB oversized body), captures the full
response body and response headers via ``APIClient.raw_request``, and
scans for credential / PII indicators ordered by severity.

Reference: Liu, Shou, Wen, Chen, Fang, Feng,
"Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the
LLM Supply Chain", arXiv:2604.08407, figure 3 and section 4.2.
"""

import json
import re


# Upstream provider hostnames. If any of these appear in a relay's error
# response, the relay is exposing its internal plumbing -- which maps onto
# the attacker's credential-collection surface.
UPSTREAM_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "api.mistral.ai",
    "api.deepseek.com",
    "api.together.xyz",
    "api.groq.com",
)

# Environment variable names whose presence in an error body means the
# relay's error handler is dumping its own process environment. Any
# OPENAI_API_KEY / ANTHROPIC_API_KEY echo is a direct credential leak for
# OTHER users of the same relay, even if our own key is not echoed.
ENV_VAR_MARKERS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY",
    "MISTRAL_API_KEY",
    "API_KEY=",
    "SECRET_KEY=",
)

# Filesystem path prefixes that signal a server-side path leak. Captures
# both POSIX and Windows deployment layouts.
PATH_PREFIXES = (
    "/home/",
    "/root/",
    "/var/www/",
    "/var/lib/",
    "/app/",
    "/opt/",
    "/usr/local/",
    "C:\\Users\\",
    "C:\\ProgramData\\",
)

# Stack trace markers from common server-side languages. Any of these in
# an error body means the relay is propagating an unhandled exception all
# the way out to the client.
STACK_TRACE_MARKERS = (
    "Traceback (most recent call last)",
    'File "',
    "at <anonymous>",
    "at Object.",
    "at async ",
    "goroutine 1 [",
    "panic: ",
)

# LiteLLM internal field names that should NEVER appear in a client-facing
# error body. Their presence signals that the relay's router/proxy internals
# bled through an unsealed error path -- which, per the LiteLLM bug tracker,
# has historically dumped full deployment lists (with ``api_key`` values),
# retry kwargs, auth objects, or routed request metadata into error
# responses. Sources: LiteLLM issues #5762 (model_list leak), #13705 (retry
# OpenTelemetry kwargs dump), #20419 (Chat/Responses bridge litellm_params
# spread). See ``reference_litellm_secret_regex`` memory.
LITELLM_INTERNAL_MARKERS = (
    "user_api_key_user_email",
    "requester_ip_address",
    "UserAPIKeyAuth",
    "previous_models",
    "litellm_params",
    '"user_api_key"',  # quote-wrapped JSON key form to avoid prose FP
    '"model_list"',    # quote-wrapped JSON key form (LiteLLM #5762)
)

# PII echo markers from provider-side guardrails (e.g. AWS Bedrock
# ``SensitiveInformationPolicyConfig``). When these appear in a client-facing
# error body, the relay is echoing detected PII (SSN, phone, names) back to
# the client verbatim -- a distinct information-disclosure class from
# credential leakage. Source: LiteLLM issue #12152.
PII_ECHO_MARKERS = (
    '"piiEntities"',
    "sensitiveInformationPolicy",
)

# Secret shape patterns adapted from LiteLLM ``_logging.py`` (Apache-2.0,
# BerriAI/litellm, ``_build_secret_patterns()``). All patterns map to HIGH
# severity because they identify credential shapes at the byte level.
# Length floors (e.g. ``{20,}``) are tuned to minimise false positives on
# documentation snippets while still catching real leaked credentials in
# error responses. See the ``reference_litellm_secret_regex`` memory for
# the full rationale and attribution notes.
#
# ``google_key_url_param`` is a v1.5.1 addition motivated by LiteLLM issues
# #8075 and #15799: Gemini's httpx wrapper writes the full request URL
# (including the ``?key=AIza...`` query parameter) into ``HTTPStatusError``
# exception strings, which then propagate into proxy error responses.
SECRET_REGEX_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9\-_]{20,}"),                      "sk_prefix_secret"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),         "bearer_token"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),                   "aws_access_key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                      "google_api_key"),
    (re.compile(r"[?&]key=[A-Za-z0-9_\-]{25,}"),                "google_key_url_param"),
    (re.compile(r"ya29\.[A-Za-z0-9_.~+/\-]{20,}"),              "gcp_oauth_token"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"), "jwt_token"),
    (re.compile(
        r"-----BEGIN[A-Z \-]*PRIVATE KEY-----[\s\S]*?-----END[A-Z \-]*PRIVATE KEY-----"
    ),                                                           "pem_private_key"),
    (re.compile(r"(?<=://)[^\s'\"]*:[^\s'\"@]+(?=@)"),          "db_connstring_password"),
]


def _build_triggers(aggressive: bool):
    """Build the list of error-probe request specs.

    Each entry is
    ``(name, method, path, body_bytes, content_type, header_override)``.
    ``header_override``, when not ``None``, is a dict of headers that are
    merged on top of the default auth headers for that trigger.  It is
    used by ``auth_probe`` to inject a fake ``Authorization`` value so
    we can detect relays that echo the request auth header back in the
    response body.

    The ``aggressive`` flag gates the oversized-context probe (256 KB body),
    which may incur metered billing on pay-as-you-go relays.

    As of v1.5 (post-one-api reverse engineering, see the
    ``reference_one_api_error_paths`` memory), the default set has seven
    triggers — five legacy shape-based triggers plus two new
    upstream-forcing / auth-echo triggers that catch silent-passthrough
    relays which v1.0's triggers missed.
    """
    valid_body = json.dumps({
        "model": "claude-opus-4-6",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode("utf-8")

    triggers = [
        (
            "malformed_json",
            "POST", "/v1/messages",
            b"{not json",
            "application/json",
            None,
        ),
        (
            "invalid_model",
            "POST", "/v1/messages",
            json.dumps({
                "model": "nonexistent-xyz-999",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "hi"}],
            }).encode("utf-8"),
            "application/json",
            None,
        ),
        (
            "wrong_content_type",
            "POST", "/v1/messages",
            valid_body,
            "text/plain",
            None,
        ),
        (
            "missing_messages",
            "POST", "/v1/messages",
            b'{"model":"claude-opus-4-6","max_tokens":10}',
            "application/json",
            None,
        ),
        (
            "unknown_endpoint",
            "POST", "/v1/nonexistent-route",
            b"{}",
            "application/json",
            None,
        ),
        # NEW in v1.5: force upstream round-trip. one-api's validation.go:14
        # only checks non-empty, so nonexistent models silently pass through
        # to upstream. An absurd max_tokens value, however, is rejected by
        # the upstream provider (Anthropic/OpenAI), forcing one-api to echo
        # the upstream error body -- which may leak the provider URL, the
        # upstream error envelope, or internal channel configuration.
        (
            "force_upstream_error",
            "POST", "/v1/messages",
            json.dumps({
                "model": "claude-opus-4-6",
                "max_tokens": 99999999,
                "messages": [{"role": "user", "content": "hi"}],
            }).encode("utf-8"),
            "application/json",
            None,
        ),
        # NEW in v1.5: auth header echo probe. Sends a distinctive fake
        # bearer so that if the relay echoes the Authorization header value
        # into the response body or a response header on a 401, we can spot
        # it deterministically via the bearer_token regex in
        # SECRET_REGEX_PATTERNS.
        (
            "auth_probe",
            "POST", "/v1/messages",
            valid_body,
            "application/json",
            {"Authorization": "Bearer nothing-fake-token-xyz-999-auth-probe"},
        ),
    ]
    if aggressive:
        # 256 KB filler. NOT 10 MB -- billing risk on metered relays.
        filler = "A" * (256 * 1024)
        big_body = json.dumps({
            "model": "claude-opus-4-6",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": filler}],
        }).encode("utf-8")
        triggers.append((
            "oversized_context",
            "POST", "/v1/messages",
            big_body,
            "application/json",
            None,
        ))
    return triggers


def _redact_api_key(text: str, api_key: str) -> str:
    """Replace api_key occurrences with ``<REDACTED_API_KEY>``.

    Also redacts the first-8 prefix so report snippets do not accidentally
    leak partial credentials via truncation.
    """
    if not api_key or not text:
        return text
    text = text.replace(api_key, "<REDACTED_API_KEY>")
    if len(api_key) >= 8:
        text = text.replace(api_key[:8], "<REDACTED_PREFIX>")
    return text


def _mk_hit(severity: str, kind: str, snippet: str, where: str, api_key: str) -> dict:
    """Build a single hit dict with snippet redaction applied unconditionally.

    All snippets are redacted regardless of ``kind`` because a path or
    stack-trace hit may still contain the api_key somewhere in the 80-char
    context window.
    """
    return {
        "severity": severity,
        "kind": kind,
        "snippet": _redact_api_key(snippet, api_key),
        "where": where,
    }


def scan_for_leaks(body: str, response_headers: dict, api_key: str, base_url: str) -> list:
    """Scan the response body and response headers for credential leaks.

    Returns a list of leak-hit dicts. Each hit is a dict with keys:
        ``severity`` : ``"critical"`` / ``"high"`` / ``"medium"``
        ``kind``     : short label describing what was found
        ``snippet``  : redacted surrounding context (up to ~120 chars)
        ``where``    : ``"body"`` or ``"header: <name>"``

    Severity ordering:
        critical : full API key value appears verbatim
        high     : first-8 key prefix OR upstream provider host
                   OR environment variable name OR any LiteLLM-style
                   secret regex pattern (sk-, Bearer, AWS, Google, JWT,
                   PEM, DB connstring, ...)
        medium   : filesystem path OR stack trace marker

    The regex patterns are adapted from LiteLLM's ``_logging.py``
    (Apache-2.0, BerriAI/litellm) and add high-confidence credential-shape
    detection beyond the literal api_key substring check that v1 shipped
    with. To avoid double-counting the same credential when the api_key
    happens to match one of the regex patterns (e.g. an Anthropic key
    starts with ``sk-``), regex matches that overlap with an
    already-claimed literal span are skipped.

    The ``base_url`` argument is accepted for interface stability and
    future extensions; the current implementation does not use it.
    """
    del base_url  # reserved for future use (e.g. own-domain allowlist)
    hits = []
    targets = [("body", body or "")]
    if response_headers:
        for k, v in response_headers.items():
            targets.append((f"header: {k}", str(v)))

    first8 = api_key[:8] if api_key and len(api_key) >= 8 else ""

    for where, text in targets:
        if not text:
            continue
        text_lower = text.lower()

        # Track (start, end) spans of literal api_key / first8 hits on this
        # target so the regex patterns below cannot double-count the same
        # credential.
        claimed_spans = []

        # CRITICAL: full api key echo
        if api_key and api_key in text:
            idx = text.index(api_key)
            claimed_spans.append((idx, idx + len(api_key)))
            raw = text[max(0, idx - 40):idx + len(api_key) + 40]
            hits.append(_mk_hit("critical", "full_api_key_echo", raw, where, api_key))
            # A critical hit supersedes the partial-prefix hit on the same
            # target, but upstream / env / path / stack trace checks below
            # are orthogonal and still run.
        elif first8 and first8 in text:
            # HIGH: first-8 prefix (only if we did not already hit CRITICAL)
            idx = text.index(first8)
            claimed_spans.append((idx, idx + len(first8)))
            raw = text[max(0, idx - 40):idx + len(first8) + 40]
            hits.append(_mk_hit("high", "api_key_prefix", raw, where, api_key))

        # HIGH: secret shape regex patterns (LiteLLM port)
        for pattern, kind in SECRET_REGEX_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            start, end = m.start(), m.end()
            # Skip if the regex match overlaps a literal span already claimed
            # by the api_key / first8 check above.
            if any(start < ce and end > cs for cs, ce in claimed_spans):
                continue
            raw = text[max(0, start - 20):min(len(text), end + 20)]
            hits.append(_mk_hit("high", kind, raw, where, api_key))

        # HIGH: upstream provider host
        for host in UPSTREAM_HOSTS:
            if host in text_lower:
                idx = text_lower.index(host)
                raw = text[max(0, idx - 30):idx + len(host) + 30]
                hits.append(_mk_hit("high", "upstream_host", raw, where, api_key))
                break

        # HIGH: environment variable name
        for env in ENV_VAR_MARKERS:
            if env in text:
                idx = text.index(env)
                raw = text[max(0, idx - 20):idx + len(env) + 40]
                hits.append(_mk_hit("high", "env_var", raw, where, api_key))
                break

        # MEDIUM: filesystem path
        for prefix in PATH_PREFIXES:
            if prefix in text:
                idx = text.index(prefix)
                raw = text[max(0, idx):idx + 80]
                hits.append(_mk_hit("medium", "fs_path", raw, where, api_key))
                break

        # MEDIUM: stack trace marker
        for marker in STACK_TRACE_MARKERS:
            if marker in text:
                idx = text.index(marker)
                raw = text[max(0, idx):idx + 120]
                hits.append(_mk_hit("medium", "stack_trace", raw, where, api_key))
                break

        # MEDIUM: LiteLLM internal field leak (v1.5.1, sourced from
        # LiteLLM issues #5762 / #13705 / #20419)
        for marker in LITELLM_INTERNAL_MARKERS:
            if marker in text:
                idx = text.index(marker)
                raw = text[max(0, idx - 20):idx + len(marker) + 60]
                hits.append(_mk_hit("medium", "litellm_internal_leak", raw, where, api_key))
                break

        # MEDIUM: provider-side guardrail PII echo (v1.5.1, sourced from
        # LiteLLM issue #12152)
        for marker in PII_ECHO_MARKERS:
            if marker in text:
                idx = text.index(marker)
                raw = text[max(0, idx):idx + 120]
                hits.append(_mk_hit("medium", "pii_echo", raw, where, api_key))
                break

    return hits


def _highest_severity(hits: list) -> str:
    """Return the highest severity present in a list of leak hits."""
    if not hits:
        return "none"
    order = ("critical", "high", "medium")
    for level in order:
        if any(h["severity"] == level for h in hits):
            return level
    return "none"


def run_error_leakage_test(client, api_key: str, base_url: str, aggressive: bool = False):
    """Run all error-leakage probes against the client.

    Returns ``(results, severity, inconclusive)`` where:

    - ``results`` is a list of per-trigger dicts with keys ``trigger``,
      ``status``, ``error``, ``hits``, ``severity``, ``body_preview``.
    - ``severity`` is the highest overall severity in
      ``{"none", "medium", "high", "critical"}``.
    - ``inconclusive`` is ``True`` iff **every** probe returned HTTP 200
      (no error surface was elicited) OR every probe failed with a
      transport error (the relay is offline / unreachable).

    Inconclusive runs must NOT be treated as clean by the caller's risk
    matrix: a relay that silently swallows malformed JSON into HTTP 200
    is itself suspicious, and a relay that refuses to accept raw_request
    transport at all cannot be audited for AC-2 leakage.
    """
    triggers = _build_triggers(aggressive)

    # Send both auth styles so a relay in either Anthropic or OpenAI mode
    # is tested uniformly. If the relay echoes either header value back to
    # us, that is the leak we are hunting.
    default_auth_headers = {
        "x-api-key": api_key,
        "Authorization": f"Bearer {api_key}",
        "anthropic-version": "2023-06-01",
    }

    results = []
    for name, method, path, body, content_type, header_override in triggers:
        # Apply per-trigger header override if present. This is how
        # auth_probe replaces the real Authorization header with a fake
        # bearer value to test for response-side header echo.
        if header_override:
            auth_headers = {**default_auth_headers, **header_override}
        else:
            auth_headers = default_auth_headers
        r = client.raw_request(
            method=method,
            path=path,
            headers=auth_headers,
            body=body,
            content_type=content_type,
            timeout=30,
        )
        status = r.get("status", 0)
        body_text = r.get("body", "") or ""
        resp_headers = r.get("headers", {}) or {}
        error = r.get("error")

        # Only scan the response when we got a real HTTP answer (non-zero
        # status, no transport error). A connection failure has nothing
        # to scan and should not be counted against the relay.
        hits = []
        if error is None and status != 0:
            hits = scan_for_leaks(body_text, resp_headers, api_key, base_url)

        severity = _highest_severity(hits)
        preview = _redact_api_key(body_text[:400], api_key)

        results.append({
            "trigger": name,
            "status": status,
            "error": error,
            "hits": hits,
            "severity": severity,
            "body_preview": preview,
        })

    all_hits = [h for r in results for h in r["hits"]]
    overall_severity = _highest_severity(all_hits)

    all_200 = all(r["status"] == 200 for r in results)
    all_errors = all(
        r["error"] is not None or r["status"] == 0 for r in results
    )
    inconclusive = all_200 or all_errors

    return results, overall_severity, inconclusive
