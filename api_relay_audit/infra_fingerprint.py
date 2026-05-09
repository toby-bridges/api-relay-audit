"""Infrastructure fingerprinting (Step 12, v1.8).

Identifies the relay-framework family (one-api / new-api / lobechat /
nginx / caddy / cloudflare ...) from response headers and response
bodies. Pure passive detection -- no fraud inference in v1.8; the
finding is informational and does NOT feed into the 6D risk matrix.

Rationale: Zhang et al., *Real Money, Fake Models: Deceptive Model
Claims in Shadow APIs*, arXiv:2603.01919, Section 3.2 Infrastructure
reports that 11 of 17 identified shadow APIs are built on OneAPI
and its derivative NewAPI open-source backbones. Knowing the framework lets the user (a) assess the
operator's professionalism, (b) cross-reference known framework-level
CVEs, and (c) distinguish first-party relays from plain reverse
proxies. Paired with Step 13 Latency Variance, this section forms
v1.8's "Infrastructure Audit Layer".

Detection surface:
    - ``GET /``                          -- landing page (often HTML)
    - ``GET /v1/models``                 -- 401/200 body, auth-header
                                           echo, ``x-powered-by``
    - ``GET /nonexistent-abc12345xyz``   -- 404 envelope

Signals are matched against a small hand-curated list of
framework-specific substrings in headers and body text. A framework
is "confirmed" if it fires in >=2 of 3 probes, "tentative" if 1 of 3,
and "unknown" if 0 of 3.
"""

from collections import Counter


# ----------------------------------------------------------------------
# Framework signature database
# ----------------------------------------------------------------------
#
# Each entry is ``(framework_name, signals)`` where ``signals`` is a
# list of ``(source, needle)`` tuples:
#
#   source = "body"           -> substring match against response body
#   source = "header:<name>"  -> substring match against that header's
#                                value. If ``needle`` is the empty
#                                string, the header's PRESENCE alone is
#                                the signal.
#
# Needles are compared case-insensitively. Order matters: the first
# framework whose signals fire wins, so list specific frameworks
# (new-api, one-api) before generic ones (nginx, caddy).
FRAMEWORK_SIGNATURES = [
    # LiteLLM: BerriAI/litellm proxy layer. Injects x-litellm-* on every
    # response including unauthenticated 401s. Header-prefix detection is
    # deterministic (1.0 confidence), concept from LLMprobe-engine
    # channel-signature.ts (clean-room reimplementation).
    ("litellm", [
        ("header_prefix:x-litellm-", ""),
    ]),
    # Helicone: Helicone.ai observability proxy. Injects helicone-* on
    # every response.
    ("helicone", [
        ("header_prefix:helicone-", ""),
    ]),
    # Portkey: Portkey.ai API gateway. Injects x-portkey-* on every
    # response.
    ("portkey", [
        ("header_prefix:x-portkey-", ""),
    ]),
    # Kong Gateway: Kong Inc. API gateway. Injects x-kong-* on every
    # response.
    ("kong-gateway", [
        ("header_prefix:x-kong-", ""),
    ]),
    # Alibaba DashScope: Alibaba Cloud model API gateway. Injects
    # x-dashscope-* on every response.
    ("alibaba-dashscope", [
        ("header_prefix:x-dashscope-", ""),
    ]),
    # Azure AI Foundry: Azure API Management layer. apim-request-id is
    # present on every response routed through Azure APIM.
    ("azure-foundry", [
        ("header:apim-request-id", ""),
    ]),
    # New API: song-quan-peng/one-api hard fork by Calcium-Ion.
    # Keeps most upstream shapes but rebrands landing page + about.
    ("new-api", [
        ("body", "new api"),
        ("body", "calcium-ion/new-api"),
        ("body", "new-api"),
        ("header:x-powered-by", "new-api"),
    ]),
    # One API: song-quanpeng/one-api. Upstream of new-api and numerous
    # private forks. 58k+ GitHub stars; the single most-used shadow
    # API backbone per arXiv:2603.01919.
    ("one-api", [
        ("body", "one api"),
        ("body", "songquanpeng/one-api"),
        ("body", "oneapi"),
        ("header:x-powered-by", "one-api"),
    ]),
    # LobeChat relay mode. Usually exposes ``/v1`` proxy endpoints
    # plus a Next.js chat UI at ``/``.
    # v1.8.1 Codex review #4 fix: the ``x-powered-by: next.js`` header
    # was removed as a standalone signal because every Vercel site and
    # unrelated Next.js frontend emits it, producing confident
    # lobechat-relay classifications on clearly unrelated operators.
    # LobeChat branding in the HTML body is the real fingerprint.
    ("lobechat-relay", [
        ("body", "lobechat"),
        ("body", "lobe-chat"),
    ]),
    # FastGPT. Commonly deployed alongside one-api as a UI layer.
    ("fastgpt", [
        ("body", "fastgpt"),
        ("body", "labring/fastgpt"),
    ]),
    # Cloudflare AI Gateway. Strong signal: ``cf-ray`` is present on
    # every response from behind Cloudflare.
    ("cloudflare", [
        ("header:cf-ray", ""),
        ("header:server", "cloudflare"),
    ]),
    # Raw nginx. No relay-specific branding; the operator just put a
    # thin proxy in front of an upstream provider. Still informative:
    # distinguishes "homemade" from "framework-based" relays.
    ("nginx-raw", [
        ("header:server", "nginx/"),
    ]),
    # Caddy. Same category as raw nginx.
    ("caddy-raw", [
        ("header:server", "caddy"),
    ]),
]


# Headers that are always informative for operator profiling,
# regardless of whether a framework was identified. These get
# pulled out and shown in the report even for "unknown" classifications.
INFORMATIVE_HEADERS = (
    "server",
    "x-powered-by",
    "via",
    "cf-ray",
    "x-served-by",
    "x-cache",
    "x-request-id",
    "x-frame-options",
    "x-litellm-version",
    "helicone-id",
    "x-portkey-request-id",
    "apim-request-id",
)


# Body scan cap. Relay landing pages can be megabytes of HTML; we only
# need enough to catch framework branding which is always near the top.
_BODY_SCAN_LIMIT = 8192


def _match_signal(signal, headers_lower, body_lower):
    """Return True if the ``(source, needle)`` signal fires."""
    source, needle = signal
    needle_lower = needle.lower()
    if source == "body":
        return needle_lower in body_lower
    if source.startswith("header:"):
        header_name = source.split(":", 1)[1].lower()
        if needle_lower == "":
            return header_name in headers_lower
        value = headers_lower.get(header_name, "")
        return needle_lower in value.lower()
    if source.startswith("header_prefix:"):
        prefix = source.split(":", 1)[1].lower()
        return any(k.startswith(prefix) for k in headers_lower)
    return False


def classify_framework(headers, body):
    """Classify a single response into ``(framework_name, matched_signals)``.

    Returns ``(None, [])`` if no framework matched. The first framework
    (in declaration order) whose signals fire wins.
    """
    if headers is None:
        headers = {}
    if body is None:
        body = ""
    headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
    body_lower = body[:_BODY_SCAN_LIMIT].lower()

    for framework, signals in FRAMEWORK_SIGNATURES:
        hits = [s for s in signals if _match_signal(s, headers_lower, body_lower)]
        if hits:
            return framework, hits
    return None, []


def extract_informative_headers(headers):
    """Return the subset of headers in ``INFORMATIVE_HEADERS`` (case-
    insensitive), preserving the original header-name casing for
    readability."""
    if not headers:
        return {}
    out = {}
    for k, v in headers.items():
        if str(k).lower() in INFORMATIVE_HEADERS:
            out[str(k)] = str(v)
    return out


def aggregate_framework(results):
    """Pick the single most-confident framework across all probe results.

    Rule: majority vote. If the same framework fires in >=2 probes, it
    is "confirmed". If it fires in exactly 1, "tentative". If no
    framework fired at all, "unknown".

    Returns ``(framework_name or None, confidence)`` where confidence
    is one of ``"confirmed"``, ``"tentative"``, or ``"unknown"``.
    """
    frameworks = [r["framework"] for r in results if r.get("framework")]
    if not frameworks:
        return None, "unknown"
    counts = Counter(frameworks)
    top, n = counts.most_common(1)[0]
    confidence = "confirmed" if n >= 2 else "tentative"
    return top, confidence


def run_infra_fingerprint(client):
    """Fire the 3 infrastructure probes and return per-probe results.

    Each probe is a ``raw_request`` with no auth headers. Some relays
    reject unauthenticated ``/v1/models``; the rejection body is still
    useful as a fingerprint source.

    Returns a list of dicts with keys:
        ``probe``        -- short name
        ``path``         -- URL path
        ``status``       -- HTTP status (0 on transport error)
        ``error``        -- transport error message or None
        ``framework``    -- matched framework name or None
        ``signals``      -- list of matched ``(source, needle)`` tuples
        ``headers``      -- extracted informative headers (subset)
        ``body_preview`` -- first 200 chars of response body
    """
    probes = [
        ("landing", "GET", "/"),
        ("models", "GET", "/v1/models"),
        ("notfound", "GET", "/nonexistent-abc12345xyz"),
    ]

    results = []
    for name, method, path in probes:
        r = client.raw_request(
            method=method,
            path=path,
            headers={},
            body=b"",
            content_type="application/json",
            timeout=15,
        )
        status = r.get("status", 0)
        headers = r.get("headers", {}) or {}
        body = r.get("body", "") or ""
        error = r.get("error")

        framework, signals = classify_framework(headers, body)
        info_headers = extract_informative_headers(headers)

        results.append({
            "probe": name,
            "path": path,
            "status": status,
            "error": error,
            "framework": framework,
            "signals": signals,
            "headers": info_headers,
            "body_preview": body[:200],
        })
    return results
