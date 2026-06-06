"""Fast API relay connectivity checks.

This module is intentionally narrower than the full audit. It sends one
low-token Anthropic-style chat request and one low-token OpenAI-chat request,
then reports whether either format is usable. It does not make security
claims or feed the audit risk matrix.
"""

import json
import shlex
import time
from dataclasses import dataclass


CONNECTIVITY_PROMPT = "Reply with the single word: ok"
CONNECTIVITY_MAX_TOKENS = 8


@dataclass
class ConnectivityProbeResult:
    """Result of one connectivity probe."""

    format_name: str
    endpoint: str
    auth_style: str
    status: int
    elapsed_seconds: float
    input_tokens: int | None
    output_tokens: int | None
    text_preview: str
    diagnostic: str
    success: bool


def _redact(text: str, api_key: str) -> str:
    if not text:
        return ""
    if api_key:
        text = text.replace(api_key, "[redacted-api-key]")
    return text


def _markdown_escape(text: str) -> str:
    text = _redact(str(text), "")
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
        .strip()
    )


def _text_from_content(content) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for block in content:
        if isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _parse_anthropic_response(data: dict) -> tuple[str, int | None, int | None]:
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    return (
        _text_from_content(data.get("content")),
        usage.get("input_tokens") if isinstance(usage.get("input_tokens"), int) else None,
        usage.get("output_tokens") if isinstance(usage.get("output_tokens"), int) else None,
    )


def _parse_openai_response(data: dict) -> tuple[str, int | None, int | None]:
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    choices = data.get("choices", []) if isinstance(data, dict) else []
    first_choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = first_choice.get("message", {})
    text = ""
    if isinstance(message, dict):
        text = _text_from_content(message.get("content"))
    if not text:
        text = _text_from_content(first_choice.get("text"))
    return (
        text,
        usage.get("prompt_tokens") if isinstance(usage.get("prompt_tokens"), int) else None,
        usage.get("completion_tokens") if isinstance(usage.get("completion_tokens"), int) else None,
    )


def _headers_summary(headers: dict) -> str:
    if not headers:
        return "no response headers"
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    parts = []
    content_type = lowered.get("content-type")
    if content_type:
        parts.append(f"content-type {content_type.split(';', 1)[0]}")
    request_headers = [
        name for name in ("request-id", "x-request-id", "x-openai-request-id")
        if name in lowered
    ]
    if request_headers:
        parts.append("request id present")
    return ", ".join(parts) if parts else f"{len(headers)} response headers"


def _status_diagnostic(status: int, error: str | None) -> str:
    if status == 0:
        return f"Transport failure: {error or 'request did not complete'}"
    if status in (401, 403):
        return "Authentication or authorization failed; check key, model access, balance, and auth style."
    if status == 404:
        return "Endpoint not found; check the base URL and whether this relay supports the format."
    if status == 429:
        return "Rate limited or quota exhausted; check relay quota or retry later."
    if status == 400:
        return "Bad request; the relay may not support this format or model."
    if status >= 500:
        return "Relay or upstream server error."
    if 200 <= status < 300:
        return "HTTP 2xx received but no usable text was parsed."
    return f"HTTP {status} received; inspect relay configuration and model access."


def _probe(client, format_name: str, endpoint: str, auth_style: str,
           headers: dict, body: dict, parser) -> ConnectivityProbeResult:
    start = time.time()
    response = client.raw_request(
        "POST",
        endpoint,
        headers,
        json.dumps(body).encode("utf-8"),
        content_type="application/json",
        timeout=client.timeout,
    )
    elapsed = time.time() - start
    status = int(response.get("status", 0) or 0)
    response_error = _redact(str(response.get("error") or ""), client.api_key)
    diagnostic = _status_diagnostic(status, response_error)
    text = ""
    input_tokens = None
    output_tokens = None
    success = False

    if 200 <= status < 300:
        try:
            data = json.loads(response.get("body") or "")
        except json.JSONDecodeError:
            diagnostic = "HTTP 2xx received but response was not valid JSON."
        else:
            text, input_tokens, output_tokens = parser(data)
            text = _redact(text.strip(), client.api_key)
            if text:
                success = True
                diagnostic = f"OK: parsed non-empty text; {_headers_summary(response.get('headers', {}))}."
            else:
                diagnostic = "HTTP 2xx received but response JSON did not contain parsed text."

    return ConnectivityProbeResult(
        format_name=format_name,
        endpoint=endpoint,
        auth_style=auth_style,
        status=status,
        elapsed_seconds=elapsed,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        text_preview=text[:80],
        diagnostic=_redact(diagnostic, client.api_key),
        success=success,
    )


def _render_token_count(value: int | None) -> str:
    return str(value) if isinstance(value, int) else "-"


def _render_status(status: int) -> str:
    return str(status) if status else "transport"


def _next_step(verdict: str, client) -> str:
    url = shlex.quote(client.base_url)
    model = shlex.quote(client.model)
    if verdict in ("OK", "WARNING"):
        return (
            "Connectivity reached at least one chat format. For the full security audit, run:\n\n"
            "```bash\n"
            "export API_RELAY_AUDIT_KEY=sk-...\n"
            f"python3 audit.py --key \"$API_RELAY_AUDIT_KEY\" --url {url} --model {model} --output report.md\n"
            "```"
        )
    return (
        "Connectivity failed for both chat formats. Check the base URL, API key, "
        "model name, relay balance/quota, and whether the relay supports Anthropic "
        "or OpenAI Chat endpoints before running the full audit."
    )


def render_connectivity_report(result: dict) -> str:
    """Render a human-readable connectivity report."""
    client = result["client"]
    verdict = result["verdict"]
    lines = [
        "# API Relay Connectivity Report",
        "",
        f"**Target**: `{client.base_url}`",
        f"**Model**: `{client.model}`",
        f"**Timeout**: `{client.timeout}s`",
        f"**Connectivity Verdict**: **{verdict}**",
        "",
        "This is a quick connectivity check, not a security audit. It does not produce a LOW/MEDIUM/HIGH risk rating.",
        "",
        "## Probe Results",
        "",
        "| Format | Endpoint | Auth style | HTTP status | Elapsed | Tokens | Text preview | Diagnostic |",
        "|---|---|---|---:|---:|---:|---|---|",
    ]
    for probe in result["probes"]:
        tokens = (
            f"{_render_token_count(probe.input_tokens)}/"
            f"{_render_token_count(probe.output_tokens)}"
        )
        lines.append(
            "| "
            f"{_markdown_escape(probe.format_name)} | "
            f"`{_markdown_escape(probe.endpoint)}` | "
            f"{_markdown_escape(probe.auth_style)} | "
            f"{_render_status(probe.status)} | "
            f"{probe.elapsed_seconds:.3f}s | "
            f"{tokens} | "
            f"{_markdown_escape(probe.text_preview) or '-'} | "
            f"{_markdown_escape(probe.diagnostic)} |"
        )
    lines.extend([
        "",
        "## Next Step",
        "",
        _next_step(verdict, client),
        "",
    ])
    return "\n".join(lines)


def run_connectivity_check(client) -> dict:
    """Run fixed Anthropic and OpenAI Chat connectivity probes."""
    common_messages = [{"role": "user", "content": CONNECTIVITY_PROMPT}]
    probes = [
        _probe(
            client,
            "Anthropic Chat",
            "/v1/messages",
            "x-api-key",
            {
                "x-api-key": client.api_key,
                "anthropic-version": "2023-06-01",
            },
            {
                "model": client.model,
                "max_tokens": CONNECTIVITY_MAX_TOKENS,
                "messages": common_messages,
            },
            _parse_anthropic_response,
        ),
        _probe(
            client,
            "OpenAI Chat",
            "/v1/chat/completions",
            "Authorization: Bearer",
            {
                "Authorization": f"Bearer {client.api_key}",
            },
            {
                "model": client.model,
                "max_tokens": CONNECTIVITY_MAX_TOKENS,
                "messages": common_messages,
            },
            _parse_openai_response,
        ),
    ]
    success_count = sum(1 for probe in probes if probe.success)
    if success_count == len(probes):
        verdict = "OK"
    elif success_count:
        verdict = "WARNING"
    else:
        verdict = "FAILED"
    result = {
        "client": client,
        "probes": probes,
        "verdict": verdict,
        "success": success_count > 0,
        "successful_formats": [probe.format_name for probe in probes if probe.success],
    }
    result["markdown"] = render_connectivity_report(result)
    return result
