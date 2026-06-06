"""
Shared API client with auto-detection (Anthropic / OpenAI) and curl fallback.

Eliminates duplicated API calling logic across scripts.
"""

import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone

import httpx

from api_relay_audit import _transport
from api_relay_audit.error_diagnosis import diagnose_error
from api_relay_audit.stream_integrity import StreamSignals


def _extract_anthropic_text(content) -> str:
    """Concatenate text from every text block in an Anthropic ``content`` array.

    Anthropic responses may lead with a ``thinking`` or ``tool_use`` block
    when extended thinking or tool use is enabled. The old ``content[0].text``
    shortcut returned ``""`` in those cases, which then cascaded into auto-
    detection flipping to the OpenAI probe and every downstream text-based
    step (token injection, identity, jailbreak, prompt extraction, tool
    substitution) seeing an empty response and silently reporting clean.
    """
    if not isinstance(content, list):
        return ""
    parts = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype is not None and btype != "text":
            continue
        text = block.get("text")
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)


def _parse_curl_i_output(output: str) -> dict:
    """Parse ``curl -i`` (or ``curl -sk -i``) stdout into a response dict.

    Handles HTTP/1.x and HTTP/2 status lines and normalises ``\\r\\n`` line
    endings. A leading ``HTTP/X 100 Continue`` preface is skipped so the
    final status is surfaced.

    Returns ``{"status": int, "headers": dict, "body": str, "error": str|None}``
    where ``status == 0`` indicates a parse failure (``error`` set to a
    short diagnostic string).
    """
    if not output:
        return {"status": 0, "headers": {}, "body": "", "error": "empty curl output"}

    # Normalise line endings so the \n\n separator is reliable.
    text = output.replace("\r\n", "\n")

    # Split into header block / body on the first blank line.
    sep_idx = text.find("\n\n")
    if sep_idx == -1:
        return {"status": 0, "headers": {}, "body": text, "error": "no header/body separator"}
    headers_block = text[:sep_idx]
    body_block = text[sep_idx + 2:]

    # Skip any ``HTTP/X 100 Continue`` preface followed by its own blank line.
    while headers_block.split("\n", 1)[0].find(" 100 ") != -1:
        next_sep = body_block.find("\n\n")
        if next_sep == -1:
            return {"status": 0, "headers": {}, "body": body_block,
                    "error": "unterminated 100 Continue preface"}
        headers_block = body_block[:next_sep]
        body_block = body_block[next_sep + 2:]

    lines = headers_block.split("\n")
    status_line = lines[0] if lines else ""
    # "HTTP/1.1 404 Not Found" or "HTTP/2 404"
    parts = status_line.split(" ", 2)
    status = 0
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    return {
        "status": status,
        "headers": headers,
        "body": body_block,
        "error": None,
    }


def _populate_stream_signals(event: dict, signals: StreamSignals) -> None:
    """Dispatch a single parsed SSE event dict into a StreamSignals.

    Mutates ``signals`` in place. Never raises — malformed fields
    are silently ignored so a broken event anywhere in the stream
    does not abort the rest of the parse.

    This helper lives at module scope (rather than on ``APIClient``)
    so it can be unit-tested without instantiating a client or
    touching the network.
    """
    signals.raw_event_count += 1
    event_type = event.get("type", "")
    if isinstance(event_type, str) and event_type:
        signals.event_types.append(event_type)

    if event_type == "message_start":
        signals.has_message_start = True
        message = event.get("message", {})
        if isinstance(message, dict):
            model_name = message.get("model")
            if isinstance(model_name, str):
                signals.message_start_model = model_name
            usage = message.get("usage", {})
            if isinstance(usage, dict):
                input_tokens = usage.get("input_tokens")
                if isinstance(input_tokens, int):
                    signals.input_tokens = input_tokens

    elif event_type == "content_block_start":
        signals.has_content_block_start = True
        block = event.get("content_block", {})
        if isinstance(block, dict):
            block_type = block.get("type", "")
            if isinstance(block_type, str) and block_type:
                signals.content_block_types.append(block_type)
            if block.get("type") == "thinking":
                signals.thinking_start_seen = True

    elif event_type == "content_block_delta":
        signals.has_content_block_delta = True
        delta = event.get("delta", {})
        if isinstance(delta, dict):
            delta_type = delta.get("type")
            if isinstance(delta_type, str) and delta_type:
                signals.delta_types.append(delta_type)

            if delta_type == "text_delta":
                signals.has_text_delta = True
            elif delta_type == "thinking_delta":
                signals.thinking_delta_seen = True
            elif delta_type == "signature_delta":
                signature = delta.get("signature")
                if isinstance(signature, str) and not signature.strip():
                    signals.empty_signature_delta_count += 1

    elif event_type == "message_delta":
        signals.has_message_delta = True
        usage = event.get("usage", {})
        if isinstance(usage, dict):
            input_tokens = usage.get("input_tokens")
            if isinstance(input_tokens, int):
                signals.message_delta_input_tokens_samples.append(input_tokens)
            output_tokens = usage.get("output_tokens")
            if isinstance(output_tokens, int):
                signals.output_tokens_samples.append(output_tokens)

    elif event_type == "message_stop":
        signals.has_message_stop = True


# v1.7.1 safety valve: cap the SSE parser buffer so a malformed/
# malicious relay that sends a huge chunk without newlines cannot
# grow memory unboundedly. 1 MB is comfortably above any real
# Anthropic event size (biggest thinking blocks are ~100 KB).
MAX_STREAM_BUFFER_BYTES = 1024 * 1024
CURL_STATUS_SENTINEL = "__CODEX_HTTP_STATUS__:"


def _process_sse_line(line: str, signals: StreamSignals) -> bool:
    """Parse a single SSE line and update ``signals``.

    Returns ``True`` if the terminal ``data: [DONE]`` sentinel was
    seen (the caller should stop parsing), ``False`` otherwise.

    Skips lines that don't start with ``data: `` (e.g. ``event: ``
    or ``id: `` lines used by some SSE implementations). Silently
    ignores malformed JSON so one broken event does not abort the
    rest of the stream.
    """
    line = line.strip()
    if not line.startswith("data: "):
        return False
    data = line[6:]
    if data == "[DONE]":
        return True
    try:
        event = json.loads(data)
    except json.JSONDecodeError:
        return False
    if isinstance(event, dict):
        _populate_stream_signals(event, signals)
    return False


def _parse_sse_stream(byte_iterator, signals: StreamSignals,
                      hasher=None) -> None:
    """Consume a byte iterator and populate ``signals`` with every
    SSE event it contains.

    Handles:

    - Multi-byte chunks that split in the middle of a UTF-8 sequence
      (uses ``errors="ignore"`` on decode so we don't wedge)
    - Multiple events in a single chunk
    - A single event split across multiple chunks (buffered until
      a newline is seen)
    - A terminal ``data: [DONE]`` sentinel
    - Malformed JSON lines (skipped silently, do not abort the
      rest of the stream)
    - Empty lines / non-``data: `` lines (skipped)
    - Streams that end without a trailing newline — the final
      residual line is flushed after the iterator exhausts (v1.7.1)
    - Adversarial streams that send >1 MB without a newline —
      ``transport_error`` is set and parsing bails (v1.7.1)

    Args:
        hasher: Optional ``hashlib`` hash object. When not None, every
            raw chunk is fed to ``hasher.update()`` for incremental
            SHA-256 of the full stream (v1.7.7 transparent-log support).

    Never raises. Mutates ``signals`` in place.
    """
    buffer = ""
    for chunk in byte_iterator:
        # v1.7.7: incremental stream hashing for transparent-log.
        if hasher is not None:
            if isinstance(chunk, (bytes, bytearray)):
                hasher.update(chunk)
            else:
                hasher.update(chunk.encode("utf-8", errors="ignore"))

        if isinstance(chunk, (bytes, bytearray)):
            buffer += chunk.decode("utf-8", errors="ignore")
        else:
            buffer += chunk

        # v1.7.1: safety valve against unbounded buffer growth on
        # adversarial or broken streams. A compliant relay will have
        # drained the buffer via newline splits before reaching this
        # check; only an unterminated line can push past the cap.
        if len(buffer) > MAX_STREAM_BUFFER_BYTES:
            signals.transport_error = (
                f"SSE stream buffer exceeded {MAX_STREAM_BUFFER_BYTES} bytes "
                "(unterminated line — possible malformed or malicious stream)"
            )
            return

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if _process_sse_line(line, signals):
                return  # [DONE] sentinel

    # v1.7.1: flush any residual final line if the stream ended
    # without a trailing newline (broken or truncated relay).
    if buffer:
        _process_sse_line(buffer, signals)


class APIClient:
    """Unified API client that auto-detects Anthropic vs OpenAI format.

    On the first ``call()``, the client tries the Anthropic native message
    format and, if that fails, falls back to the OpenAI-compatible
    ``/chat/completions`` endpoint.  If a Python-level SSL error is
    encountered, the transport silently switches to a ``curl -sk``
    subprocess so the audit can continue against self-signed relays.

    Attributes:
        base_url: Root URL of the relay (trailing slash stripped).
        api_key: Bearer / x-api-key token.
        model: Model identifier forwarded to the relay.
        timeout: Per-request timeout in seconds.
        verbose: If ``True``, diagnostic messages are printed to stdout.
    """

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: int = 120, verbose: bool = True):
        """Initialise the client.

        Args:
            base_url: Root URL of the API relay (e.g. ``"https://relay.example.com"``).
            api_key: Authentication token sent as ``x-api-key`` (Anthropic)
                or ``Authorization: Bearer`` (OpenAI).
            model: Model identifier to include in every request body.
            timeout: HTTP / curl timeout in seconds. Defaults to 120.
            verbose: Whether to print diagnostic log lines. Defaults to True.
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.verbose = verbose
        self._format = None   # "anthropic" | "openai" | None (auto)
        self._use_curl = False
        self._transparent_logger = None  # Optional[TransparentLogger]

    @property
    def detected_format(self):
        """Return the detected API format.

        Returns:
            The string ``"anthropic"``, ``"openai"``, or ``None`` if
            auto-detection has not yet been performed.
        """
        return self._format

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    # -- Low-level transport --------------------------------------------------

    def _curl_post(self, url: str, headers: dict, body: dict) -> dict:
        return _transport.curl_post_json(
            url, headers, body, self.timeout, subprocess_module=subprocess)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        if self._use_curl:
            return self._curl_post(url, headers, body)
        return _transport.httpx_post_json(
            url, headers, body, self.timeout, httpx_module=httpx)

    @staticmethod
    def _error_result(error, **extra):
        error_text = str(error)
        result = {
            "error": error_text,
            "diagnosis": diagnose_error(error_text),
        }
        result.update(extra)
        return result

    # -- Anthropic native format ----------------------------------------------

    def _call_anthropic(self, messages, system=None, max_tokens=512):
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {"model": self.model, "max_tokens": max_tokens, "messages": messages}
        if system:
            body["system"] = system
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        data = self._post(url, headers, body)
        if "_http_error" in data:
            return self._error_result(data["_http_error"])
        text = _extract_anthropic_text(data.get("content"))
        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "raw": data,
        }

    # -- OpenAI compatible format ---------------------------------------------

    def _call_openai(self, messages, system=None, max_tokens=512):
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/chat/completions"

        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)
        body = {"model": self.model, "max_tokens": max_tokens, "messages": msgs}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

        data = self._post(url, headers, body)
        if "_http_error" in data:
            return self._error_result(data["_http_error"])
        choice = data.get("choices", [{}])[0]
        text = choice.get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw": data,
        }

    # -- Public API -----------------------------------------------------------

    def ensure_format(self):
        """Warm-up call that forces format auto-detection to complete.

        Step 13 latency-variance timing is sensitive to the detection
        cost: the first ``call()`` on an OpenAI-compatible relay
        silently executes an extra failing Anthropic probe before the
        successful OpenAI request, so that first "sample" is actually
        2 round-trips. Calling ``ensure_format()`` before the timing
        loop discards that detection cost so every measured sample is
        a truly identical minimal request.

        Cost: at most one ``call()`` round-trip with ``max_tokens=1``.
        Returns nothing; swallows any error (Step 13 will still surface
        the failure if subsequent probes fail).
        """
        if self._format is not None:
            return
        try:
            self.call(
                [{"role": "user", "content": "ok"}],
                max_tokens=1,
            )
        except Exception:
            pass

    def call(self, messages, system=None, max_tokens=512):
        """Send a chat completion request, auto-detecting format on first call.

        The method records wall-clock elapsed time and attaches it as the
        ``"time"`` key in the returned dict.

        Args:
            messages: List of message dicts, e.g.
                ``[{"role": "user", "content": "Hi"}]``.
            system: Optional system prompt string. Sent as a top-level
                ``"system"`` field (Anthropic) or as a system-role message
                (OpenAI).
            max_tokens: Maximum tokens to generate. Defaults to 512.

        Returns:
            A dict with the following keys on success:

            - ``text`` (str): The model's reply text.
            - ``input_tokens`` (int): Prompt token count.
            - ``output_tokens`` (int): Completion token count.
            - ``raw`` (dict): Full JSON response from the relay.
            - ``time`` (float): Wall-clock seconds elapsed.

            On failure the dict contains ``"error"`` (str) and ``"time"``.

        Examples:
            >>> client = APIClient("https://relay.example.com", "sk-...", "claude-3")
            >>> result = client.call([{"role": "user", "content": "Say hello"}])
            >>> if "error" not in result:
            ...     print(result["text"])
        """
        start = time.time()
        request_body = json.dumps({"model": self.model, "max_tokens": max_tokens,
                                   "messages": messages, "system": system or ""})
        try:
            result = self._call_with_detection(messages, system, max_tokens)
            result["time"] = time.time() - start
            # v1.7.7 transparent-log
            self._log_transparent(
                "call", self._resolve_call_url(), "POST",
                request_body, json.dumps(result.get("raw", {})),
                200 if "error" not in result else 0,
                None, result["time"], result.get("error"))
            return result
        except Exception as e:
            elapsed = time.time() - start
            self._log_transparent(
                "call", self._resolve_call_url(), "POST",
                request_body, None, 0, None, elapsed, str(e))
            return self._error_result(e, time=elapsed)

    def _resolve_call_url(self) -> str:
        """Reconstruct the URL used by the last ``call()`` based on detected format."""
        base = self.base_url
        if self._format == "openai":
            if not base.endswith("/v1"):
                base += "/v1"
            return base + "/chat/completions"
        # anthropic or unknown — default to anthropic path
        if base.endswith("/v1"):
            base = base[:-3]
        return base + "/v1/messages"

    def _call_with_detection(self, messages, system, max_tokens):
        # Already detected — use that format
        if self._format == "openai":
            return self._call_openai(messages, system, max_tokens)
        if self._format == "anthropic":
            return self._call_anthropic(messages, system, max_tokens)

        # Auto-detect: try Anthropic first
        anthropic_result = None
        try:
            anthropic_result = self._call_anthropic(messages, system, max_tokens)
            if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                self._format = "anthropic"
                self._log("  [format] -> Anthropic native")
                return anthropic_result
        except Exception as e:
            if self._handle_ssl_error(e):
                # Retry Anthropic with curl before falling through to OpenAI
                try:
                    anthropic_result = self._call_anthropic(messages, system, max_tokens)
                    if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                        self._format = "anthropic"
                        self._log("  [format] -> Anthropic native (curl)")
                        return anthropic_result
                except Exception:
                    pass  # Fall through to OpenAI probe

        # Fallback to OpenAI
        self._log("  [format] Anthropic failed/empty, trying OpenAI...")
        openai_result = None
        try:
            openai_result = self._call_openai(messages, system, max_tokens)
            if "error" not in openai_result and openai_result.get("text", "").strip():
                self._format = "openai"
                suffix = " (curl)" if self._use_curl else ""
                self._log(f"  [format] -> OpenAI compatible{suffix}")
                return openai_result
        except Exception as e:
            if self._handle_ssl_error(e):
                return self._call_with_detection(messages, system, max_tokens)

        # Both failed — return whichever has more info
        if anthropic_result and "error" not in anthropic_result:
            self._format = "anthropic"
            return anthropic_result
        if openai_result and "error" not in openai_result:
            self._format = "openai"
            return openai_result
        return anthropic_result or openai_result or self._error_result("Both formats failed")

    def _handle_ssl_error(self, e: Exception) -> bool:
        """Switch to curl on SSL errors. Returns True if retry is warranted."""
        if not self._use_curl and ("SSL" in str(e) or "Connect" in type(e).__name__):
            self._use_curl = True
            self._log("  [transport] Python SSL error, switching to curl")
            return True
        return False

    # -- Transparent forensic logging (v1.7.7, arXiv §7.3) -------------------

    def set_transparent_logger(self, logger):
        """Attach a :class:`TransparentLogger` to record every request."""
        self._transparent_logger = logger

    def _log_transparent(self, method_name: str, url: str,
                         http_method: str, request_body_bytes,
                         response_body_bytes, status_code: int,
                         response_headers, elapsed: float,
                         error=None):
        """Write one JSONL entry if a transparent logger is attached.

        ``response_body_bytes`` may be raw data (str/bytes — will be
        hashed) or a pre-computed hex digest string from incremental
        stream hashing (64-char hex — passed through as-is).
        """
        if self._transparent_logger is None:
            return
        from api_relay_audit.transparent_log import sha256hex, redact_error
        # Pre-computed digest from stream hashing is a 64-char hex string.
        if isinstance(response_body_bytes, str) and len(response_body_bytes) == 64:
            try:
                int(response_body_bytes, 16)
                resp_hash = response_body_bytes
            except ValueError:
                resp_hash = sha256hex(response_body_bytes)
        else:
            resp_hash = sha256hex(response_body_bytes)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method_name,
            "url": url,
            "http_method": http_method,
            "request_body_sha256": sha256hex(request_body_bytes),
            "response_body_sha256": resp_hash,
            "status_code": status_code,
            "response_headers": response_headers,
            "tls_version": None,   # deferred to follow-up commit
            "tls_cipher": None,    # deferred to follow-up commit
            "elapsed_seconds": round(elapsed, 3),
            "transport": "curl" if self._use_curl else "httpx",
            "error": redact_error(error),
        }
        self._transparent_logger.log_entry(entry)

    def get_models(self):
        """Fetch the model list from the ``/v1/models`` endpoint.

        Uses the same transport (httpx or curl) that has been selected for
        regular requests.

        Returns:
            A list of model dicts as returned by the relay's ``data`` field,
            or an empty list if the request fails.

        Examples:
            >>> models = client.get_models()
            >>> for m in models:
            ...     print(m.get("id"))
        """
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/models"

        # Try both auth styles: OpenAI Bearer first, then Anthropic x-api-key
        auth_variants = [
            {"Authorization": f"Bearer {self.api_key}"},
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
        ]
        # If format already detected, try the matching auth first
        if self._format == "anthropic":
            auth_variants.reverse()

        start = time.time()
        for headers in auth_variants:
            try:
                if self._use_curl:
                    data = _transport.curl_get_json_data(
                        url, headers, subprocess_module=subprocess)
                    if data:
                        self._log_transparent(
                            "get_models", url, "GET", None,
                            json.dumps(data), 200, None,
                            time.time() - start)
                        return data
                else:
                    status, data, text, response_headers = _transport.httpx_get_json_data(
                        url, headers, httpx_module=httpx)
                    if status == 200 and data:
                        self._log_transparent(
                            "get_models", url, "GET", None,
                            text, 200, response_headers,
                            time.time() - start)
                        return data
            except Exception:
                continue
        self._log_transparent(
            "get_models", url, "GET", None, None, 0, None,
            time.time() - start, "all auth variants failed")
        return []

    # -- Raw request (Step 9 error-leakage probes) ----------------------------

    def raw_request(self, method: str, path: str, headers: dict,
                    body: bytes, content_type: str = "application/json",
                    timeout: int = 30) -> dict:
        """Low-level request that preserves the full response body and headers.

        Bypasses the normal ``_post`` HTTP-status-code error handling so the
        Step 9 error-leakage probes can inspect error responses verbatim.
        Never raises; on transport failure, returns a dict with
        ``status == 0`` and an ``error`` string.

        Args:
            method: HTTP method (e.g. ``"POST"``).
            path: URL path starting with ``/``. If ``self.base_url`` already
                ends in ``/v1`` and ``path`` starts with ``/v1``, the duplicate
                segment is stripped.
            headers: Request headers (content-type is overridden by
                ``content_type``).
            body: Raw request body bytes.
            content_type: Content-Type header value. Defaults to
                ``"application/json"``.
            timeout: Per-request timeout in seconds. Defaults to 30.

        Returns:
            ``{"status": int, "headers": dict, "body": str, "error": str|None}``.
            ``status == 0`` indicates a transport failure; ``error`` is then
            a short diagnostic string.
        """
        base = self.base_url
        if base.endswith("/v1") and path.startswith("/v1"):
            base = base[:-3]
        url = base + path

        start = time.time()
        if self._use_curl:
            result = self._curl_raw_request(method, url, headers, body, content_type, timeout)
            self._log_transparent(
                "raw_request", url, method, body, result.get("body"),
                result.get("status", 0), result.get("headers"),
                time.time() - start, result.get("error"))
            return result
        try:
            result = _transport.httpx_raw_request(
                method, url, headers, body, content_type, timeout,
                httpx_module=httpx)
            self._log_transparent(
                "raw_request", url, method, body, result.get("body"),
                result.get("status", 0), result.get("headers"),
                time.time() - start)
            return result
        except Exception as e:
            # On an SSL / connect error, transparently fall back to curl so
            # the audit can still inspect the relay's error surface even
            # under a self-signed certificate.
            if self._handle_ssl_error(e):
                result = self._curl_raw_request(method, url, headers, body, content_type, timeout)
                self._log_transparent(
                    "raw_request", url, method, body, result.get("body"),
                    result.get("status", 0), result.get("headers"),
                    time.time() - start, result.get("error"))
                return result
            self._log_transparent(
                "raw_request", url, method, body, None,
                0, None, time.time() - start, str(e))
            return {"status": 0, "headers": {}, "body": "", "error": str(e)}

    def _curl_raw_request(self, method: str, url: str, headers: dict,
                          body: bytes, content_type: str, timeout: int) -> dict:
        """Curl-based fallback for ``raw_request``.

        Uses ``curl -sk -i -X <method>`` to capture both headers and body
        on stdout. Ignores self-signed certificate errors (``-k``).
        """
        return _transport.curl_raw_request(
            method, url, headers, body, content_type, timeout,
            parser=_parse_curl_i_output, subprocess_module=subprocess)

    # -- Streaming (Step 10 stream integrity) --------------------------------

    def stream_call(self, messages, system=None, max_tokens=512,
                    with_thinking: bool = True, timeout: int = 120) -> StreamSignals:
        """Open an Anthropic-format streaming request and capture SSE signals.

        Unlike :meth:`call`, this method is **Anthropic-only**. The SSE event
        schema differs from OpenAI's, and Step 10's whitelist is specifically
        about Anthropic's event shape. If the target relay is a pure
        OpenAI-compatible endpoint, the stream request returns a non-200
        status (or an OpenAI-format stream that fails our whitelist), and
        the caller should treat the result as *inconclusive*.

        Never raises. All transport errors are written to
        :attr:`StreamSignals.transport_error` so the caller can always
        inspect the returned dataclass. A zero-event return with
        ``transport_error is None`` is valid and means the relay opened the
        stream cleanly but produced no data.

        Args:
            messages: List of user/assistant message dicts.
            system: Optional system prompt string.
            max_tokens: Maximum tokens to generate. Defaults to 512.
            with_thinking: If True, include a ``thinking`` block in the
                request body to exercise the thinking-block delta path.
                Defaults to True because Step 10's whole point is to
                watch for thinking signature anomalies.
            timeout: Per-stream timeout in seconds. Defaults to 120.

        Returns:
            A fully populated :class:`StreamSignals` dataclass.
        """
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": True,
        }
        if system:
            body["system"] = system
        if with_thinking:
            # thinking.budget_tokens must be strictly less than max_tokens
            body["thinking"] = {
                "type": "enabled",
                "budget_tokens": max(1, max_tokens - 1),
            }

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "text/event-stream",
        }

        signals = StreamSignals()
        # v1.7.7: incremental hasher for transparent-log stream SHA-256.
        hasher = hashlib.sha256() if self._transparent_logger else None
        request_body_json = json.dumps(body)
        start = time.time()
        try:
            if self._use_curl:
                self._stream_via_curl(url, headers, body, timeout, signals, hasher)
            else:
                self._stream_via_httpx(url, headers, body, timeout, signals, hasher)
        except Exception as e:
            if signals.transport_error is None:
                signals.transport_error = str(e)
        finally:
            signals.total_duration_seconds = time.time() - start
            self._log_transparent(
                "stream_call", url, "POST", request_body_json,
                hasher.hexdigest() if hasher else None,
                200 if signals.transport_error is None else 0,
                None, signals.total_duration_seconds,
                signals.transport_error)

        return signals

    def _stream_via_httpx(self, url: str, headers: dict, body: dict,
                          timeout: int, signals: StreamSignals,
                          hasher=None) -> None:
        """httpx branch of :meth:`stream_call`. SSL errors trigger a
        one-time fallback to the curl branch (mirroring :meth:`_post`)."""
        try:
            with httpx.Client(timeout=timeout) as client:
                with client.stream("POST", url, headers=headers, json=body) as response:
                    if response.status_code != 200:
                        # Read a tiny prefix of the error body for diagnostics,
                        # truncated so an unredacted error page cannot bloat signals.
                        try:
                            err_body = response.read().decode("utf-8", errors="ignore")[:200]
                        except Exception:
                            err_body = ""
                        signals.transport_error = (
                            f"HTTP {response.status_code}"
                            + (f": {err_body}" if err_body else "")
                        )
                        return
                    _parse_sse_stream(response.iter_bytes(), signals, hasher)
        except Exception as e:
            if self._handle_ssl_error(e):
                self._stream_via_curl(url, headers, body, timeout, signals, hasher)
                return
            raise

    def _stream_via_curl(self, url: str, headers: dict, body: dict,
                         timeout: int, signals: StreamSignals,
                         hasher=None) -> None:
        """Curl branch of :meth:`stream_call`. Uses ``curl -N --no-buffer``
        to disable curl's own output buffering so SSE events are streamed
        to stdout as they arrive. The request body is piped via stdin.

        Read stdout line-by-line so short SSE frames are yielded as soon
        as curl flushes them. Fixed in v1.8.2: ``read(4096)`` blocked
        until the buffer filled or the process exited, which made the
        curl fallback behave like a buffered fetch instead of an
        incremental stream.
        """
        cmd = [
            "curl", "-sk", *_transport.curl_loopback_no_proxy_args(url),
            "-N", "--no-buffer", "-X", "POST", url,
            "--max-time", str(timeout),
            "-w", f"\n{CURL_STATUS_SENTINEL}%{{http_code}}\n",
            "--data-binary", "@-",
        ]
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                proc.stdin.write(json.dumps(body).encode("utf-8"))
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                # Curl already died (e.g. SSL handshake failed); let the
                # wait() + stderr read below report the real reason.
                pass

            def iter_stdout():
                status_prefix = CURL_STATUS_SENTINEL.encode("utf-8")
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if stripped.startswith(status_prefix):
                        try:
                            http_status[0] = int(
                                stripped[len(status_prefix):].decode("ascii", errors="ignore")
                            )
                        except ValueError:
                            pass
                        continue
                    if not line.lstrip().startswith(b"data: "):
                        preview = line.decode("utf-8", errors="replace").strip()
                        if preview and len(non_sse_preview) < 4:
                            non_sse_preview.append(preview)
                        continue
                    yield line

            http_status = [None]
            non_sse_preview = []
            _parse_sse_stream(iter_stdout(), signals, hasher)
            proc.wait(timeout=timeout + 10)
            if signals.transport_error is None and http_status[0] is not None and http_status[0] >= 400:
                preview = " ".join(non_sse_preview)[:200]
                if preview:
                    signals.transport_error = (
                        f"HTTP {http_status[0]} on stream open (non-SSE body: {preview})"
                    )
                else:
                    signals.transport_error = f"HTTP {http_status[0]} on stream open"
            elif signals.transport_error is None and signals.raw_event_count == 0 and non_sse_preview:
                signals.transport_error = (
                    f"Non-SSE stream response: {' '.join(non_sse_preview)[:200]}"
                )
            if proc.returncode != 0:
                # v1.7.1 Codex fix: ANY non-zero curl exit must set
                # transport_error so analyze_stream returns inconclusive.
                # The previous `and signals.raw_event_count == 0` guard
                # silently swallowed mid-stream failures and judged
                # truncated streams as clean. Already-parsed signals are
                # preserved for debugging.
                err = proc.stderr.read().decode("utf-8", errors="replace")[:200]
                if signals.transport_error is None:
                    signals.transport_error = f"curl failed: {err}"
        except subprocess.TimeoutExpired:
            if signals.transport_error is None:
                signals.transport_error = "curl stream timeout"
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as e:
            if signals.transport_error is None:
                signals.transport_error = str(e)
