"""
Shared API client with auto-detection (Anthropic / OpenAI) and curl fallback.

Eliminates duplicated API calling logic across scripts.
"""

import hashlib
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone

import httpx

from api_relay_audit import _transport
from api_relay_audit.error_diagnosis import diagnose_error
from api_relay_audit.error_leakage import redact_sensitive_text
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


TOOL_PROBE_TEXT_LIMIT = 200


def _is_token_char(char) -> bool:
    return (char.isascii() and char.isalnum()) or char in "-_.~+/="


def _clip_probe_text(text, limit=TOOL_PROBE_TEXT_LIMIT) -> str:
    """Bound the text a no-call Tool Call probe returned.

    When the cut lands inside a token, the partial token is dropped so a
    truncated credential cannot fall below the redaction patterns' minimum
    length before the report layer redacts the excerpt.
    """
    if not isinstance(text, str):
        return ""
    if len(text) <= limit:
        return text
    end = limit
    if _is_token_char(text[limit]):
        while end and _is_token_char(text[end - 1]):
            end -= 1
    return text[:end]


def _thinking_config(max_tokens: int) -> dict:
    """Return the ``thinking`` request field shared by :meth:`APIClient.call`
    and :meth:`APIClient.stream_call`.

    ``thinking.budget_tokens`` must be strictly less than ``max_tokens``.
    Keeping one builder means a stream / non-stream request pair always
    asks for the same thinking configuration.
    """
    return {"type": "enabled", "budget_tokens": max(1, max_tokens - 1)}


def _optional_call_kwargs(with_thinking=False) -> dict:
    """Return ``with_thinking`` as a keyword argument only when set, so a
    default call keeps its original ``(messages, system, max_tokens)`` shape
    all the way down to the format-specific helpers."""
    return {"with_thinking": True} if with_thinking else {}


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
            if block.get("type") in ("thinking", "redacted_thinking"):
                _capture_thinking_block_start(block, signals)

    elif event_type == "content_block_delta":
        signals.has_content_block_delta = True
        delta = event.get("delta", {})
        if isinstance(delta, dict):
            delta_type = delta.get("type")
            if isinstance(delta_type, str) and delta_type:
                signals.delta_types.append(delta_type)

            if delta_type == "text_delta":
                signals.has_text_delta = True
                text = delta.get("text")
                if isinstance(text, str) and len(signals.text) < MAX_STREAM_TEXT_CHARS:
                    signals.text = (signals.text + text)[:MAX_STREAM_TEXT_CHARS]
            elif delta_type == "thinking_delta":
                signals.thinking_delta_seen = True
                _capture_thinking_delta(signals, "thinking", delta.get("thinking"))
            elif delta_type == "signature_delta":
                signature = delta.get("signature")
                if isinstance(signature, str) and not signature.strip():
                    signals.empty_signature_delta_count += 1
                _capture_thinking_delta(signals, "signature", signature)

    elif event_type == "message_delta":
        signals.has_message_delta = True
        message_delta = event.get("delta", {})
        if isinstance(message_delta, dict):
            stop_reason = message_delta.get("stop_reason")
            if isinstance(stop_reason, str) and stop_reason:
                signals.stop_reason = stop_reason
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


def _thinking_capture_size(signals: StreamSignals) -> int:
    """Characters held in ``signals.thinking_blocks`` payload fields."""
    size = 0
    for block in signals.thinking_blocks:
        for key in ("thinking", "signature", "data"):
            value = block.get(key)
            if isinstance(value, str):
                size += len(value)
    return size


def _capture_thinking_block_start(block: dict, signals: StreamSignals) -> None:
    """Open one captured ``thinking`` / ``redacted_thinking`` block.

    The block is kept in the shape the Messages API accepts back. Once a
    bound is hit the capture stops for good and is marked truncated, so a
    partial block is never replayed.
    """
    if signals.thinking_capture_truncated:
        return
    if block.get("type") == "redacted_thinking":
        data = block.get("data")
        entry = {"type": "redacted_thinking",
                 "data": data if isinstance(data, str) else ""}
    else:
        thinking = block.get("thinking")
        signature = block.get("signature")
        entry = {"type": "thinking",
                 "thinking": thinking if isinstance(thinking, str) else "",
                 "signature": signature if isinstance(signature, str) else ""}
    added = sum(len(v) for k, v in entry.items() if k != "type")
    if (len(signals.thinking_blocks) >= MAX_STREAM_THINKING_BLOCKS
            or _thinking_capture_size(signals) + added > MAX_STREAM_THINKING_CHARS):
        signals.thinking_capture_truncated = True
        return
    signals.thinking_blocks.append(entry)


def _capture_thinking_delta(signals: StreamSignals, key: str, value) -> None:
    """Append a ``thinking_delta`` / ``signature_delta`` value to the open block.

    Deltas belong to the block opened by the latest ``content_block_start``,
    so they are applied only while that block is a captured thinking block.
    A genuine stream sends one ``signature_delta`` per block; appending keeps
    a relay that splits it into several deltas replayable.
    """
    if signals.thinking_capture_truncated or not isinstance(value, str):
        return
    if (not signals.thinking_blocks
            or not signals.content_block_types
            or signals.content_block_types[-1] != "thinking"
            or signals.thinking_blocks[-1].get("type") != "thinking"):
        return
    if _thinking_capture_size(signals) + len(value) > MAX_STREAM_THINKING_CHARS:
        signals.thinking_capture_truncated = True
        return
    signals.thinking_blocks[-1][key] += value


# v1.7.1 safety valve: cap the SSE parser buffer so a malformed/
# malicious relay that sends a huge chunk without newlines cannot
# grow memory unboundedly. 1 MB is comfortably above any real
# Anthropic event size (biggest thinking blocks are ~100 KB).
MAX_STREAM_BUFFER_BYTES = 1024 * 1024
# Same idea for StreamSignals.text: bound memory and CPU when a relay streams
# far more text than requested. 64 KiB is far above Step 10's 100-token probe.
MAX_STREAM_TEXT_CHARS = 64 * 1024
# Same idea for StreamSignals.thinking_blocks (thinking text, signatures and
# redacted data kept for the opt-in signature round-trip). Step 10's probe
# thinks for under 100 tokens, so real streams stay far below both bounds.
MAX_STREAM_THINKING_CHARS = 64 * 1024
MAX_STREAM_THINKING_BLOCKS = 16
# Error text kept from a signature replay, after redaction.
REPLAY_ERROR_CHARS = 160
CURL_STATUS_SENTINEL = "__CODEX_HTTP_STATUS__:"


def _clip_replay_error(text, api_key: str) -> str:
    """Redact, flatten and clip the error text of a signature replay.

    Redaction runs on the full text before the cut, so a credential cannot
    survive by being split at the boundary.
    """
    text = redact_sensitive_text(str(text), api_key)
    return " ".join(text.split())[:REPLAY_ERROR_CHARS]


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

    def _call_anthropic(self, messages, system=None, max_tokens=512,
                        with_thinking=False):
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {"model": self.model, "max_tokens": max_tokens, "messages": messages}
        if system:
            body["system"] = system
        if with_thinking:
            body["thinking"] = _thinking_config(max_tokens)
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

    def _call_openai(self, messages, system=None, max_tokens=512,
                     with_thinking=False):
        # ``with_thinking`` is accepted for signature parity with
        # ``_call_anthropic`` but ignored: Chat Completions has no standard
        # ``thinking`` field, and strict endpoints reject unknown fields.
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

    def _prepare_tool_probe_anthropic(self, messages, tool_spec, max_tokens=256):
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "tools": [{**tool_spec, "strict": True}],
            "tool_choice": {
                "type": "tool",
                "name": tool_spec["name"],
                "disable_parallel_tool_use": True,
            },
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        return url, headers, body

    def _call_tool_probe_anthropic(self, messages, tool_spec, max_tokens=256,
                                   prepared=None):
        url, headers, body = prepared or self._prepare_tool_probe_anthropic(
            messages, tool_spec, max_tokens=max_tokens)
        data = self._post(url, headers, body)
        if "_http_error" in data:
            return self._error_result(data["_http_error"])

        tool_calls = []
        content = data.get("content", [])
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                block_type = block.get("type")
                tool_like = block_type == "tool_use" or any(
                    key in block for key in ("id", "name", "input")
                )
                if not tool_like:
                    continue
                arguments = block.get("input")
                arguments_error = None
                if not isinstance(arguments, dict):
                    arguments_error = "Anthropic tool input was not a JSON object"
                    arguments = None
                tool_calls.append({
                    "type": "function" if block_type == "tool_use" else block_type,
                    "id": block.get("id"),
                    "name": block.get("name"),
                    "arguments": arguments,
                    "arguments_error": arguments_error,
                })

        usage = data.get("usage", {})
        result = {
            "protocol": "anthropic",
            "tool_calls": tool_calls,
            "stop_reason": data.get("stop_reason"),
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "raw": data,
        }
        if not tool_calls:
            result["text"] = _clip_probe_text(_extract_anthropic_text(content))
        return result

    def _prepare_tool_probe_openai(self, messages, tool_spec, max_tokens=256):
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/chat/completions"

        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "tools": [{
                "type": "function",
                "function": {
                    "name": tool_spec["name"],
                    "description": tool_spec["description"],
                    "parameters": tool_spec["input_schema"],
                    "strict": True,
                },
            }],
            "tool_choice": {
                "type": "function",
                "function": {"name": tool_spec["name"]},
            },
            "parallel_tool_calls": False,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }
        return url, headers, body

    def _call_tool_probe_openai(self, messages, tool_spec, max_tokens=256,
                                prepared=None):
        url, headers, body = prepared or self._prepare_tool_probe_openai(
            messages, tool_spec, max_tokens=max_tokens)
        data = self._post(url, headers, body)
        if "_http_error" in data:
            return self._error_result(data["_http_error"])

        choices = data.get("choices", [])
        choice = choices[0] if isinstance(choices, list) and choices else {}
        if not isinstance(choice, dict):
            choice = {}
        message = choice.get("message", {})
        if not isinstance(message, dict):
            message = {}
        raw_calls = message.get("tool_calls", [])
        if not isinstance(raw_calls, list):
            raw_calls = []

        tool_calls = []
        for raw_call in raw_calls:
            if not isinstance(raw_call, dict):
                continue
            call_type = raw_call.get("type")
            if call_type == "function":
                function = raw_call.get("function", {})
                if not isinstance(function, dict):
                    function = {}
                raw_arguments = function.get("arguments")
                arguments = None
                arguments_error = None
                if not isinstance(raw_arguments, str):
                    arguments_error = "OpenAI tool arguments were not a JSON string"
                else:
                    try:
                        arguments = json.loads(raw_arguments)
                    except (TypeError, ValueError):
                        arguments_error = "invalid JSON arguments"
                    if arguments_error is None and not isinstance(arguments, dict):
                        arguments_error = "OpenAI tool arguments were not a JSON object"
                        arguments = None
                name = function.get("name")
            else:
                custom = raw_call.get("custom", {})
                if not isinstance(custom, dict):
                    custom = {}
                name = custom.get("name")
                arguments = None
                arguments_error = "Unexpected non-function Tool Call type"
            tool_calls.append({
                "type": call_type,
                "id": raw_call.get("id"),
                "name": name,
                "arguments": arguments,
                "arguments_error": arguments_error,
            })

        usage = data.get("usage", {})
        result = {
            "protocol": "openai",
            "tool_calls": tool_calls,
            "stop_reason": choice.get("finish_reason"),
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw": data,
        }
        if not tool_calls:
            content = message.get("content")
            text = content if isinstance(content, str) else _extract_anthropic_text(content)
            result["text"] = _clip_probe_text(text)
        return result

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

    def call(self, messages, system=None, max_tokens=512, with_thinking=False):
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
            with_thinking: If True, send the same ``thinking`` block that
                :meth:`stream_call` sends. Anthropic format only; the
                OpenAI-compatible body ignores it. Defaults to False.

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
        logged_request = {"model": self.model, "max_tokens": max_tokens,
                          "messages": messages, "system": system or ""}
        if with_thinking:
            logged_request["thinking"] = _thinking_config(max_tokens)
        request_body = json.dumps(logged_request)
        try:
            result = self._call_with_detection(
                messages, system, max_tokens,
                **_optional_call_kwargs(with_thinking))
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

    def call_tool_probe(self, messages, tool_spec, max_tokens=256):
        """Request one inert client Tool Call without ever executing it.

        ``tool_spec`` uses the protocol-neutral Anthropic shape (``name``,
        ``description``, ``input_schema``). The client forces that tool,
        disables parallel calls, and normalizes Anthropic/OpenAI responses
        into a shared ``tool_calls`` list. No executor callback exists and no
        ``tool_result`` follow-up request is sent.
        """
        start = time.time()
        request_url = self._resolve_call_url()
        request_body = json.dumps({})
        try:
            if self._format is None:
                self.ensure_format()
            if self._format == "anthropic":
                prepared = self._prepare_tool_probe_anthropic(
                    messages, tool_spec, max_tokens=max_tokens)
                request_url, _, wire_body = prepared
                request_body = json.dumps(wire_body)
                result = self._call_tool_probe_anthropic(
                    messages, tool_spec, max_tokens=max_tokens,
                    prepared=prepared)
            elif self._format == "openai":
                prepared = self._prepare_tool_probe_openai(
                    messages, tool_spec, max_tokens=max_tokens)
                request_url, _, wire_body = prepared
                request_body = json.dumps(wire_body)
                result = self._call_tool_probe_openai(
                    messages, tool_spec, max_tokens=max_tokens,
                    prepared=prepared)
            else:
                result = self._error_result(
                    "Could not detect API format for structured Tool Call probe")
            result["time"] = time.time() - start
            self._log_transparent(
                "tool_call_probe", request_url, "POST",
                request_body, json.dumps(result.get("raw", {})),
                200 if "error" not in result else 0,
                None, result["time"], result.get("error"))
            return result
        except Exception as e:
            elapsed = time.time() - start
            self._log_transparent(
                "tool_call_probe", request_url, "POST",
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

    def _call_with_detection(self, messages, system, max_tokens,
                             with_thinking=False):
        extra = _optional_call_kwargs(with_thinking)
        # Already detected — use that format
        if self._format == "openai":
            return self._call_openai(messages, system, max_tokens, **extra)
        if self._format == "anthropic":
            return self._call_anthropic(messages, system, max_tokens, **extra)

        # Auto-detect: try Anthropic first
        anthropic_result = None
        try:
            anthropic_result = self._call_anthropic(messages, system, max_tokens, **extra)
            if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                self._format = "anthropic"
                self._log("  [format] -> Anthropic native")
                return anthropic_result
        except Exception as e:
            if self._handle_ssl_error(e):
                # Retry Anthropic with curl before falling through to OpenAI
                try:
                    anthropic_result = self._call_anthropic(messages, system, max_tokens, **extra)
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
            openai_result = self._call_openai(messages, system, max_tokens, **extra)
            if "error" not in openai_result and openai_result.get("text", "").strip():
                self._format = "openai"
                suffix = " (curl)" if self._use_curl else ""
                self._log(f"  [format] -> OpenAI compatible{suffix}")
                return openai_result
        except Exception as e:
            if self._handle_ssl_error(e):
                return self._call_with_detection(messages, system, max_tokens, **extra)

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
            body["thinking"] = _thinking_config(max_tokens)

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

    def replay_thinking(self, messages_prefix, assistant_content,
                        follow_up_text, max_tokens=32) -> dict:
        """Pass a streamed assistant turn back once (opt-in signature round-trip).

        Sends one non-stream Anthropic request whose ``messages`` are
        ``messages_prefix`` (the original user turn, unchanged), an assistant
        turn whose ``content`` is ``assistant_content`` exactly as given (the
        streamed thinking blocks plus the reply text) and a new user turn with
        ``follow_up_text``. ``thinking`` comes from the same builder as the
        Step 10 stream. No system prompt, tools or sampling parameters are
        sent: current API versions reject temperature / top_p / top_k.

        Never raises. Returns a normalized dict:

        - ``status``: HTTP status code, or ``None`` on a transport failure
        - ``error``: ``None`` on 2xx; otherwise the error message of an error
          body (else the raw body or transport error), redacted and clipped
          to :data:`REPLAY_ERROR_CHARS` characters
        - ``error_type``: ``error.type`` of an Anthropic error body, or ``None``
        - ``input_tokens``: ``usage.input_tokens`` of a 2xx reply, or ``None``
        """
        result = {"status": None, "error": None, "error_type": None,
                  "input_tokens": None}
        try:
            body = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": list(messages_prefix) + [
                    {"role": "assistant", "content": assistant_content},
                    {"role": "user", "content": follow_up_text},
                ],
                "thinking": _thinking_config(max_tokens),
            }
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
            response = self.raw_request(
                "POST", "/v1/messages", headers,
                json.dumps(body).encode("utf-8"),
                content_type="application/json", timeout=self.timeout,
            )
            if not isinstance(response, dict):
                response = {"status": 0, "error": "unexpected raw_request result"}
            status = response.get("status")
            if isinstance(status, bool) or not isinstance(status, int) or status <= 0:
                result["error"] = _clip_replay_error(
                    response.get("error") or "no HTTP status", self.api_key)
                return result
            result["status"] = status
            body_text = response.get("body")
            body_text = body_text if isinstance(body_text, str) else ""
            try:
                payload = json.loads(body_text) if body_text.strip() else None
            except ValueError:
                payload = None
            if 200 <= status < 300:
                usage = payload.get("usage") if isinstance(payload, dict) else None
                input_tokens = usage.get("input_tokens") if isinstance(usage, dict) else None
                if isinstance(input_tokens, int) and not isinstance(input_tokens, bool):
                    result["input_tokens"] = input_tokens
                return result
            message = body_text
            error_obj = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(error_obj, dict):
                if payload.get("type") == "error" and isinstance(error_obj.get("type"), str):
                    result["error_type"] = _clip_replay_error(
                        error_obj["type"], self.api_key)
                if isinstance(error_obj.get("message"), str) and error_obj["message"].strip():
                    message = error_obj["message"]
            result["error"] = _clip_replay_error(
                message if message.strip() else f"HTTP {status}", self.api_key)
        except Exception as e:
            result["error"] = _clip_replay_error(
                f"{type(e).__name__}: {e}", self.api_key)
        return result

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
        to stdout as they arrive. Headers are piped through curl config stdin;
        the request body is held in a private, short-lived file.

        Read stdout line-by-line so short SSE frames are yielded as soon
        as curl flushes them. Fixed in v1.8.2: ``read(4096)`` blocked
        until the buffer filled or the process exited, which made the
        curl fallback behave like a buffered fetch instead of an
        incremental stream.
        """
        body_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb", delete=False, prefix="api-relay-body-", suffix=".json"
            ) as body_file:
                body_path = body_file.name
                body_file.write(json.dumps(body).encode("utf-8"))
            cmd = [
                "curl", "-sk", *_transport.curl_loopback_no_proxy_args(url),
                "-N", "--no-buffer", "-X", "POST", url,
                "--max-time", str(timeout),
                "-w", f"\n{CURL_STATUS_SENTINEL}%{{http_code}}\n",
                "--config", "-", "--data-binary", f"@{body_path}",
            ]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                proc.stdin.write(_transport.curl_header_config(headers).encode("utf-8"))
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
        finally:
            if body_path is not None:
                try:
                    os.unlink(body_path)
                except OSError:
                    pass
