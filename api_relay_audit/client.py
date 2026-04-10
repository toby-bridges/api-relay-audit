"""
Shared API client with auto-detection (Anthropic / OpenAI) and curl fallback.

Eliminates duplicated API calling logic across scripts.
"""

import json
import subprocess
import time

import httpx


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
        cmd = ["curl", "-sk", "-X", "POST", url, "--max-time", str(self.timeout),
               "--config", "-"]
        cmd.extend(["-d", json.dumps(body)])
        config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
        r = subprocess.run(cmd, capture_output=True, text=True, input=config,
                           timeout=self.timeout + 10)
        if r.returncode != 0:
            raise RuntimeError(f"curl failed: {r.stderr[:200]}")
        return json.loads(r.stdout)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        if self._use_curl:
            return self._curl_post(url, headers, body)
        r = httpx.post(url, headers=headers, json=body, timeout=self.timeout)
        if r.status_code != 200:
            return {"_http_error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return r.json()

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
            return {"error": data["_http_error"]}
        text = data.get("content", [{}])[0].get("text", "")
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
            return {"error": data["_http_error"]}
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
        try:
            result = self._call_with_detection(messages, system, max_tokens)
            result["time"] = time.time() - start
            return result
        except Exception as e:
            return {"error": str(e), "time": time.time() - start}

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
        return anthropic_result or openai_result or {"error": "Both formats failed"}

    def _handle_ssl_error(self, e: Exception) -> bool:
        """Switch to curl on SSL errors. Returns True if retry is warranted."""
        if not self._use_curl and ("SSL" in str(e) or "Connect" in type(e).__name__):
            self._use_curl = True
            self._log("  [transport] Python SSL error, switching to curl")
            return True
        return False

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

        for headers in auth_variants:
            try:
                if self._use_curl:
                    cmd = ["curl", "-sk", url, "--max-time", "15", "--config", "-"]
                    config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
                    r = subprocess.run(cmd, capture_output=True, text=True, input=config, timeout=25)
                    if r.returncode == 0:
                        data = json.loads(r.stdout).get("data", [])
                        if data:
                            return data
                else:
                    r = httpx.get(url, headers=headers, timeout=15)
                    if r.status_code == 200:
                        data = r.json().get("data", [])
                        if data:
                            return data
            except Exception:
                continue
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

        if self._use_curl:
            return self._curl_raw_request(method, url, headers, body, content_type, timeout)
        try:
            r = httpx.request(
                method=method,
                url=url,
                headers={**headers, "content-type": content_type},
                content=body,
                timeout=timeout,
            )
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text,
                "error": None,
            }
        except Exception as e:
            # On an SSL / connect error, transparently fall back to curl so
            # the audit can still inspect the relay's error surface even
            # under a self-signed certificate.
            if self._handle_ssl_error(e):
                return self._curl_raw_request(method, url, headers, body, content_type, timeout)
            return {"status": 0, "headers": {}, "body": "", "error": str(e)}

    def _curl_raw_request(self, method: str, url: str, headers: dict,
                          body: bytes, content_type: str, timeout: int) -> dict:
        """Curl-based fallback for ``raw_request``.

        Uses ``curl -sk -i -X <method>`` to capture both headers and body
        on stdout. Ignores self-signed certificate errors (``-k``).
        """
        all_headers = {**headers, "content-type": content_type}
        cmd = ["curl", "-sk", "-i", "-X", method, url,
               "--max-time", str(timeout), "--data-binary", "@-"]
        for k, v in all_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        try:
            r = subprocess.run(cmd, capture_output=True, input=body,
                               timeout=timeout + 10)
            if r.returncode != 0:
                err = r.stderr.decode("utf-8", errors="replace")[:200]
                return {"status": 0, "headers": {}, "body": "",
                        "error": f"curl failed: {err}"}
            output = r.stdout.decode("utf-8", errors="replace")
            return _parse_curl_i_output(output)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "error": str(e)}
