"""
Shared API client with auto-detection (Anthropic / OpenAI) and curl fallback.

Eliminates duplicated API calling logic across scripts.
"""

import json
import subprocess
import time

import httpx


class APIClient:
    """Unified API client that auto-detects format and falls back to curl on SSL errors."""

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: int = 120, verbose: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.verbose = verbose
        self._format = None   # "anthropic" | "openai" | None (auto)
        self._use_curl = False

    @property
    def detected_format(self):
        return self._format

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    # -- Low-level transport --------------------------------------------------

    def _curl_post(self, url: str, headers: dict, body: dict) -> dict:
        cmd = ["curl", "-sk", "-X", "POST", url, "--max-time", str(self.timeout)]
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        cmd.extend(["-d", json.dumps(body)])
        r = subprocess.run(cmd, capture_output=True, text=True,
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
        """Send a request, auto-detecting format on first call.

        Returns dict with keys: text, input_tokens, output_tokens, raw
        Or dict with key: error
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
            self._handle_ssl_error(e)

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
        """Fetch model list from /v1/models."""
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/models"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            if self._use_curl:
                cmd = ["curl", "-sk", url, "--max-time", "15"]
                for k, v in headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                if r.returncode == 0:
                    return json.loads(r.stdout).get("data", [])
            else:
                r = httpx.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    return r.json().get("data", [])
        except Exception:
            pass
        return []
