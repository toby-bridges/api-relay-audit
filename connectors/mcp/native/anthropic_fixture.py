"""Local-only Messages API fixture driving a genuine Claude Code MCP loop.

This is a scripted provider, not a model-quality test. Requests are processed in
memory; only tool names, counts and allowlisted outcomes are retained. The relay
under audit is a separate HTTP fixture supplied by ``common.py``.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from urllib.parse import urlsplit


PROVIDER_KEY = "sk-synthetic-native-claude-provider-only"
TOOLS = ("check_connectivity", "run_audit", "get_audit_result")


def tool_result_value(content):
    """Find the connector payload in native host tool-result text blocks."""
    if isinstance(content, str):
        try:
            value = json.loads(content)
        except (ValueError, TypeError):
            return None
        return tool_result_value(value)
    if isinstance(content, dict):
        if "ok" in content:
            return content
        for key in ("text", "content", "structuredContent"):
            if key in content:
                result = tool_result_value(content[key])
                if result is not None:
                    return result
    elif isinstance(content, list):
        for item in content:
            result = tool_result_value(item)
            if result is not None:
                return result
    return None


class AnthropicFixture:
    """Bounded scripted native-host protocol exchange over loopback SSE."""

    def __init__(self, scenario="smoke", *, slow_started=None, privacy_markers=()):
        if scenario not in ("smoke", "lifecycle", "exit_running"):
            raise ValueError("Unknown fixture scenario")
        self.scenario = scenario
        self.slow_started = slow_started
        self.privacy_markers = tuple(privacy_markers)
        self.requests = 0
        self.discovered_tools = set()
        self.unexpected_tools = set()
        self.dispatched = []
        self.results = []
        self._seen = set()
        self._pending = {}
        self.failures = []
        self.fast_job = None
        self.slow_job = None
        self.fast_completed = False
        self.cancelled = False
        self.finished = threading.Event()
        self.running_job_returned = threading.Event()
        self._server = None

    def __enter__(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def respond_json(self, status, value):
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                path = urlsplit(self.path).path
                length = int(self.headers.get("Content-Length", "0"))
                if length > 2 * 1024 * 1024:
                    self.respond_json(413, {"error": {"type": "invalid_request_error", "message": "Fixture size limit"}})
                    return
                data = self.rfile.read(length)
                if self.headers.get("x-api-key") != PROVIDER_KEY:
                    fixture.failures.append("provider_auth_not_synthetic")
                    self.respond_json(401, {"error": {"type": "authentication_error", "message": "Fixture auth required"}})
                    return
                try:
                    request = json.loads(data)
                except ValueError:
                    fixture.failures.append("provider_invalid_json")
                    self.respond_json(400, {"error": {"type": "invalid_request_error", "message": "Fixture JSON required"}})
                    return
                if path == "/v1/messages/count_tokens":
                    self.respond_json(200, {"input_tokens": 100})
                    return
                if path != "/v1/messages":
                    fixture.failures.append("provider_unexpected_endpoint")
                    self.respond_json(404, {"error": {"type": "not_found_error", "message": "Fixture endpoint unavailable"}})
                    return
                try:
                    block = fixture.next_block(request)
                    fixture.send_message(self, request, block)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as exc:
                    fixture.failures.append("provider_" + type(exc).__name__)
                    self.respond_json(500, {"error": {"type": "api_error", "message": "Fixture protocol failure"}})

            def do_GET(self):
                fixture.failures.append("provider_unexpected_get")
                self.respond_json(404, {"error": {"type": "not_found_error", "message": "Fixture endpoint unavailable"}})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://127.0.0.1:{self._server.server_port}"
        return self

    def __exit__(self, *_args):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def _call(self, bare_name, args):
        full_name = next((name for name in self.discovered_tools if name.endswith("__" + bare_name)), None)
        if full_name is None:
            self.failures.append("missing_native_mcp_tool")
            return {"type": "text", "text": "Native fixture failed: missing tool."}
        ident = f"toolu_native_{len(self.dispatched) + 1}"
        self.dispatched.append(bare_name)
        self._pending[ident] = bare_name
        return {"type": "tool_use", "id": ident, "name": full_name, "input": args}

    def _consume(self, request):
        for tool in request.get("tools", []):
            name = tool.get("name", "")
            if name in {"mcp__relay_audit__" + tool for tool in TOOLS}:
                self.discovered_tools.add(name)
            else:
                self.unexpected_tools.add(name)
        for message in request.get("messages", []):
            content = message.get("content", [])
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                ident = block.get("tool_use_id")
                if ident in self._seen:
                    continue
                self._seen.add(ident)
                raw = json.dumps(block.get("content", ""))
                if any(marker and marker in raw for marker in self.privacy_markers):
                    self.failures.append("tool_result_privacy_leak")
                name = self._pending.get(ident)
                value = tool_result_value(block.get("content"))
                if block.get("is_error") or not value or not value.get("ok"):
                    self.failures.append("native_tool_result_error")
                self.results.append({"name": name, "value": value, "is_error": bool(block.get("is_error"))})
                if name == "run_audit" and value and value.get("status") == "running":
                    if self.fast_job is None and self.scenario == "lifecycle":
                        self.fast_job = value.get("job_id")
                    else:
                        self.slow_job = value.get("job_id")
                        self.running_job_returned.set()
                if name == "get_audit_result" and value:
                    if value.get("job_id") == self.fast_job and value.get("status") == "completed":
                        self.fast_completed = True
                    if value.get("job_id") == self.slow_job and value.get("status") == "cancelled":
                        self.cancelled = True

    def next_block(self, request):
        self.requests += 1
        self._consume(request)
        if self.requests > 120 or self.failures:
            self.finished.set()
            return {"type": "text", "text": "Native fixture stopped."}
        if not self.dispatched:
            return self._call("run_audit", {"target_id": "slow", "mode": "quick"}) if self.scenario == "exit_running" else self._call("check_connectivity", {"target_id": "fixture"})
        if self.scenario == "exit_running" and self.slow_job:
            if self.slow_started is not None and not self.slow_started.wait(10):
                self.failures.append("slow_relay_request_not_started")
            self.finished.set()
            return {"type": "text", "text": "Native MCP fixture complete."}
        if self.scenario == "smoke":
            self.finished.set()
            return {"type": "text", "text": "Native MCP fixture complete."}
        if not self.fast_job:
            return self._call("run_audit", {"target_id": "fixture", "mode": "quick"})
        if not self.fast_completed:
            time.sleep(0.2)
            return self._call("get_audit_result", {"job_id": self.fast_job})
        if not self.slow_job:
            return self._call("run_audit", {"target_id": "slow", "mode": "quick"})
        if not self.cancelled:
            if self.slow_started is not None and not self.slow_started.wait(10):
                self.failures.append("slow_relay_request_not_started")
            return self._call("get_audit_result", {"job_id": self.slow_job, "action": "cancel"})
        self.finished.set()
        return {"type": "text", "text": "Native MCP fixture complete."}

    def send_message(self, handler, request, block):
        stop_reason = "tool_use" if block["type"] == "tool_use" else "end_turn"
        message = {"id": f"msg_native_{self.requests}", "type": "message", "role": "assistant",
                   "model": request.get("model", "claude-sonnet-4-6"), "content": [block],
                   "stop_reason": stop_reason, "stop_sequence": None,
                   "usage": {"input_tokens": 100, "output_tokens": 20}}
        if not request.get("stream"):
            handler.respond_json(200, message)
            return
        initial = message | {"content": [], "stop_reason": None, "usage": {"input_tokens": 100, "output_tokens": 1}}
        start_block = block | ({"input": {}} if block["type"] == "tool_use" else {"text": ""})
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])} if block["type"] == "tool_use" else {"type": "text_delta", "text": block["text"]}
        events = [("message_start", {"message": initial}),
                  ("content_block_start", {"index": 0, "content_block": start_block}),
                  ("content_block_delta", {"index": 0, "delta": delta}),
                  ("content_block_stop", {"index": 0}),
                  ("message_delta", {"delta": {"stop_reason": stop_reason, "stop_sequence": None}, "usage": {"output_tokens": 20}}),
                  ("message_stop", {})]
        data = "".join(f"event: {kind}\ndata: {json.dumps(value | {'type': kind})}\n\n" for kind, value in events).encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header("Cache-Control", "no-cache")
        handler.end_headers()
        handler.wfile.write(data)
        handler.wfile.flush()

    def summary(self):
        completed = next((item["value"] for item in reversed(self.results) if item["name"] == "get_audit_result" and item["value"] and item["value"].get("status") == "completed"), None)
        return {"provider_requests": self.requests, "discovered_tools": sorted(self.discovered_tools),
                "unexpected_tools_count": len(self.unexpected_tools), "tool_dispatch_counts": {name: self.dispatched.count(name) for name in TOOLS},
                "tool_result_count": len(self.results), "connectivity_success": any(item["name"] == "check_connectivity" and item["value"] and item["value"].get("connectivity", {}).get("success") for item in self.results),
                "audit_completed": self.fast_completed,
                "risk_level": completed.get("result", {}).get("risk_level") if completed else None,
                "audit_cancelled": self.cancelled, "running_job_returned": self.running_job_returned.is_set(),
                "slow_relay_request_started": self.slow_started.is_set() if self.slow_started is not None else False,
                "failures": list(self.failures)}
