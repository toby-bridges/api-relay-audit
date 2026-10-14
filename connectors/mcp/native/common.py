"""Synthetic loopback fixtures and private installed-package host sandboxes."""
from __future__ import annotations

from collections import Counter
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
SECRET = "sk-synthetic-native-relay-only"
KEY_ENV = "API_RELAY_AUDIT_TEST_KEY"
EXPECTED_TOOLS = {"check_connectivity", "run_audit", "get_audit_result"}


class Relay:
    """The audited relay; responses deliberately contain synthetic evidence."""
    def __init__(self):
        self.events = []
        self.slow_started = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def respond(self, status, value):
                raw = json.dumps(value).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def receipt(self):
                # Keep only endpoint labels and credential-match booleans.
                owner.events.append({"method": self.command, "slow": self.path.startswith("/slow/"),
                    "endpoint": self.path.split("?")[0].removeprefix("/slow"),
                    "auth_matches_synthetic": self.headers.get("x-api-key") == SECRET or self.headers.get("Authorization") == "Bearer " + SECRET})

            def do_GET(self):
                self.receipt()
                if self.path.endswith("/v1/models"):
                    self.respond(200, {"data": [{"id": "claude-fixture"}]})
                else:
                    self.respond(404, {"error": {"message": "Synthetic endpoint failure " + SECRET}})

            def do_POST(self):
                self.receipt()
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path.startswith("/slow/"):
                    owner.slow_started.set()
                    time.sleep(2)
                try:
                    request = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    self.respond(400, {"error": {"message": "Synthetic JSON failure " + SECRET}})
                    return
                if not isinstance(request, dict) or not request.get("messages") or request.get("max_tokens", 0) > 1_000_000:
                    self.respond(400, {"error": {"message": "Synthetic invalid input " + SECRET}})
                elif self.path.endswith("/v1/messages"):
                    self.respond(200, {"id": "msg_synthetic", "model": "claude-fixture", "type": "message", "role": "assistant",
                        "content": [{"type": "text", "text": "Injected synthetic response " + SECRET}],
                        "stop_reason": "end_turn", "usage": {"input_tokens": 8, "output_tokens": 1}})
                elif self.path.endswith("/v1/chat/completions"):
                    self.respond(200, {"choices": [{"message": {"content": "Injected synthetic response " + SECRET}}],
                        "usage": {"prompt_tokens": 8, "completion_tokens": 1}})
                else:
                    self.respond(404, {"error": {"message": "Synthetic missing endpoint " + SECRET}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def summary(self):
        counts = Counter(f"{event['method']} {event['endpoint']}" for event in self.events)
        return {"request_count": len(self.events), "endpoint_counts": dict(counts),
                "slow_request_count": sum(event["slow"] for event in self.events),
                "synthetic_auth_match_count": sum(event["auth_matches_synthetic"] for event in self.events)}


class HostSandbox:
    """Private package install; no parent environment or user config mutation."""
    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="api-relay-audit-native-host-")
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.reports = self.root / "reports"
        self.state = self.root / "state"
        self.install_root = self.root / "package"
        for directory in (self.workspace, self.reports, self.state):
            directory.mkdir(mode=0o700)
        self.python = sys.executable
        wheels = list((PROJECT / "dist").glob("api_relay_audit_mcp-2.5.0.dev1-*.whl"))
        if len(wheels) != 1:
            self.temporary.cleanup()
            raise RuntimeError("exact_candidate_wheel_required")
        wheel = wheels[0]
        self.wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
                    "PYTHONPATH": str(self.install_root), KEY_ENV: SECRET}
        installation = subprocess.run([self.python, "-m", "pip", "install", "--no-index", "--no-deps",
                    "--target", str(self.install_root), str(wheel)], env={"PATH": self.env["PATH"], "LANG": self.env["LANG"]},
                    capture_output=True, timeout=30)
        if installation.returncode:
            self.temporary.cleanup()
            raise RuntimeError("private_wheel_install_failed")
        self.relay = Relay()
        self.relay.start()
        self.connector_config = self.root / "connector.json"
        self.connector_config.write_text(json.dumps({"report_root": str(self.reports), "timeout_seconds": 10,
            "audit_timeout_seconds": 30, "targets": {
                "fixture": {"url": self.relay.url, "model": "claude-fixture", "key_env": KEY_ENV},
                "slow": {"url": self.relay.url + "/slow", "model": "claude-fixture", "key_env": KEY_ENV}}}))
        self.connector_config.chmod(0o600)
        return self

    def mcp_config(self, server_name="relay_audit"):
        path = self.root / "mcp.json"
        path.write_text(json.dumps({"mcpServers": {server_name: {"type": "stdio", "command": self.python,
            "args": ["-m", "api_relay_audit_mcp", "--config", str(self.connector_config)],
            "env": {KEY_ENV: SECRET, "PYTHONPATH": str(self.install_root)}}}}))
        path.chmod(0o600)
        return path

    def own_processes(self):
        # Enumerate only descendants tagged by our uniquely generated config path.
        result = subprocess.run(["pgrep", "-f", str(self.connector_config)], capture_output=True, text=True)
        return [int(pid) for pid in result.stdout.split()] if result.returncode == 0 else []

    def close(self):
        self.relay.close()
        self.temporary.cleanup()

    def __exit__(self, *_args):
        self.close()


def assert_private_result(value):
    serialized = json.dumps(value)
    for forbidden in (SECRET, "Injected synthetic", "127.0.0.1", "markdown", "Bearer ", "flag_messages"):
        if forbidden in serialized:
            raise AssertionError("untrusted_evidence_reached_native_tool_result")


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def dump_result(host, payload, output_path=None):
    record = {"host": host, "scope": "configuration-isolated-native-host-loopback",
              "real_provider_used": False, "real_credentials_used": False,
              "physical_network_isolation_verified": False, **payload}
    raw = json.dumps(record, indent=2) + "\n"
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw)
    print(raw)
    return record
