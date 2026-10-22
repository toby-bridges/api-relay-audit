"""Exercise genuine Codex app-server MCP dispatch without a model turn."""
from __future__ import annotations

import argparse
import json
import mmap
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import threading
import time

from common import EXPECTED_TOOLS, HostSandbox, assert_private_result, dump_result, stop_group
from common import SECRET


class NativeRPC:
    def __init__(self, command, cwd, env, privacy_markers=()):
        self.process = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.messages = queue.Queue()
        self.stderr = []
        self.notifications = []
        self.next_id = 0
        self.request_methods = {}
        self.privacy_violation = False
        self.marker_receipts = {}
        self.stdout_line_count = 0
        self.stderr_line_count = 0
        def scan(line, boundary):
            if any(marker and marker in line for marker in privacy_markers):
                self.marker_receipts[boundary] = self.marker_receipts.get(boundary, 0) + 1
                # The operator requested config/read to verify the generated
                # fixture config. Its successful administrative response may
                # contain that config; it is never a model/tool result.
                if boundary != "administrative_config_response":
                    self.privacy_violation = True
        def stdout():
            for line in self.process.stdout:
                self.stdout_line_count += 1
                try:
                    value = json.loads(line)
                except ValueError:
                    scan(line, "protocol_noise")
                    self.messages.put({"protocol_noise": True})
                    continue
                if not isinstance(value, dict):
                    scan(line, "protocol_noise")
                    self.messages.put({"protocol_noise": True})
                    continue
                method = self.request_methods.pop(value.get("id"), None)
                result = value.get("result")
                administrative = (method == "config/read" and "method" not in value and "error" not in value
                                  and isinstance(result, dict) and isinstance(result.get("config"), dict))
                boundary = "administrative_config_response" if administrative else "native_protocol_output"
                scan(line, boundary)
                self.messages.put(value)
        def stderr():
            for line in self.process.stderr:
                self.stderr_line_count += 1
                scan(line, "native_stderr")
                if len(self.stderr) < 200:
                    self.stderr.append(line)
        self.readers = [threading.Thread(target=stdout, daemon=True), threading.Thread(target=stderr, daemon=True)]
        for reader in self.readers:
            reader.start()

    def send(self, method, params, request_id=None):
        message = {"method": method, "params": params}
        if request_id is not None:
            message["id"] = request_id
            self.request_methods[request_id] = method
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method, params, timeout=20):
        self.next_id += 1
        request_id = self.next_id
        self.send(method, params, request_id)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = self.messages.get(timeout=min(0.5, deadline - time.monotonic()))
            except queue.Empty:
                if self.process.poll() is not None:
                    raise RuntimeError("codex_host_exited_before_response")
                continue
            if value.get("protocol_noise"):
                raise RuntimeError("codex_protocol_noise")
            if value.get("id") == request_id:
                if "error" in value:
                    # Never reflect config/account fields from protocol errors.
                    failure = RuntimeError("codex_rpc_error_" + method.replace("/", "_"))
                    failure.rpc_error = value["error"]
                    raise failure
                return value["result"]
            self.notifications.append(value)
        raise RuntimeError("codex_rpc_timeout_" + method.replace("/", "_"))

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
            method = "stdin_eof"
        except subprocess.TimeoutExpired:
            stop_group(self.process)
            method = "harness_sigterm_fallback"
        for reader in self.readers:
            reader.join(timeout=2)
        if any(reader.is_alive() for reader in self.readers):
            raise RuntimeError("native_output_drain_incomplete")
        return method


def bundled_catalog(executable, destination):
    """Copy only the executable's public bundled catalog into temporary state."""
    with open(executable, "rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            offset = data.find(b'"models": [\n')
            if offset < 4:
                raise RuntimeError("bundled_catalog_unavailable")
            raw = data[offset - 4:offset + 2 * 1024 * 1024].decode("utf-8", errors="ignore")
            catalog, _end = json.JSONDecoder().raw_decode(raw)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("models"), list) or not catalog["models"]:
        raise RuntimeError("invalid_bundled_catalog")
    destination.write_text(json.dumps(catalog))
    return catalog["models"][0]["slug"]


def child_process_witness(root_pid):
    table = {}
    raw = subprocess.check_output(["ps", "-eo", "pid=,ppid=,stat="], text=True)
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) == 3:
            table[int(fields[0])] = (int(fields[1]), fields[2])
    descendants = set()
    pending = {root_pid}
    while pending:
        children = {pid for pid, (parent, _status) in table.items() if parent in pending and pid not in descendants}
        descendants.update(children)
        pending = children
    return descendants, table


def run(sandbox, executable):
    state = sandbox.state / "codex"
    state.mkdir(mode=0o700)
    catalog_path = state / "catalog.json"
    model = bundled_catalog(executable, catalog_path)
    config_path = state / "config.toml"
    q = json.dumps
    config_path.write_text(f'''model = {q(model)}
model_provider = "native_fixture"
model_catalog_json = {q(str(catalog_path))}
cli_auth_credentials_store = "ephemeral"
check_for_update_on_startup = false
approval_policy = "never"
sandbox_mode = "read-only"
[analytics]
enabled = false
[otel]
exporter = "none"
trace_exporter = "none"
metrics_exporter = "none"
[features]
apps = false
plugins = false
[model_providers.native_fixture]
name = "Local native-host fixture (no model turn)"
base_url = {q(sandbox.relay.url + "/unused-model-provider")}
requires_openai_auth = false
wire_api = "responses"
[mcp_servers.relay_audit]
command = {q(sandbox.python)}
args = {q(["-m", "api_relay_audit_mcp", "--config", str(sandbox.connector_config)])}
startup_timeout_sec = 10
tool_timeout_sec = 15
required = true
[mcp_servers.relay_audit.env]
API_RELAY_AUDIT_TEST_KEY = {q(sandbox.env["API_RELAY_AUDIT_TEST_KEY"])}
PYTHONPATH = {q(str(sandbox.install_root))}
''')
    config_path.chmod(0o600)
    env = {**sandbox.env, "CODEX_HOME": str(state)}
    version = subprocess.check_output([executable, "--version"], env=env, text=True).strip()
    rpc = NativeRPC([executable, "app-server", "--strict-config", "--stdio"], sandbox.workspace, env,
                    privacy_markers=(SECRET, sandbox.relay.url))
    checks = {}
    thread_id = None
    descendants_at_exit = set()
    teardown_method = None
    try:
        rpc.request("initialize", {"clientInfo": {"name": "api-relay-audit-native-test", "version": "1.0.0"},
            "capabilities": {"experimentalApi": True}})
        rpc.send("initialized", {})
        checks["native_initialize"] = True
        requirements = rpc.request("configRequirements/read", {})
        # Read only these policy choices. Do not persist the protocol response.
        policies = requirements.get("requirements") or {}
        if policies.get("modelProvider") not in (None, "native_fixture"):
            raise RuntimeError("managed_provider_conflicts_with_fixture")
        if policies.get("cliAuthCredentialsStore") not in (None, "ephemeral"):
            raise RuntimeError("managed_auth_backend_conflicts_with_fixture")
        if policies.get("modelCatalogJson") not in (None, str(catalog_path)):
            raise RuntimeError("managed_catalog_conflicts_with_fixture")
        if (policies.get("modelProviders") or {}).get("native_fixture") is not None:
            raise RuntimeError("managed_provider_definition_conflicts_with_fixture")
        features = policies.get("featureRequirements") or {}
        if features.get("apps") is True or features.get("plugins") is True or policies.get("checkForUpdateOnStartup") is True:
            raise RuntimeError("managed_features_conflict_with_fixture")
        checks["managed_provider_does_not_override_fixture"] = True
        effective = rpc.request("config/read", {"includeLayers": False})["config"]
        if effective.get("model_provider") != "native_fixture" or effective.get("analytics", {}).get("enabled") is not False:
            raise RuntimeError("effective_isolation_config_mismatch")
        checks["effective_local_provider_and_analytics_disabled"] = True
        thread = rpc.request("thread/start", {"cwd": str(sandbox.workspace), "ephemeral": True})
        thread_id = thread["thread"]["id"]
        checks["ephemeral_native_thread"] = thread["thread"].get("ephemeral") is True
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            listing = rpc.request("mcpServerStatus/list", {"threadId": thread_id, "detail": "toolsAndAuthOnly"})
            servers = listing["data"]
            if {server["name"] for server in servers} != {"relay_audit"}:
                raise RuntimeError("unexpected_native_mcp_server")
            tools = servers[0].get("tools", {})
            names = set(tools) if isinstance(tools, dict) else {tool["name"] for tool in tools}
            if names == EXPECTED_TOOLS:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("native_tool_discovery_failed")
        checks["exact_three_tools_and_one_server"] = True

        def call(tool, arguments):
            result = rpc.request("mcpServer/tool/call", {"threadId": thread_id, "server": "relay_audit", "tool": tool, "arguments": arguments})
            assert_private_result(result)
            payload = result.get("structuredContent")
            if payload is None:
                payload = json.loads(next(block["text"] for block in result["content"] if block.get("type") == "text"))
            assert_private_result(payload)
            return payload

        receipt = call("check_connectivity", {"target_id": "fixture"})
        assert receipt["connectivity"]["success"] is True
        assert receipt["risk_level"] is None and receipt["coverage"] is None
        checks["connectivity_success_is_unrated"] = True
        invalid = call("check_connectivity", {"target_id": "unconfigured"})
        assert invalid == {"ok": False, "error": "unknown_target"}
        checks["fixed_unknown_target_error"] = True
        malformed = call("run_audit", {"target_id": "fixture", "mode": "bad-input"})
        assert malformed == {"ok": False, "error": "invalid_tool_arguments"}
        checks["fixed_invalid_argument_error"] = True
        launched = call("run_audit", {"target_id": "fixture", "mode": "quick"})
        assert launched["status"] == "running"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            completed = call("get_audit_result", {"job_id": launched["job_id"]})
            if completed["status"] != "running":
                break
            time.sleep(0.1)
        assert completed["status"] == "completed" and completed["result"]["risk_level"] == "HIGH"
        assert completed["result"]["coverage"]["skipped_steps"]["step_numbers"] == [1, 7, 11, 13]
        checks["native_quick_audit_preserves_high_and_skips"] = True
        checks["private_tool_results"] = True
        slow = call("run_audit", {"target_id": "slow"})
        assert sandbox.relay.slow_started.wait(timeout=5)
        cancelled = call("get_audit_result", {"job_id": slow["job_id"], "action": "cancel"})
        assert cancelled["status"] == "cancelled"
        checks["native_active_job_cancelled"] = True
        sandbox.relay.slow_started.clear()
        exit_job = call("run_audit", {"target_id": "slow"})
        assert exit_job["status"] == "running" and sandbox.relay.slow_started.wait(timeout=5)
        descendants_at_exit, _table = child_process_witness(rpc.process.pid)
        assert len(descendants_at_exit) >= 3
        checks["active_job_at_host_exit_witnessed"] = True
    finally:
        teardown_method = rpc.close()
    if teardown_method != "stdin_eof":
        raise RuntimeError("native_eof_cleanup_required_harness_termination")
    checks["native_eof_exit_without_harness_termination"] = True
    deadline = time.monotonic() + 5
    while sandbox.own_processes() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not sandbox.own_processes(), "native_host_left_mcp_process"
    checks["native_host_exit_reaped_mcp_server"] = True
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        _unused, table = child_process_witness(-1)
        survivors = {pid for pid in descendants_at_exit if pid in table and not table[pid][1].startswith("Z")}
        if not survivors:
            break
        time.sleep(0.1)
    if survivors:
        for pid in survivors:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        raise RuntimeError("native_host_left_audit_descendants")
    checks["native_exit_reaped_audit_and_curl_descendants"] = True
    assert not any("unused-model-provider" in event["endpoint"] for event in sandbox.relay.events)
    checks["no_model_turn_or_fixture_model_request"] = True
    native_logs = "".join(rpc.stderr) + json.dumps(rpc.notifications)
    assert SECRET not in native_logs and sandbox.relay.url not in native_logs and not rpc.privacy_violation
    checks["native_notifications_and_stderr_privacy"] = True
    checks["all_native_output_scanned_with_admin_config_separated"] = True
    return {"host_version": version, "adapter_wheel_sha256": sandbox.wheel_sha256,
            "checks": checks, "passed_check_count": sum(checks.values()),
            "relay": sandbox.relay.summary(), "native_ui_verified": False,
            "observed_descendants_at_exit": len(descendants_at_exit), "live_descendants_after_exit": 0,
            "teardown_method": teardown_method,
            "native_stdout_lines_scanned": rpc.stdout_line_count, "native_stderr_lines_scanned": rpc.stderr_line_count,
            "fixture_marker_receipts": rpc.marker_receipts,
            "personal_credentials_supplied": False, "existing_account_credentials_configured": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    executable = shutil.which("codex")
    if not executable:
        raise SystemExit("codex_binary_unavailable")
    with HostSandbox() as sandbox:
        result = run(sandbox, executable)
    dump_result("codex-app-server", result, args.output)


if __name__ == "__main__":
    main()
