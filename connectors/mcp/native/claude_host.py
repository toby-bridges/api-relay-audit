"""Genuine Claude Code host tests using a scripted loopback provider.

The native executable dispatches the installed MCP tools; the model provider is
deterministic and local. This proves host integration, not model selection or
real-provider compatibility. No user authentication/configuration is loaded.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time

from anthropic_fixture import AnthropicFixture, PROVIDER_KEY, TOOLS


def process_table():
    """Read PID relationships only; never read process argument strings."""
    output = subprocess.run(["/bin/ps", "-eo", "pid=,ppid=,stat="], capture_output=True,
                            text=True, timeout=5, check=True).stdout
    result = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 3:
            result[int(fields[0])] = (int(fields[1]), fields[2])
    return result


def descendants(root_pid, table):
    found = set()
    parents = {root_pid}
    while parents:
        children = {pid for pid, (ppid, _status) in table.items() if ppid in parents and pid not in found}
        found.update(children)
        parents = children
    return found


def host_environment(state_root, provider_url):
    state_root = Path(state_root)
    (state_root / "tmp").mkdir(parents=True, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
        "TMPDIR": str(state_root / "tmp"), "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
        "CLAUDE_CONFIG_DIR": str(state_root / "claude-config"),
        "ANTHROPIC_API_KEY": PROVIDER_KEY, "ANTHROPIC_BASE_URL": provider_url,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1", "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_SKIP_UPDATE_CHECK": "1", "CLAUDE_CODE_DISABLE_FAST_MODE": "1",
        "ENABLE_TOOL_SEARCH": "false",
    }


def run_scenario(*, binary, python, config, cwd, state_root, scenario,
                 mcp_env, slow_started=None, privacy_markers=(), timeout=100):
    """Execute one finite native-host turn and retain sanitized evidence only."""
    state_root = Path(state_root)
    state_root.mkdir(parents=True, exist_ok=True)
    mcp_config = state_root / "mcp.json"
    mcp_config.write_text(json.dumps({"mcpServers": {"relay_audit": {
        "type": "stdio", "command": str(python),
        "args": ["-m", "api_relay_audit_mcp", "--config", str(config)],
        "env": mcp_env,
    }}}))
    mcp_config.chmod(0o600)
    seen = set()
    stopped = threading.Event()
    with AnthropicFixture(scenario, slow_started=slow_started,
                          privacy_markers=privacy_markers) as provider:
        privacy_markers = tuple(privacy_markers) + (PROVIDER_KEY, provider.url)
        provider.privacy_markers = privacy_markers + ("Bearer ", "markdown", "flag_messages")
        args = [str(binary), "--bare", "--strict-mcp-config", "--mcp-config", str(mcp_config),
                "--setting-sources", "", "--settings", "{}", "--tools", "",
                "--permission-mode", "dontAsk", "--permission-prompts", "none",
                "--allowedTools", ",".join("mcp__relay_audit__" + name for name in TOOLS),
                "--no-session-persistence", "--no-chrome", "--disable-slash-commands",
                "--model", "claude-sonnet-4-6", "--system-prompt", "Local MCP verification fixture.",
                "--output-format", "stream-json", "--verbose", "-p",
                "Exercise the preconfigured local relay audit MCP tools for the verification fixture."]
        child = subprocess.Popen(args, cwd=cwd, env=host_environment(state_root, provider.url),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)

        def watch():
            while not stopped.wait(0.05):
                try:
                    seen.update(descendants(child.pid, process_table()))
                except (OSError, subprocess.SubprocessError):
                    pass

        monitor = threading.Thread(target=watch, daemon=True)
        monitor.start()
        timed_out = False
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                stdout, stderr = child.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                stdout, stderr = child.communicate(timeout=5)
        finally:
            stopped.set()
            monitor.join(timeout=2)
        # Native-host exit must let MCP perform its own process cleanup. Killing
        # leaked children here would mask the behavior being tested.
        deadline = time.monotonic() + 5
        alive = set()
        while time.monotonic() < deadline:
            table = process_table()
            alive = {pid for pid in seen if pid in table and not table[pid][1].startswith("Z")}
            if not alive:
                break
            time.sleep(0.1)
        output = stdout + stderr
        privacy_ok = not any(marker and marker.encode() in output for marker in privacy_markers)
        messages = []
        for line in stdout.splitlines():
            try:
                messages.append(json.loads(line))
            except ValueError:
                pass
        native_result = next((value for value in reversed(messages) if value.get("type") == "result"), {})
        init = next((value for value in messages if value.get("type") == "system" and value.get("subtype") == "init"), {})
        servers = init.get("mcp_servers", [])
        expected_connected = any(item.get("name") == "relay_audit" and item.get("status") == "connected" for item in servers)
        native_other_servers = [item for item in servers if item.get("name") != "relay_audit"]
        value = provider.summary() | {
            "scenario": scenario, "exit_code": child.returncode, "timed_out": timed_out,
            "native_result_success": native_result.get("subtype") == "success" and not native_result.get("is_error", False),
            "native_connector_connected": expected_connected,
            "native_other_servers_count": len(native_other_servers),
            "output_privacy_passed": privacy_ok,
            "observed_descendant_count": len(seen), "live_descendant_count_after_exit": len(alive),
        }
        # Failure diagnostics are fixed labels, never excerpts of host logs.
        if not native_result:
            value["failures"].append("native_final_result_missing")
        if not value["native_result_success"]:
            value["failures"].append("native_result_failed")
        if not expected_connected:
            value["failures"].append("native_connector_not_connected")
        if value["discovered_tools"] != sorted("mcp__relay_audit__" + name for name in TOOLS):
            value["failures"].append("native_tool_discovery_mismatch")
        if value["unexpected_tools_count"] or native_other_servers:
            value["failures"].append("native_host_not_isolated")
        if timed_out:
            value["failures"].append("native_host_timeout")
        if scenario in ("smoke", "lifecycle") and not value["connectivity_success"]:
            value["failures"].append("native_connectivity_failed")
        if scenario == "lifecycle" and (not value["audit_completed"] or value["risk_level"] != "HIGH" or not value["audit_cancelled"]):
            value["failures"].append("native_lifecycle_mismatch")
        if scenario == "exit_running" and (not value["running_job_returned"] or not value["slow_relay_request_started"]):
            value["failures"].append("native_running_job_missing")
        if not seen:
            value["failures"].append("native_child_process_not_witnessed")
        if alive:
            value["failures"].append("native_descendants_survived_exit")
            # Cleanup is reported as a failed assertion before teardown. It
            # cannot convert failed native cleanup into a pass.
            for pid in alive:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        if not privacy_ok:
            value["failures"].append("native_output_privacy_leak")
        return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claude", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = args.claude or (Path(shutil.which("claude")) if shutil.which("claude") else None)
    if binary is None:
        raise SystemExit("claude_binary_unavailable")
    # Common sandbox owns the pinned wheel, relay fixture and private reports.
    from common import HostSandbox, dump_result, SECRET
    with HostSandbox() as sandbox:
        version_env = host_environment(sandbox.root / "version-state", "http://127.0.0.1:1")
        version = subprocess.run([str(binary), "--version"], capture_output=True,
                                 text=True, env=version_env, cwd=sandbox.workspace, timeout=10, check=True).stdout.strip()
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)\b", version)
        if match is None or tuple(int(part) for part in match.groups()) < (2, 1, 286):
            raise RuntimeError("claude_bare_isolation_requires_2_1_286_or_later")
        results = []
        for scenario in ("smoke", "lifecycle", "exit_running"):
            sandbox.relay.slow_started.clear()
            results.append(run_scenario(binary=binary, python=sandbox.python,
                config=sandbox.connector_config, cwd=sandbox.workspace, state_root=sandbox.root / scenario,
                scenario=scenario, mcp_env=sandbox.env,
                slow_started=sandbox.relay.slow_started,
                privacy_markers=(SECRET, sandbox.relay.url, "Injected synthetic response", "ignore the host")))
            if results[-1]["failures"]:
                break
        evidence = {"host": "Claude Code", "host_version": version,
                    "test_kind": "native dispatch with scripted localhost provider; real model decisions not tested",
                    "installed_wheel_sha256": sandbox.wheel_sha256, "scenarios": results,
                    "relay": sandbox.relay.summary()}
    dump_result("claude", evidence, args.output)
    return 0 if len(results) == 3 and all(not item["failures"] and item["exit_code"] == 0 for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
