#!/usr/bin/env python3
"""Local installation, parser, and loopback recipe checks; no publication."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ENGINE_SHA = "fd99409bf745090a26bb4616fd33fbe0d873de08cfe077df413b2b93845f151d"
BASELINE = "390de58b83f8e3a7b6c54944c78eae286238dbf5"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    cli = args.tools / "node_modules/skills/bin/cli.mjs"
    cli_pkg = json.loads((cli.parent.parent / "package.json").read_text())
    checks, commands = [], []

    def check(name, passed, evidence=None):
        checks.append({"name": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name)

    env = {k: os.environ[k] for k in ("PATH", "TMPDIR", "LANG") if k in os.environ}
    env.update(DISABLE_TELEMETRY="1", DO_NOT_TRACK="1", CI="1", NO_COLOR="1",
               PYTHONDONTWRITEBYTECODE="1", GIT_TERMINAL_PROMPT="0")
    with tempfile.TemporaryDirectory(prefix="relay-skill-verification-") as temp:
        temp = Path(temp)
        guard, guard_log = temp / "deny-network.mjs", temp / "blocked-network.jsonl"
        guard.write_text("""
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
const deny = () => {
  fs.appendFileSync(process.env.SKILL_VERIFY_NETWORK_LOG, '{"blocked":true}\\n');
  throw new Error('Network disabled during local skill verification');
};
globalThis.fetch = deny;
http.request = deny; http.get = deny;
https.request = deny; https.get = deny;
net.connect = deny; net.createConnection = deny; tls.connect = deny;
""")
        env.update(NODE_OPTIONS="--import=" + str(guard),
                   SKILL_VERIFY_NETWORK_LOG=str(guard_log),
                   XDG_CONFIG_HOME=str(temp / "config"),
                   XDG_CACHE_HOME=str(temp / "cache"))

        def run(label, argv, cwd=temp, extra_env=None):
            proc = subprocess.run(argv, cwd=cwd, env={**env, **(extra_env or {})},
                                  text=True, capture_output=True, timeout=45)
            commands.append({"label": label, "argv": [str(x) for x in argv],
                             "exit_code": proc.returncode,
                             "stdout_sha256": digest(proc.stdout.encode()),
                             "stderr_sha256": digest(proc.stderr.encode())})
            if proc.returncode:
                raise RuntimeError(label + ": " + proc.stderr[-1500:] + proc.stdout[-1500:])
            return proc.stdout

        check("skills_cli_pinned", cli_pkg["version"] == "1.7.4", cli_pkg["version"])
        node_version = run("node-version", ["node", "--version"]).strip()
        cli_sha = digest((cli.parent.parent / "dist/cli.mjs").read_bytes())
        source = repo / "skills/api-relay-audit"
        skill_bytes = (source / "SKILL.md").read_bytes()
        body = skill_bytes.decode().split("---", 2)[2].strip()
        root_body = (repo / "SKILL.md").read_text().split("---", 2)[2].strip()
        check("shared_neutral_body", body == root_body)
        check("credential_recipe_uses_env_name",
              "--key-env API_RELAY_AUDIT_KEY" in body and not re.search(r'--key\s', body))
        check("all_three_profiles_documented", all(s in body for s in ("general", "web3", "full")))
        root_listing = run("root-discovery", ["node", str(cli), "add", str(repo), "--list"])
        nested_listing = run("nested-discovery", ["node", str(cli), "add", str(source), "--list"])
        check("root_discovery_one_skill", "Found 1 skill" in root_listing)
        check("nested_discovery_one_skill", "Found 1 skill" in nested_listing)

        project = temp / "cursor-project"
        project.mkdir()
        installation = json.loads(run("cursor-install", [
            "node", str(cli), "add", str(source), "--skill", "api-relay-audit",
            "--agent", "cursor", "--copy", "--yes", "--json",
        ], cwd=project))
        check("cursor_install_success", len(installation) == 1 and installation[0]["status"] == "installed")
        installed_dir = project / ".agents/skills/api-relay-audit"
        installed = installed_dir / "SKILL.md"
        check("cursor_documented_install_path", installed.is_file(), ".agents/skills/api-relay-audit/SKILL.md")
        check("installed_bytes_match", installed.read_bytes() == skill_bytes, digest(skill_bytes))
        check("single_file_bundle", sorted(p.name for p in installed_dir.iterdir()) == ["SKILL.md"])
        check("copy_is_independent", not installed.is_symlink())
        listing = json.loads(run("cursor-list", ["node", str(cli), "list", "--agent", "cursor", "--json"], cwd=project))
        check("cursor_list_recognizes_skill", len(listing) == 1 and listing[0]["name"] == "api-relay-audit")
        prompt = run("prompt-load-no-model", [
            "node", str(cli), "use", str(installed_dir), "--skill", "api-relay-audit",
        ], cwd=project)
        check("full_instructions_load_without_model", body in prompt)
        detector = json.loads(run("cursor-directory-detector", [
            "node", "--disable-warning=ExperimentalWarning",
            str(repo / "docs/distribution/skills-cursor/verify-cursor-detector.mjs"),
            str(repo), str(args.tools / "cursor-source"),
        ]))
        check("cursor_directory_single_skill", detector["component"]["name"] == "api-relay-audit")
        check("cursor_copy_preserves_whole_body", detector["component"]["content_sha256"] == digest(body.encode()))

        engine = args.tools / "audit-v2.5.0.py"
        check("released_engine_hash", digest(engine.read_bytes()) == ENGINE_SHA, ENGINE_SHA)
        check("worktree_engine_unchanged", digest((repo / "audit.py").read_bytes()) == ENGINE_SHA)
        engine_dir = temp / "engine"
        engine_dir.mkdir()
        shutil.copyfile(engine, engine_dir / "audit.py")
        validation_code = body.split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
        valid = subprocess.run([sys.executable, "-", str(engine)], input=validation_code,
                               text=True, capture_output=True, env=env, timeout=15)
        check("installed_hash_recipe_accepts_release", valid.returncode == 0)
        bad = temp / "bad-engine.py"
        bad.write_text("print('not the released engine')\n")
        invalid = subprocess.run([sys.executable, "-", str(bad)], input=validation_code,
                                 text=True, capture_output=True, env=env, timeout=15)
        check("installed_hash_recipe_rejects_mismatch",
              invalid.returncode != 0 and "SHA-256 mismatch" in invalid.stderr)
        receipts = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                receipts.append({"method": "POST", "format": "anthropic" if self.path.endswith("/messages") else "openai"})
                if self.path.endswith("/messages"):
                    payload = {"id": "msg_local_fixture", "type": "message", "role": "assistant",
                               "model": request.get("model"), "content": [{"type": "text", "text": "OK"}],
                               "stop_reason": "end_turn", "usage": {"input_tokens": 8, "output_tokens": 1}}
                else:
                    payload = {"id": "chatcmpl_local_fixture", "model": request.get("model"),
                               "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": 8, "completion_tokens": 1, "total_tokens": 9}}
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        fake_key = "local-fixture-" + os.urandom(16).hex()
        bindir = temp / "bin"
        bindir.mkdir()
        curl_receipts = temp / "curl.jsonl"
        curl_wrapper = bindir / "curl"
        curl_wrapper.write_text("#!" + sys.executable + "\n" + """
import json, os, sys
args = sys.argv[1:]
urls = [x for x in args if x.startswith(('http://','https://'))]
assert urls and all(x.startswith(os.environ['SKILL_VERIFY_LOOPBACK_PREFIX']) for x in urls)
assert os.environ['API_RELAY_AUDIT_KEY'] not in ' '.join(args)
with open(os.environ['SKILL_VERIFY_CURL_LOG'], 'a') as f:
    f.write(json.dumps({'loopback_only': True, 'key_absent_from_argv': True}) + '\\n')
os.execv('/usr/bin/curl', ['curl', '-q', '--noproxy', '*'] + args)
""")
        curl_wrapper.chmod(0o700)
        fence = chr(96) * 3
        recipe = next(block for block in re.findall(fence + r"bash\n(.*?)\n" + fence, body, re.S)
                      if "--connectivity" in block)
        run_env = {
            "API_RELAY_AUDIT_KEY": fake_key,
            "API_RELAY_AUDIT_URL": "http://127.0.0.1:" + str(server.server_port) + "/v1",
            "AUDIT_WORKDIR": str(engine_dir),
            "SKILL_VERIFY_LOOPBACK_PREFIX": "http://127.0.0.1:" + str(server.server_port) + "/",
            "SKILL_VERIFY_CURL_LOG": str(curl_receipts),
            "PATH": str(bindir) + os.pathsep + env["PATH"],
        }
        try:
            run("installed-connectivity-recipe", ["/bin/bash", "-euo", "pipefail", "-c", recipe], extra_env=run_env)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        report_bytes = (engine_dir / "connectivity.json").read_bytes()
        report = json.loads(report_bytes)
        check("installed_recipe_reaches_both_protocols",
              {r["format"] for r in receipts} == {"anthropic", "openai"}, {"fixture_requests": len(receipts)})
        check("connectivity_success", report["connectivity"]["success"] is True)
        check("connectivity_not_a_safety_rating", report["risk_level"] is None and report["coverage"] is None)
        curl_checks = [json.loads(x) for x in curl_receipts.read_text().splitlines()]
        check("curl_requests_loopback_only", len(curl_checks) >= 2 and all(x["loopback_only"] for x in curl_checks))
        check("key_absent_from_curl_argv", all(x["key_absent_from_argv"] for x in curl_checks))
        check("key_absent_from_report", fake_key.encode() not in report_bytes)
        check("key_absent_from_recorded_commands", fake_key not in json.dumps(commands))
        check("fixture_shutdown", not thread.is_alive())
        check("cli_attempted_no_network", not guard_log.exists() or not guard_log.read_text())
        for command in commands:
            command["argv"] = [
                value.replace(str(repo), "$CANDIDATE")
                .replace(str(args.tools), "$TOOLS")
                .replace(str(temp), "$TEMP")
                .replace(sys.executable, "python3")
                for value in command["argv"]
            ]
        evidence = {
            "status": "local_verified_publication_pending", "baseline_commit": BASELINE,
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
            "runtime": {"node": node_version, "python": sys.version.split()[0],
                        "skills_cli": cli_pkg["version"], "cli_sha256": cli_sha},
            "candidate": {"root_sha256": digest((repo / "SKILL.md").read_bytes()),
                          "nested_sha256": digest(skill_bytes), "body_sha256": digest(body.encode())},
            "passed": len(checks), "failed": 0, "checks": checks,
            "cursor_directory": detector, "commands": commands,
            "boundaries": {"telemetry_disabled": True, "cli_api_guard_no_network_attempts": True,
                           "synthetic_key_only": True, "real_provider_calls": 0,
                           "model_turns": 0, "directory_submissions": 0,
                           "user_level_installations": 0, "temporary_installations_removed": True},
        }
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"passed": len(checks), "failed": 0, "output": str(args.output)}))


if __name__ == "__main__":
    main()
