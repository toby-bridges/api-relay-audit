"""Verify the distributable artifact, not only imports from the source tree."""
from email.parser import BytesParser
from hashlib import sha256
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import threading
import zipfile

import pytest

PROJECT = Path(__file__).resolve().parents[1]
REPOSITORY = PROJECT.parent.parent
PACKAGE = "api_relay_audit_mcp"


def execute(args, *, cwd, env=None):
    result = subprocess.run([sys.executable, *args], cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


@pytest.fixture(scope="module")
def archives(tmp_path_factory):
    directory = tmp_path_factory.mktemp("mcp-package")
    output = directory / "from-repository"
    execute(["-m", "build", str(PROJECT), "--outdir", str(output)], cwd=directory)
    return directory, next(output.glob("*.whl")), next(output.glob("*.tar.gz"))


def test_wheel_and_sdist_bundle_exact_engine_license_and_package_metadata(archives):
    _directory, wheel, source = archives
    repository_source = (REPOSITORY / "scripts" / "build-standalone.py").is_file()
    expected_engine = ((REPOSITORY / "audit.py") if repository_source else (PROJECT / PACKAGE / "_audit.py")).read_bytes()
    expected_license = (PROJECT / "LICENSE").read_bytes()
    with zipfile.ZipFile(wheel) as archive:
        engine = archive.read(f"{PACKAGE}/_audit.py")
        assert engine == expected_engine
        provenance = json.loads(archive.read(f"{PACKAGE}/provenance.json"))
        assert sha256(engine).hexdigest() == provenance["engine_sha256"]
        assert provenance["engine_commit"] == "75bdac000051871c9f088a3be58e6f17a8854ffb"
        assert archive.read(f"{PACKAGE}/config.example.json") == (PROJECT / "config.example.json").read_bytes()
        for example in (PROJECT / "examples").iterdir():
            assert archive.read(f"{PACKAGE}/examples/{example.name}") == example.read_bytes()
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        assert metadata["Name"] == "api-relay-audit-mcp"
        assert metadata["Version"] == "2.5.0.dev1"
        assert metadata["Requires-Python"] == ">=3.10"
        assert "mcp==2.3.0" in metadata.get_all("Requires-Dist")
        license_name = next(name for name in archive.namelist() if name.endswith("/licenses/LICENSE"))
        assert archive.read(license_name) == expected_license
        entrypoint_name = next(name for name in archive.namelist() if name.endswith("/entry_points.txt"))
        assert "api-relay-audit-mcp = api_relay_audit_mcp.server:main" in archive.read(entrypoint_name).decode()
    with tarfile.open(source) as archive:
        engine_name = next(name for name in archive.getnames() if name.endswith(f"/{PACKAGE}/_audit.py"))
        assert archive.extractfile(engine_name).read() == expected_engine
        license_name = next(name for name in archive.getnames() if name.endswith("/LICENSE"))
        assert archive.extractfile(license_name).read() == expected_license
    # The source tree has no manually maintained third engine copy.
    if repository_source:
        assert not (PROJECT / PACKAGE / "_audit.py").exists()


def test_sdist_rebuild_installed_entrypoints_and_engine_work_outside_repository(archives):
    directory, _wheel, source = archives
    extraction = directory / "independent-source"
    extraction.mkdir()
    with tarfile.open(source) as archive:
        # The local build creates only regular files/directories. Explicit
        # extraction keeps this test compatible with the Python 3.10 baseline.
        for member in archive:
            destination = extraction / member.name
            destination.resolve().relative_to(extraction.resolve())
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                assert member.isfile()
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
    unpacked = next(extraction.iterdir())
    output = directory / "from-sdist"
    execute(["-m", "build", "--wheel", str(unpacked), "--outdir", str(output)], cwd=directory)
    rebuilt = next(output.glob("*.whl"))
    installation = directory / "installation"
    execute(["-m", "pip", "install", "--no-deps", "--target", str(installation), str(rebuilt)], cwd=directory)
    environment = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(installation)}
    assert execute(["-m", PACKAGE, "--version"], cwd=directory, env=environment).stdout.strip() == "2.5.0.dev1"
    console = installation / "bin" / "api-relay-audit-mcp"
    entry = subprocess.run([str(console), "--version"], cwd=directory, env=environment,
                           capture_output=True, text=True, timeout=10)
    assert entry.returncode == 0
    assert entry.stdout.strip() == "2.5.0.dev1"
    help_text = execute([str(installation / PACKAGE / "_audit.py"), "--help"],
                        cwd=directory, env=environment).stdout
    assert "--key-env" in help_text and "--format" in help_text
    # Malformed local configuration fails with the same bounded public error.
    config = directory / "private.json"
    config.write_text(json.dumps({"report_root": str(directory), "secret": "synthetic-private-value"}))
    rejected = subprocess.run([str(console), "--config", str(config)], cwd=directory, env=environment,
                              capture_output=True, text=True, timeout=10)
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert rejected.stderr == "Invalid local connector configuration.\n"


@pytest.mark.anyio
async def test_installed_wheel_uses_bundled_engine_over_real_stdio(archives, tmp_path):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    directory, wheel, _source = archives
    installation = directory / "protocol-installation"
    execute(["-m", "pip", "install", "--no-deps", "--target", str(installation), str(wheel)], cwd=directory)
    secret = "sk-synthetic-installed-package-only"
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            assert self.headers.get("x-api-key") == secret or self.headers.get("Authorization") == "Bearer " + secret
            requests.append(self.path)
            value = ({"content": [{"type": "text", "text": secret}], "usage": {"input_tokens": 8, "output_tokens": 1}}
                     if self.path == "/v1/messages" else
                     {"choices": [{"message": {"content": secret}}], "usage": {"prompt_tokens": 8, "completion_tokens": 1}})
            raw = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    relay = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    config = tmp_path / "connector.json"
    config.write_text(json.dumps({"report_root": str(tmp_path), "targets": {
        "fixture": {"url": f"http://127.0.0.1:{relay.server_port}", "model": "claude-fixture",
                    "key_env": "API_RELAY_AUDIT_INSTALLED_TEST_KEY"}}}))
    parameters = StdioServerParameters(command=sys.executable,
        args=["-m", PACKAGE, "--config", str(config)], cwd=str(directory),
        env={"PYTHONPATH": str(installation), "API_RELAY_AUDIT_INSTALLED_TEST_KEY": secret})
    try:
        async with Client(parameters, read_timeout_seconds=10) as client:
            tools = await client.list_tools()
            assert {tool.name for tool in tools.tools} == {"check_connectivity", "run_audit", "get_audit_result"}
            result = (await client.call_tool("check_connectivity", {"target_id": "fixture"})).structured_content
            assert result["ok"] is True and result["tool_version"] == "v2.5.0"
            assert result["risk_level"] is None and result["coverage"] is None
            assert result["connectivity"] == {"success": True, "successful_formats": ["Anthropic Chat", "OpenAI Chat"]}
            assert secret not in json.dumps(result)
            assert "127.0.0.1" not in json.dumps(result)
        assert requests == ["/v1/messages", "/v1/chat/completions"]
    finally:
        relay.shutdown()
        relay.server_close()


@pytest.fixture
def anyio_backend():
    return "asyncio"
