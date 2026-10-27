"""Behavior of historical website links after authored source moves."""

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _builder():
    spec = importlib.util.spec_from_file_location("legacy_pages", ROOT / "scripts/build-legacy-pages.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inputs(tmp_path):
    manifest = json.loads((ROOT / "docs/site-migration/legacy-paths.json").read_text())
    website = tmp_path / "website"
    for relative in manifest["public_files"]:
        path = website / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("public fixture: " + relative).encode())
    evidence = tmp_path / "registry.json"
    evidence.write_text("[]\n")
    output = tmp_path / "output"
    return manifest, website, evidence, output


def test_all_known_legacy_pages_have_canonical_and_manual_fallback(tmp_path):
    module = _builder()
    manifest, website, evidence, output = _inputs(tmp_path)
    result = module.build(ROOT / "docs/site-migration/legacy-paths.json", website, evidence, output)
    assert result == {"redirect_pages": 11, "public_assets": 3, "evidence_records": 0}
    for page in manifest["pages"]:
        text = (output / page).read_text()
        url = module.canonical_url(page)
        assert f'<link rel="canonical" href="{url}">' in text
        assert 'http-equiv="refresh"' not in text
        assert f'href="{url}"' in text
    assert module.canonical_url("index.html") == "https://apirelayaudit.com/"
    assert module.canonical_url("zh/index.html") == "https://apirelayaudit.com/zh/"
    assert module.canonical_url("myindex.html") == "https://apirelayaudit.com/myindex.html"


def test_browser_redirect_preserves_query_and_fragment_without_changing_origin(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the independent browser-script mechanism test")
    text = _builder().redirect_html("https://apirelayaudit.com/guides/audit-claude-api-relay-safely.html")
    script = re.search(r"<script>\n(.*?)</script>", text, re.S).group(1)
    harness = """const vm = require('node:vm');
let captured;
const window = {location: {hostname: 'toby-bridges.github.io', search: '?from=legacy&next=https%3A%2F%2Fevil.invalid', hash: '#download', replace: x => captured=x}};
vm.runInNewContext(JSON.parse(process.argv[1]), {window, URL});
process.stdout.write(captured);
"""
    result = subprocess.run([node, "-e", harness, json.dumps(script)], capture_output=True, text=True, check=True)
    assert result.stdout == ("https://apirelayaudit.com/guides/audit-claude-api-relay-safely.html"
                             "?from=legacy&next=https%3A%2F%2Fevil.invalid#download")


def test_redirect_does_not_loop_if_artifact_is_accidentally_served_on_canonical_domain():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the independent browser-script mechanism test")
    text = _builder().redirect_html("https://apirelayaudit.com/")
    script = re.search(r"<script>\n(.*?)</script>", text, re.S).group(1)
    harness = """const vm = require('node:vm');
let redirected=false;
const window = {location: {hostname: 'apirelayaudit.com', search: '?x=1', hash: '#x', replace: () => redirected=true}};
vm.runInNewContext(JSON.parse(process.argv[1]), {window, URL});
process.stdout.write(JSON.stringify(redirected));
"""
    result = subprocess.run([node, "-e", harness, json.dumps(script)], capture_output=True, text=True, check=True)
    assert result.stdout == "false"


def test_legacy_assets_and_public_registry_remain_available(tmp_path):
    module = _builder()
    manifest, website, evidence, output = _inputs(tmp_path)
    module.build(ROOT / "docs/site-migration/legacy-paths.json", website, evidence, output)
    for relative in manifest["public_files"]:
        assert (output / relative).read_bytes() == (website / relative).read_bytes()
    assert json.loads((output / "data/evidence.json").read_text()) == []
    assert "https://apirelayaudit.com/sitemap.xml" in (output / "robots.txt").read_text()


@pytest.mark.parametrize("bad_path", ["../outside.html", "/absolute.html", "a/../b.html", "a\\b.html", "%2e%2e/file.html", "x.html?next=evil"])
def test_manifest_rejects_paths_that_escape_public_url_boundary(tmp_path, bad_path):
    module = _builder()
    manifest, _website, _evidence, _output = _inputs(tmp_path)
    manifest["pages"].append(bad_path)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        module.load_manifest(path)


def test_builder_refuses_non_array_evidence_before_writing(tmp_path):
    module = _builder()
    _manifest, website, evidence, output = _inputs(tmp_path)
    evidence.write_text('{"unexpected": "object"}')
    with pytest.raises(ValueError, match="JSON array"):
        module.build(ROOT / "docs/site-migration/legacy-paths.json", website, evidence, output)
    assert not output.exists()


def test_registry_is_public_tool_source_not_website_source():
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    import process_submission
    assert process_submission.EVIDENCE_JSON == ROOT / "evidence/registry.json"
    assert isinstance(json.loads((ROOT / "evidence/registry.json").read_text()), list)


def test_legacy_workflow_refuses_deployment_until_custom_domain_is_released(tmp_path):
    workflow = (ROOT / ".github/workflows/pages.yml").read_text()
    start = workflow.index("      - name: Require custom domain to be moved")
    end = workflow.index("      - uses: actions/configure-pages", start)
    block = workflow[start:end].split("        run: |\n", 1)[1]
    commands = "\n".join(line.removeprefix("          ") for line in block.splitlines())
    commands = commands.replace("${{ github.repository }}", "example/tool")
    for value, expected in [("apirelayaudit.com", 1), ("", 0)]:
        script = 'gh() { printf "%s" "$BOUND_DOMAIN"; }\n' + commands
        result = subprocess.run(["bash", "-c", script], env={"BOUND_DOMAIN": value}, capture_output=True, text=True)
        assert result.returncode == expected, result.stderr
