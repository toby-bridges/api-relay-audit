import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-release-artifact.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_release_artifact", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_parse_sha256_file_accepts_sha256sum_format():
    mod = load_module()
    digest = "a" * 64

    assert mod.parse_sha256_file(f"{digest}  audit.py\n") == digest


def test_parse_sha256_file_rejects_missing_digest():
    mod = load_module()

    with pytest.raises(ValueError):
        mod.parse_sha256_file("not-a-digest  audit.py\n")


def test_require_equal_reports_hashes_on_mismatch():
    mod = load_module()

    with pytest.raises(SystemExit) as exc:
        mod.require_equal("left", b"one", "right", b"two")

    message = str(exc.value)
    assert "release artifact mismatch" in message
    assert mod.sha256_bytes(b"one") in message
    assert mod.sha256_bytes(b"two") in message


def test_generated_standalone_bytes_imports_builder():
    mod = load_module()

    data = mod.generated_standalone_bytes()

    assert data.startswith(b"#!/usr/bin/env python")
    assert b"GENERATED STANDALONE ARTIFACT" in data


def test_verify_local_uses_explicit_source_ref(monkeypatch):
    mod = load_module()
    calls = []

    def fake_show(ref, path):
        calls.append((ref, path))
        return b"same"

    monkeypatch.setattr(mod, "git_show_bytes", fake_show)
    monkeypatch.setattr(mod, "generated_standalone_bytes", lambda: b"same")

    assert mod.verify_local("deadbeef") == b"same"
    assert calls == [("deadbeef", "audit.py"), ("HEAD", "audit.py")]


def test_source_ref_defaults_to_tag():
    mod = load_module()

    args = mod.parse_args(["--tag", "v2.3.1", "--skip-release-download"])
    assert args.source_ref is None


def test_workflow_has_bounded_draft_recovery():
    workflow = (ROOT / ".github" / "workflows" / "release-draft.yml").read_text(
        encoding="utf-8"
    )

    assert "release already published" in workflow
    assert "draft target mismatch" in workflow
    assert "tag exists without a release" in workflow
    assert 'gh release upload "${TAG}"' in workflow
    assert "--clobber" in workflow
    assert '--source-ref "${GITHUB_SHA}"' in workflow
