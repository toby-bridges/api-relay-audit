"""Regression checks for VERSION-derived release surfaces."""

import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parent.parent
SYNC_VERSION = REPO_ROOT / "scripts" / "sync-version.py"
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit.py"
STANDALONE_AUDIT = REPO_ROOT / "audit.py"


def _load_sync_version_module():
    spec = importlib.util.spec_from_file_location("sync_version", SYNC_VERSION)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_module(path: Path, name: str):
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_semver_display_version_derivation():
    sync_version = _load_sync_version_module()

    minor_release = sync_version.parse_version("2.3.0")
    assert minor_release.full == "2.3.0"
    assert minor_release.tag == "v2.3.0"
    assert minor_release.display == "v2.3"

    patch_release = sync_version.parse_version("2.3.1")
    assert patch_release.full == "2.3.1"
    assert patch_release.tag == "v2.3.1"
    assert patch_release.display == "v2.3.1"


def test_invalid_version_rejected():
    sync_version = _load_sync_version_module()

    for value in ["v2.3.0", "2.3", "2.3.0-beta", "02.3.0"]:
        try:
            sync_version.parse_version(value)
        except ValueError:
            continue
        raise AssertionError(f"invalid version accepted: {value}")


def test_current_release_notes_path_exists():
    sync_version = _load_sync_version_module()
    version = sync_version.version_from_file()
    expected_name = (
        f"v{version.major}.{version.minor}.md"
        if version.patch == 0
        else f"v{version.full}.md"
    )

    assert version.release_notes_path.name == expected_name
    assert version.release_notes_path.exists()


def test_canonical_version_surfaces_are_synced():
    result = subprocess.run(
        [sys.executable, "scripts/sync-version.py", "--check"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr


def test_generated_standalone_uses_display_version():
    version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    major, minor, patch = (int(part) for part in version.split("."))
    display = f"v{major}.{minor}" if patch == 0 else f"v{version}"

    standalone = STANDALONE_AUDIT.read_text(encoding="utf-8")
    modular = AUDIT_SCRIPT.read_text(encoding="utf-8")
    assert f"API Relay Security Audit Tool {display}" in modular
    assert f"API Relay Security Audit Tool {display} --- Standalone Edition" in standalone
    assert f'TOOL_VERSION_FALLBACK = "{version}"' in modular
    assert f'TOOL_VERSION_FALLBACK = "{version}"' in standalone


def test_standalone_metadata_ignores_arbitrary_neighbor_version(tmp_path):
    module = _load_module(STANDALONE_AUDIT, "standalone_audit_metadata_boundary")
    downstream = tmp_path / "downstream"
    downstream.mkdir()
    (downstream / "VERSION").write_text("9.9.9\n", encoding="utf-8")

    module.__file__ = str(downstream / "audit.py")

    assert module._tool_version() == module.TOOL_VERSION_FALLBACK


def test_standalone_metadata_does_not_probe_downstream_git_repo(tmp_path):
    module = _load_module(STANDALONE_AUDIT, "standalone_audit_commit_boundary")
    downstream = tmp_path / "downstream"
    downstream.mkdir()
    (downstream / ".git").mkdir()
    (downstream / "VERSION").write_text("9.9.9\n", encoding="utf-8")

    module.__file__ = str(downstream / "audit.py")

    with patch.object(module.subprocess, "run") as run:
        assert module._tool_commit_from_checkout() == ""
    run.assert_not_called()


def test_modular_metadata_reads_version_only_for_project_checkout_shape(tmp_path):
    module = _load_module(AUDIT_SCRIPT, "modular_audit_metadata_boundary")
    checkout = tmp_path / "api-relay-audit"
    (checkout / "scripts").mkdir(parents=True)
    (checkout / "api_relay_audit").mkdir()
    (checkout / "VERSION").write_text("3.4.5\n", encoding="utf-8")
    (checkout / "scripts" / "build-standalone.py").write_text("", encoding="utf-8")
    (checkout / "api_relay_audit" / "reporter.py").write_text("", encoding="utf-8")

    module.__file__ = str(checkout / "scripts" / "audit.py")

    assert module._tool_version() == "3.4.5"
