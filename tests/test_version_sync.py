"""Regression checks for VERSION-derived release surfaces."""

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SYNC_VERSION = REPO_ROOT / "scripts" / "sync-version.py"


def _load_sync_version_module():
    spec = importlib.util.spec_from_file_location("sync_version", SYNC_VERSION)
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

    standalone = (REPO_ROOT / "audit.py").read_text(encoding="utf-8")
    modular = (REPO_ROOT / "scripts" / "audit.py").read_text(encoding="utf-8")
    assert f"API Relay Security Audit Tool {display}" in modular
    assert f"API Relay Security Audit Tool {display} --- Standalone Edition" in standalone
