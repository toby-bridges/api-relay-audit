#!/usr/bin/env python3
"""Verify standalone release artifact provenance.

The release contract is intentionally strict: the committed ``audit.py`` at a
release tag, the generated standalone artifact for the checked-out source, and
the GitHub Release asset must be the same bytes. This script is designed for
the draft-release workflow, but it is also useful as a maintainer post-release
check.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_STANDALONE = REPO_ROOT / "scripts" / "build-standalone.py"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_sha256_file(text: str) -> str:
    """Return the first SHA-256 digest from a sha256sum-style file."""
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not match:
        raise ValueError("sha256 file does not contain a 64-character digest")
    return match.group(1).lower()


def run(args: list[str], *, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def git_show_bytes(ref: str, path: str) -> bytes:
    return run(["git", "show", f"{ref}:{path}"]).stdout


def generated_standalone_bytes() -> bytes:
    spec = importlib.util.spec_from_file_location("build_standalone", BUILD_STANDALONE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BUILD_STANDALONE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.build_text().encode("utf-8")


def fail(message: str) -> None:
    raise SystemExit(message)


def require_equal(left_label: str, left: bytes, right_label: str, right: bytes) -> None:
    if left == right:
        print(f"OK: {left_label} == {right_label} ({sha256_bytes(left)})")
        return
    fail(
        f"release artifact mismatch: {left_label} ({sha256_bytes(left)}) "
        f"!= {right_label} ({sha256_bytes(right)})"
    )


def verify_local(source_ref: str) -> bytes:
    source_bytes = git_show_bytes(source_ref, "audit.py")
    head_bytes = git_show_bytes("HEAD", "audit.py")
    generated_bytes = generated_standalone_bytes()

    require_equal(f"{source_ref}:audit.py", source_bytes, "HEAD:audit.py", head_bytes)
    require_equal("HEAD:audit.py", head_bytes, "generated standalone", generated_bytes)
    return source_bytes


def download_release_assets(tag: str, repo: str | None, dest: Path) -> tuple[Path, Path]:
    cmd = ["gh", "release", "download", tag, "--pattern", "audit.py*", "--dir", str(dest)]
    if repo:
        cmd.extend(["--repo", repo])
    run(cmd)

    audit_asset = dest / "audit.py"
    sha_asset = dest / "audit.py.sha256"
    if not audit_asset.is_file():
        fail(f"release asset missing: {audit_asset.name}")
    if not sha_asset.is_file():
        fail(f"release asset missing: {sha_asset.name}")
    return audit_asset, sha_asset


def verify_release_assets(
    tag: str,
    expected_bytes: bytes,
    repo: str | None,
    source_ref: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="api-relay-audit-release-") as tmp:
        audit_asset, sha_asset = download_release_assets(tag, repo, Path(tmp))
        asset_bytes = audit_asset.read_bytes()
        published_digest = parse_sha256_file(sha_asset.read_text(encoding="utf-8"))
        actual_digest = sha256_bytes(asset_bytes)

        if published_digest != actual_digest:
            fail(
                "release checksum mismatch: audit.py.sha256 "
                f"({published_digest}) != audit.py asset ({actual_digest})"
            )
        print(f"OK: audit.py.sha256 matches release asset ({actual_digest})")
        require_equal(
            "release asset audit.py",
            asset_bytes,
            f"{source_ref}:audit.py",
            expected_bytes,
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify that a release audit.py asset matches the tagged generated artifact."
    )
    parser.add_argument("--tag", required=True, help="Release tag, e.g. v2.3.1")
    parser.add_argument(
        "--source-ref",
        default=None,
        help=(
            "Git ref that owns the expected audit.py bytes. Defaults to --tag. "
            "Draft-release workflows should pass the exact release commit SHA."
        ),
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="GitHub repository for gh release download, e.g. owner/repo.",
    )
    parser.add_argument(
        "--skip-release-download",
        action="store_true",
        help="Only verify tag, working tree, and generated standalone bytes.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source_ref = args.source_ref or args.tag
    expected_bytes = verify_local(source_ref)
    if not args.skip_release_download:
        verify_release_assets(args.tag, expected_bytes, args.repo, source_ref)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
