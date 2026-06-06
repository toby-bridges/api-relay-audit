#!/usr/bin/env python3
"""Sync release-version surfaces from the root VERSION file.

Default mode rewrites derived version surfaces. ``--check`` verifies the same
surfaces without writing. The root VERSION file is the only manual version
source for release preparation.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = REPO_ROOT / "VERSION"


SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
)
DISPLAY_VERSION_RE = r"v\d+\.\d+(?:\.\d+)?"
FULL_VERSION_RE = r"\d+\.\d+\.\d+"
RAW_AUDIT_URL_RE = (
    r"https://raw\.githubusercontent\.com/toby-bridges/api-relay-audit/"
    r"(?!\$\{AUDIT_SCRIPT_REF\})[^/]+/audit\.py"
)


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int

    @property
    def full(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def tag(self) -> str:
        return f"v{self.full}"

    @property
    def display(self) -> str:
        if self.patch == 0:
            return f"v{self.major}.{self.minor}"
        return self.tag

    @property
    def release_notes_path(self) -> Path:
        return REPO_ROOT / "docs" / "releases" / f"{self.display}.md"


@dataclass(frozen=True)
class PlannedFile:
    path: Path
    expected: str


def parse_version(text: str) -> Version:
    value = text.strip()
    match = SEMVER_RE.fullmatch(value)
    if not match:
        raise ValueError(
            f"VERSION must be MAJOR.MINOR.PATCH SemVer without prefix: {value!r}"
        )
    major, minor, patch = (int(part) for part in match.groups())
    return Version(major, minor, patch)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def version_from_file() -> Version:
    return parse_version(read_text(VERSION_FILE))


def replace_regex(
    text: str,
    pattern: str,
    replacement: str,
    path: Path,
    *,
    required: bool = True,
) -> str:
    updated, count = re.subn(
        pattern,
        lambda _match: replacement,
        text,
        flags=re.MULTILINE,
    )
    if required and count == 0:
        rel = path.relative_to(REPO_ROOT)
        raise ValueError(f"{rel}: pattern not found: {pattern}")
    return updated


def sync_audit_script(version: Version, path: Path) -> str:
    text = read_text(path)
    return replace_regex(
        text,
        rf"API Relay Security Audit Tool {DISPLAY_VERSION_RE}",
        f"API Relay Security Audit Tool {version.display}",
        path,
    )


def sync_build_standalone(version: Version, path: Path) -> str:
    text = read_text(path)
    if "def display_version_from_file()" in text and '"VERSION"' in text:
        return text
    return replace_regex(
        text,
        rf"API Relay Security Audit Tool {DISPLAY_VERSION_RE} --- Standalone Edition",
        f"API Relay Security Audit Tool {version.display} --- Standalone Edition",
        path,
    )


def sync_package_init(version: Version, path: Path) -> str:
    text = read_text(path)
    return replace_regex(
        text,
        rf'^__version__ = "{FULL_VERSION_RE}"$',
        f'__version__ = "{version.full}"',
        path,
    )


def sync_skill(version: Version, path: Path) -> str:
    text = read_text(path)
    text = replace_regex(
        text,
        rf"^version:\s+{FULL_VERSION_RE}$",
        f"version: {version.full}",
        path,
    )
    text = replace_regex(
        text,
        r"^AUDIT_SCRIPT_REF=[^\s]+$",
        f"AUDIT_SCRIPT_REF={version.tag}",
        path,
    )
    text = replace_regex(
        text,
        RAW_AUDIT_URL_RE,
        f"https://raw.githubusercontent.com/toby-bridges/api-relay-audit/{version.tag}/audit.py",
        path,
        required=False,
    )
    return text


def sync_skill_distribution(version: Version, path: Path) -> str:
    text = read_text(path)
    text = replace_regex(
        text,
        rf"- version `{FULL_VERSION_RE}`",
        f"- version `{version.full}`",
        path,
    )
    text = replace_regex(
        text,
        r"- audit script ref `[^`]+`",
        f"- audit script ref `{version.tag}`",
        path,
    )
    text = replace_regex(
        text,
        rf"--version {FULL_VERSION_RE} \\",
        f"--version {version.full} \\",
        path,
    )
    return text


def sync_citation(version: Version, path: Path) -> str:
    text = read_text(path)
    return replace_regex(
        text,
        r'^version: "\d+\.\d+(?:\.\d+)?"$',
        f'version: "{version.full}"',
        path,
    )


def sync_release_notes(version: Version, path: Path) -> str:
    if not path.exists():
        rel = path.relative_to(REPO_ROOT)
        raise FileNotFoundError(
            f"{rel} is required for release {version.tag}; create it before syncing"
        )
    text = read_text(path)
    text = replace_regex(
        text,
        rf"^# {DISPLAY_VERSION_RE}:",
        f"# {version.display}:",
        path,
    )
    text = replace_regex(
        text,
        rf"API Relay Audit {DISPLAY_VERSION_RE}",
        f"API Relay Audit {version.display}",
        path,
    )
    text = replace_regex(
        text,
        r"^AUDIT_SCRIPT_REF=[^\s]+$",
        f"AUDIT_SCRIPT_REF={version.tag}",
        path,
    )
    return text


def sync_python_explanation(version: Version, path: Path) -> str:
    text = read_text(path)
    return replace_regex(
        text,
        rf'__version__ = "{FULL_VERSION_RE}"',
        f'__version__ = "{version.full}"',
        path,
    )


def planned_files(version: Version) -> list[PlannedFile]:
    audit_script = REPO_ROOT / "scripts" / "audit.py"
    build_standalone = REPO_ROOT / "scripts" / "build-standalone.py"
    package_init = REPO_ROOT / "api_relay_audit" / "__init__.py"
    root_skill = REPO_ROOT / "SKILL.md"
    hermes_skill = REPO_ROOT / "skills" / "api-relay-audit" / "SKILL.md"
    skill_distribution = REPO_ROOT / "docs" / "skill-distribution.md"
    python_explanation = REPO_ROOT / "docs" / "python-code-explanation-zh.md"
    citation = REPO_ROOT / "CITATION.cff"

    return [
        PlannedFile(audit_script, sync_audit_script(version, audit_script)),
        PlannedFile(build_standalone, sync_build_standalone(version, build_standalone)),
        PlannedFile(package_init, sync_package_init(version, package_init)),
        PlannedFile(root_skill, sync_skill(version, root_skill)),
        PlannedFile(hermes_skill, sync_skill(version, hermes_skill)),
        PlannedFile(
            skill_distribution,
            sync_skill_distribution(version, skill_distribution),
        ),
        PlannedFile(
            python_explanation,
            sync_python_explanation(version, python_explanation),
        ),
        PlannedFile(citation, sync_citation(version, citation)),
        PlannedFile(
            version.release_notes_path,
            sync_release_notes(version, version.release_notes_path),
        ),
    ]


def diff_text(path: Path, current: str, expected: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            current.splitlines(),
            expected.splitlines(),
            fromfile=f"{path.relative_to(REPO_ROOT)} (current)",
            tofile=f"{path.relative_to(REPO_ROOT)} (expected)",
            lineterm="",
            n=3,
        )
    )


def check(version: Version) -> int:
    failures = []
    for planned in planned_files(version):
        current = read_text(planned.path)
        if current == planned.expected:
            continue
        failures.append(diff_text(planned.path, current, planned.expected))

    if failures:
        print("Version drift detected. Regenerate with: python3 scripts/sync-version.py", file=sys.stderr)
        print("\n\n".join(failures), file=sys.stderr)
        return 1

    print(f"Version sync check passed for {version.tag}.")
    return 0


def write(version: Version) -> int:
    changed = []
    for planned in planned_files(version):
        current = read_text(planned.path)
        if current == planned.expected:
            continue
        planned.path.write_text(planned.expected, encoding="utf-8")
        changed.append(planned.path.relative_to(REPO_ROOT))

    if changed:
        for path in changed:
            print(f"Wrote {path}")
    else:
        print(f"Version surfaces already synced for {version.tag}.")
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Sync or check versioned release surfaces from VERSION."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if any derived version surface is stale.",
    )
    parser.add_argument(
        "--show",
        choices=["full", "display", "tag", "release-notes"],
        help="Print a derived version value and exit without writing.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        version = version_from_file()
        if args.show:
            values = {
                "full": version.full,
                "display": version.display,
                "tag": version.tag,
                "release-notes": str(version.release_notes_path.relative_to(REPO_ROOT)),
            }
            print(values[args.show])
            return 0
        if args.check:
            return check(version)
        return write(version)
    except Exception as exc:
        print(f"sync-version.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
