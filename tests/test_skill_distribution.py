"""Regression checks for OpenClaw / Hermes skill distribution contracts."""

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT_SKILL = REPO_ROOT / "SKILL.md"
HERMES_SKILL = REPO_ROOT / "skills" / "api-relay-audit" / "SKILL.md"
SKILL_DISTRIBUTION_DOC = REPO_ROOT / "docs" / "skill-distribution.md"
QUERY_FAMILY_DOC = REPO_ROOT / "docs" / "query-families.md"
HOMEPAGE = REPO_ROOT / "web" / "index.html"


def _read(path):
    return path.read_text(encoding="utf-8")


def _version_parts():
    version = _read(REPO_ROOT / "VERSION").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version)
    major, minor, patch = (int(part) for part in version.split("."))
    return version, major, minor, patch


VERSION, VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH = _version_parts()
VERSION_TAG = f"v{VERSION}"
DISPLAY_VERSION = (
    f"v{VERSION_MAJOR}.{VERSION_MINOR}"
    if VERSION_PATCH == 0
    else VERSION_TAG
)
RELEASE_DRAFT = REPO_ROOT / "docs" / "releases" / f"{DISPLAY_VERSION}.md"


def _frontmatter(path):
    text = _read(path)
    assert text.startswith("---\n")
    _head, fm, _body = text.split("---", 2)
    return fm.strip()


def _has_line(text, pattern):
    return re.search(pattern, text, re.MULTILINE) is not None


def test_skill_frontmatter_declares_required_distribution_fields():
    root = _frontmatter(ROOT_SKILL)
    assert _has_line(root, r"^name:\s+api-relay-audit$")
    assert _has_line(root, r"^description:\s+.+OpenClaw")
    assert _has_line(root, rf"^version:\s+{re.escape(VERSION)}$")
    for field in ["metadata:", "openclaw:", "requires:", "bins:", "anyBins:", "envVars:", "skillKey: api-relay-audit"]:
        assert field in root

    hermes = _frontmatter(HERMES_SKILL)
    assert _has_line(hermes, r"^name:\s+api-relay-audit$")
    assert _has_line(hermes, r"^description:\s+Use when")
    assert _has_line(hermes, rf"^version:\s+{re.escape(VERSION)}$")
    assert _has_line(hermes, r"^platforms:\s+\[linux,\s+macos,\s+windows\]$")
    for field in [
        "author: Toby Bridges",
        "license: AGPL-3.0-only",
        "metadata:",
        "hermes:",
        "tags:",
        "required_environment_variables:",
        "API_RELAY_AUDIT_KEY",
    ]:
        assert field in hermes


def test_versioned_skill_artifacts_pin_audit_script_download():
    assert RELEASE_DRAFT.exists()
    for path in [ROOT_SKILL, HERMES_SKILL, RELEASE_DRAFT]:
        text = _read(path)
        assert VERSION_TAG in text
        assert "master/audit.py" not in text

    distribution_doc = _read(SKILL_DISTRIBUTION_DOC)
    assert VERSION_TAG in distribution_doc
    assert "Do not publish a\nversioned skill that downloads mutable `master/audit.py`" in distribution_doc


def test_skill_surfaces_do_not_regress_to_13_step_copy():
    surfaces = [
        REPO_ROOT / "README.md",
        ROOT_SKILL,
        HERMES_SKILL,
        SKILL_DISTRIBUTION_DOC,
        RELEASE_DRAFT,
        REPO_ROOT / "web" / "guides" / "openclaw-hermes-skill-api-relay-audit.html",
        HOMEPAGE,
        REPO_ROOT / "web" / "zh" / "index.html",
    ]
    forbidden = ["13-step", "13 steps", "13 步", "Steps 1-10"]
    for path in surfaces:
        text = _read(path)
        for phrase in forbidden:
            assert phrase not in text, f"{path} contains stale phrase {phrase!r}"


def test_homepage_agent_tab_matches_openclaw_hermes_contract():
    text = _read(HOMEPAGE)
    assert "OpenClaw or Hermes skill" in text
    assert "hermes skills install toby-bridges/api-relay-audit/skills/api-relay-audit" in text
    assert "API_RELAY_AUDIT_KEY" in text
    assert "Claude Code Skill" not in text
    assert "~/.claude/commands" not in text
    assert "my key is sk-xxx" not in text


def test_homepage_channel_classifier_is_not_marked_future():
    text = _read(HOMEPAGE)
    assert "Upstream Channel Classifier" in text
    assert "cmp_channel:\"Upstream Channel Classifier\"" in text
    assert "cmp_channel:\"上游通道分类\"" in text
    assert "Channel Fingerprint" not in text
    assert '<td class="soon">Soon</td>' not in text


def test_growth_surfaces_keep_query_families_separate():
    surfaces = [
        REPO_ROOT / "README.md",
        HOMEPAGE,
        REPO_ROOT / "web" / "zh" / "index.html",
        ROOT_SKILL,
        HERMES_SKILL,
        SKILL_DISTRIBUTION_DOC,
        QUERY_FAMILY_DOC,
    ]
    required_families = [
        "API relay audit",
        "Prompt injection audit",
        "Model substitution signals",
        "Web3 relay audit",
    ]
    for path in surfaces:
        text = _read(path).lower()
        for family in required_families:
            assert family.lower() in text, f"{path} is missing {family!r}"


def test_growth_surfaces_preserve_current_audit_contract():
    surfaces = [REPO_ROOT / "README.md", HOMEPAGE, ROOT_SKILL, HERMES_SKILL]
    for path in surfaces:
        text = _read(path)
        assert "API Relay Audit" in text
        assert "14-step" in text or "14 steps" in text or "14 步" in text
        for profile in ["general", "web3", "full"]:
            assert profile in text


def test_web3_relay_audit_is_profile_gated():
    surfaces = [REPO_ROOT / "README.md", HOMEPAGE, QUERY_FAMILY_DOC, ROOT_SKILL, HERMES_SKILL]
    for path in surfaces:
        text = _read(path)
        assert "Web3 relay audit" in text
        assert "--profile web3" in text or "`web3`" in text or "profile web3" in text
        assert "Step 11" in text
        assert "profile-gated" in text


def test_model_substitution_copy_requires_corroboration():
    surfaces = [REPO_ROOT / "README.md", HOMEPAGE, QUERY_FAMILY_DOC, ROOT_SKILL, HERMES_SKILL]
    for path in surfaces:
        text = _read(path)
        assert "model substitution" in text.lower()
        assert "signals" in text.lower()
        assert "standalone" in text.lower() or "单独证明" in text
        assert "provider proof" in text.lower() or "provider-level proof" in text.lower() or "provider 替换" in text


def test_root_skill_secret_handling_prefers_secure_environment():
    text = _read(ROOT_SKILL)
    assert "secure environment" in text
    assert "API_RELAY_AUDIT_KEY" in text
    assert "The agent may also ask the user directly" not in text
    assert "avoid repeating the raw key in chat" in text


def test_hermes_skill_supports_windows_git_bash_contract():
    text = _read(HERMES_SKILL)
    frontmatter = _frontmatter(HERMES_SKILL)
    assert "windows" in frontmatter
    assert "Git Bash" in text
    assert "PowerShell" in text
