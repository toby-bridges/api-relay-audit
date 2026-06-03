"""Regression checks for OpenClaw / Hermes skill distribution contracts."""

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT_SKILL = REPO_ROOT / "SKILL.md"
HERMES_SKILL = REPO_ROOT / "skills" / "api-relay-audit" / "SKILL.md"
RELEASE_DRAFT = REPO_ROOT / "docs" / "releases" / "v2.3.md"
SKILL_DISTRIBUTION_DOC = REPO_ROOT / "docs" / "skill-distribution.md"
HOMEPAGE = REPO_ROOT / "web" / "index.html"

AUDIT_SCRIPT_REF = "fa12ae8513ef77c13c4cd8227a47e9121a257504"


def _read(path):
    return path.read_text(encoding="utf-8")


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
    assert _has_line(root, r"^version:\s+2\.3\.0$")
    for field in ["metadata:", "openclaw:", "requires:", "bins:", "anyBins:", "envVars:", "skillKey: api-relay-audit"]:
        assert field in root

    hermes = _frontmatter(HERMES_SKILL)
    assert _has_line(hermes, r"^name:\s+api-relay-audit$")
    assert _has_line(hermes, r"^description:\s+Use when")
    assert _has_line(hermes, r"^version:\s+2\.3\.0$")
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
    for path in [ROOT_SKILL, HERMES_SKILL, RELEASE_DRAFT]:
        text = _read(path)
        assert AUDIT_SCRIPT_REF in text
        assert "master/audit.py" not in text

    distribution_doc = _read(SKILL_DISTRIBUTION_DOC)
    assert AUDIT_SCRIPT_REF in distribution_doc
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


def test_root_skill_secret_handling_prefers_secure_environment():
    text = _read(ROOT_SKILL)
    assert "secure environment" in text
    assert "API_RELAY_AUDIT_KEY" in text
    assert "The agent may also ask the user directly" not in text
    assert "avoid repeating the raw key in chat" in text
