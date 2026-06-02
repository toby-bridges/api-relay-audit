import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DOC = REPO_ROOT / "docs" / "report-artifact-schema.md"
FIXTURE_JSON = REPO_ROOT / "docs" / "examples" / "sanitized-audit-report.fixture.json"
FIXTURE_MD = REPO_ROOT / "docs" / "examples" / "sanitized-audit-report.md"


REQUIRED_FIELDS = {
    "schema_version",
    "tool_version",
    "profile",
    "target_host_redacted",
    "overall_rating",
    "generated_at",
    "fixture_source",
    "steps",
    "redaction_notes",
    "submission_compatibility",
}

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{8,}", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bya29\.[0-9A-Za-z_-]+\b"),
]


def _fixture():
    return json.loads(FIXTURE_JSON.read_text(encoding="utf-8"))


def test_fixture_json_matches_schema_core_fields():
    fixture = _fixture()
    assert REQUIRED_FIELDS <= set(fixture)
    assert fixture["schema_version"] == "report-artifact-v0.1"
    assert fixture["tool_version"] == "v2.3"
    assert fixture["profile"] in {"general", "web3", "full"}
    assert fixture["target_host_redacted"] == "example.invalid"
    assert fixture["overall_rating"] in {"LOW", "MEDIUM", "HIGH"}
    assert fixture["submission_compatibility"] == {
        "intended_for_future_submission_page": True,
        "public_safe_example": True,
    }


def test_schema_doc_mentions_required_fields():
    schema_text = SCHEMA_DOC.read_text(encoding="utf-8")
    for field in REQUIRED_FIELDS:
        assert field in schema_text


def test_fixture_steps_cover_report_surface_and_verdicts():
    fixture = _fixture()
    steps = fixture["steps"]
    assert len(steps) == 14
    assert {step["step_number"] for step in steps} == set(range(1, 15))
    assert {step["verdict"] for step in steps} >= {
        "clean",
        "anomaly",
        "inconclusive",
        "informational",
    }
    assert any("Web3" in step["step_name"] for step in steps)
    assert any("Tool-call rewriting" == step["step_name"] for step in steps)
    assert any("SSE" in step["step_name"] for step in steps)


def test_markdown_and_json_core_fields_match():
    fixture = _fixture()
    markdown = FIXTURE_MD.read_text(encoding="utf-8")
    for value in [
        fixture["schema_version"],
        fixture["tool_version"],
        fixture["profile"],
        fixture["target_host_redacted"],
        fixture["overall_rating"],
        fixture["generated_at"],
    ]:
        assert value in markdown
    assert "not a real relay result" in markdown
    assert "future submission" in markdown.lower()


def test_example_report_is_public_safe():
    combined = "\n".join(
        [
            SCHEMA_DOC.read_text(encoding="utf-8"),
            FIXTURE_JSON.read_text(encoding="utf-8"),
            FIXTURE_MD.read_text(encoding="utf-8"),
        ]
    )
    assert "example.invalid" in combined
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(combined), pattern.pattern
    forbidden_phrases = [
        "recommended relay",
        "safe relay provider",
        "best relay provider",
    ]
    lower = combined.lower()
    for phrase in forbidden_phrases:
        assert phrase not in lower
