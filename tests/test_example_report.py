import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DOC = REPO_ROOT / "docs" / "report-artifact-schema.md"
FIXTURE_JSON = REPO_ROOT / "docs" / "examples" / "sanitized-audit-report.fixture.json"
FIXTURE_MD = REPO_ROOT / "docs" / "examples" / "sanitized-audit-report.md"
README = REPO_ROOT / "README.md"
GUIDE = REPO_ROOT / "web" / "guides" / "audit-claude-api-relay-safely.html"


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

STEP_REQUIRED_FIELDS = {
    "step_number",
    "step_name",
    "step_status",
    "verdict",
    "severity",
    "summary",
    "evidence_redacted",
}

STEP_STATUSES = {"run", "skipped", "profile_gated", "not_applicable"}
VERDICTS = {"clean", "anomaly", "inconclusive", "informational"}
SEVERITIES = {"none", "low", "medium", "high"}

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{8,}", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bya29\.[0-9A-Za-z_-]+\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"[?&]key=[A-Za-z0-9_-]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:postgres|postgresql|mysql|mongodb)://[^\s)]+", re.IGNORECASE),
    re.compile(r"\b[A-Z][A-Z0-9_]{2,}_KEY\s*="),
    re.compile(r"(?<!redacted)/Users/[^\s)]+"),
    re.compile(r"(?<!redacted)/home/[^\s)]+"),
    re.compile(r"C:\\Users\\[^\s)]+", re.IGNORECASE),
    re.compile(r"\bapi\.(?:openai|anthropic)\.com\b", re.IGNORECASE),
]


def _fixture():
    return json.loads(FIXTURE_JSON.read_text(encoding="utf-8"))


def _markdown():
    return FIXTURE_MD.read_text(encoding="utf-8")


def _strip_code(value):
    value = value.strip()
    if value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value.replace("`", "")


def _step_rows(markdown):
    rows = {}
    for line in markdown.splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or cells[0] in {"Step", "---"}:
            continue
        if len(cells) != 6:
            continue
        step_number = int(cells[0])
        rows[step_number] = {
            "step_name": cells[1],
            "step_status": _strip_code(cells[2]),
            "verdict": _strip_code(cells[3]),
            "severity": _strip_code(cells[4]),
            "summary": _strip_code(cells[5]),
        }
    return rows


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
    normalized = re.sub(r"\s+", " ", schema_text)
    for field in REQUIRED_FIELDS:
        assert field in schema_text
    for field in STEP_REQUIRED_FIELDS:
        assert field in schema_text
    assert "No backward compatibility or CLI JSON output is promised" in normalized
    assert "skipped/profile-gated steps must not be rendered as clean" in schema_text


def test_fixture_steps_cover_report_surface_and_verdicts():
    fixture = _fixture()
    steps = fixture["steps"]
    assert len(steps) == 14
    assert {step["step_number"] for step in steps} == set(range(1, 15))
    for step in steps:
        assert STEP_REQUIRED_FIELDS <= set(step)
        assert step["step_status"] in STEP_STATUSES
        assert step["verdict"] in VERDICTS
        assert step["severity"] in SEVERITIES
    assert any("Web3" in step["step_name"] for step in steps)
    assert any("Tool-call rewriting" == step["step_name"] for step in steps)
    assert any("SSE" in step["step_name"] for step in steps)


def test_markdown_and_json_core_fields_match():
    fixture = _fixture()
    markdown = _markdown()
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


def test_markdown_step_table_matches_fixture_json():
    fixture = _fixture()
    rows = _step_rows(_markdown())
    assert set(rows) == set(range(1, 15))
    for step in fixture["steps"]:
        row = rows[step["step_number"]]
        assert row["step_name"] == step["step_name"]
        assert row["step_status"] == step["step_status"]
        assert row["verdict"] == step["verdict"]
        assert row["severity"] == step["severity"]
        assert row["summary"] == step["summary"]


def test_markdown_does_not_duplicate_numbered_step_headings():
    markdown = _markdown()
    numbered_headings = re.findall(r"^##\s+(\d+)\.", markdown, re.MULTILINE)
    assert len(numbered_headings) == len(set(numbered_headings))


def test_public_links_point_to_schema_backed_example():
    for path in [README, GUIDE]:
        text = path.read_text(encoding="utf-8")
        assert "docs/examples/sanitized-audit-report.md" in text
        assert "docs/example-audit-report.md" not in text


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
        "low risk",
        "recommended relay",
        "safe to use",
        "safe relay",
        "safe relay provider",
        "best relay provider",
        "approved relay",
        "certified relay",
        "verified safe",
        "clean result",
    ]
    lower = combined.lower()
    for phrase in forbidden_phrases:
        assert phrase not in lower
