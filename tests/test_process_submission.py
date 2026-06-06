"""Unit tests for scripts/process_submission.py."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from process_submission import (  # noqa: E402
    build_evidence_branch_name,
    build_evidence_record,
    check_account_age,
    check_rate_limit,
    evidence_needs_staleness_review,
    extract_artifact_url,
    extract_image_urls,
    find_existing_evidence_index,
    load_pending_evidence_pr_entries,
    normalize_report_hash,
    parse_issue_body,
    upsert_evidence_record,
    validate_fields,
)


REPORT_HASH = "a" * 64
SAMPLE_BODY = f"""### Relay Domain / 中转站域名

api.example.com

### Audit Profile / 审计配置

full

### Claimed Provider / 声称供应商

Anthropic via Example Relay

### API Format / API 格式

anthropic-native

### Model Tested / 测试模型

claude-opus-4-6

### Tool Version / 工具版本

v2.3

### Tool Commit / 工具提交

040676c

### Tested At / 审计时间

2026-06-01T12:00:00Z

### Overall Rating / 总体评级

HIGH

### Evidence Level / 证据等级

redacted-report

### Step Summary / 步骤摘要

Step 3 prompt injection: anomaly
Step 5 identity consistency: inconclusive
Step 11 Web3 prompt injection: clean

### Operator Contacted / 是否联系运营方

yes

### False Positive Suspected / 是否怀疑误报

no

### Report Screenshot / 报告截图

![report](https://user-images.githubusercontent.com/123/report.png)

### Report Artifact / 报告文件

[report-redacted.md](https://github.com/user-attachments/files/123/report-redacted.md)

### Report Hash / 报告哈希

sha256:{REPORT_HASH}

### Key Findings / 主要发现

- \U0001f534 Token injection: +3200 tokens
- \U0001f7e1 Prompt extraction: 2/6

### Additional Notes / 补充说明

Test submission
"""


def test_parse_issue_body():
    fields = parse_issue_body(SAMPLE_BODY)
    assert fields["relay_domain"] == "api.example.com"
    assert fields["profile"] == "full"
    assert fields["claimed_provider"] == "Anthropic via Example Relay"
    assert fields["api_format"] == "anthropic-native"
    assert fields["model_tested"] == "claude-opus-4-6"
    assert fields["tool_version"] == "v2.3"
    assert fields["tool_commit"] == "040676c"
    assert fields["tested_at"] == "2026-06-01T12:00:00Z"
    assert fields["overall_rating"] == "HIGH"
    assert fields["evidence_level"] == "redacted-report"
    assert "Step 3 prompt injection" in fields["step_summary"]
    assert fields["operator_contacted"] == "yes"
    assert fields["false_positive_suspected"] == "no"
    assert fields["report_hash"] == f"sha256:{REPORT_HASH}"
    assert "report.png" in fields["report_image"]
    assert "report-redacted.md" in fields["report_artifact"]


def test_validate_fields_valid():
    fields = parse_issue_body(SAMPLE_BODY)
    assert validate_fields(fields) == []


def test_validate_fields_rejects_bad():
    bad = {
        "relay_domain": "",
        "profile": "xxx",
        "overall_rating": "MAYBE",
        "tool_commit": "not-a-commit",
        "tested_at": "yesterday",
        "report_hash": "nope",
    }
    errors = validate_fields(bad)
    assert len(errors) > 0


def test_build_evidence_record():
    fields = parse_issue_body(SAMPLE_BODY)
    entry = build_evidence_record(fields, "testuser", "42")
    assert entry["recordType"] == "community-submitted-audit-evidence"
    assert entry["relayDomain"] == "api.example.com"
    assert entry["claimedProvider"] == "Anthropic via Example Relay"
    assert entry["apiFormat"] == "anthropic-native"
    assert entry["modelTested"] == "claude-opus-4-6"
    assert entry["toolCommit"] == "040676c"
    assert entry["auditProfile"] == "full"
    assert entry["toolReportedOverallRating"] == "HIGH"
    assert entry["evidenceLevel"] == "redacted-report"
    assert "Step 5 identity consistency" in entry["stepSummary"]
    assert entry["operatorContacted"] == "yes"
    assert entry["falsePositiveSuspected"] == "no"
    assert entry["reportHash"] == f"sha256:{REPORT_HASH}"
    assert (
        entry["reportArtifactUrl"]
        == "https://github.com/user-attachments/files/123/report-redacted.md"
    )
    assert entry["evidenceStatus"] == "accepted_unverified"
    assert entry["reviewStatus"] == "unverified"
    assert entry["disputeStatus"] == "none"
    assert entry["staleAfter"] == "2026-08-30"
    assert entry["source"] == "github-issue"
    assert len(entry["redFlags"]) == 2
    assert len(entry["reportImages"]) == 1
    assert entry["reportImages"][0] != entry["reportArtifactUrl"]


def test_upsert_evidence_record_replaces_same_issue():
    fields = parse_issue_body(SAMPLE_BODY)
    original = build_evidence_record(fields, "testuser", "42")
    updated_fields = parse_issue_body(_make_body(overall_rating="MEDIUM"))
    updated = build_evidence_record(updated_fields, "testuser", "42")

    data, action = upsert_evidence_record([original], updated)

    assert action == "updated"
    assert len(data) == 1
    assert data[0]["issueNumber"] == 42
    assert data[0]["toolReportedOverallRating"] == "MEDIUM"


def test_upsert_evidence_record_replaces_same_domain_report_hash():
    fields = parse_issue_body(SAMPLE_BODY)
    original = build_evidence_record(fields, "testuser", "42")
    duplicate_fields = parse_issue_body(_make_body(relay_domain="API.Example.COM."))
    duplicate = build_evidence_record(duplicate_fields, "other-user", "99")

    assert find_existing_evidence_index([original], duplicate) == 0
    data, action = upsert_evidence_record([original], duplicate)

    assert action == "updated"
    assert len(data) == 1
    assert data[0]["issueNumber"] == 99
    assert data[0]["relayDomain"] == "api.example.com"


def test_check_account_age():
    young = datetime.now(timezone.utc) - timedelta(days=3)
    old = datetime.now(timezone.utc) - timedelta(days=60)
    assert check_account_age(young.isoformat()) is True
    assert check_account_age(old.isoformat()) is False
    assert check_account_age("") is True
    assert check_account_age(None) is True


def test_extract_image_urls():
    assert extract_image_urls("![x](https://img.com/a.png)") == ["https://img.com/a.png"]
    assert extract_image_urls("no image") == []
    assert len(extract_image_urls("![a](https://a.com/1.png) ![b](https://b.com/2.jpg)")) == 2


def test_extract_artifact_url():
    assert (
        extract_artifact_url("[report.md](https://github.com/user-attachments/files/1/report.md)")
        == "https://github.com/user-attachments/files/1/report.md"
    )
    assert extract_artifact_url("https://example.com/report-redacted.md") == (
        "https://example.com/report-redacted.md"
    )
    assert extract_artifact_url("http://example.com/report.md") == ""
    assert extract_artifact_url("no link") == ""


def test_check_rate_limit():
    now_iso = datetime.now(timezone.utc).isoformat()
    fake_data = [{"relayDomain": "test.com", "submittedAt": now_iso} for _ in range(10)]
    assert check_rate_limit("test.com", fake_data) is True
    assert check_rate_limit("other.com", fake_data) is False
    assert check_rate_limit("test.com", []) is False


def test_empty_body_rejected():
    fields = parse_issue_body("")
    errors = validate_fields(fields)
    assert len(errors) >= 9


def _make_body(**overrides):
    """Build a valid issue body, then override specific field values."""
    defaults = {
        "relay_domain": "api.example.com",
        "profile": "full",
        "claimed_provider": "Anthropic via Example Relay",
        "api_format": "anthropic-native",
        "model_tested": "claude-opus-4-6",
        "tool_version": "v2.3",
        "tool_commit": "040676c",
        "tested_at": "2026-06-01T12:00:00Z",
        "overall_rating": "HIGH",
        "evidence_level": "redacted-report",
        "step_summary": (
            "Step 3 prompt injection: anomaly\n"
            "Step 5 identity consistency: inconclusive\n"
            "Step 11 Web3 prompt injection: clean"
        ),
        "operator_contacted": "yes",
        "false_positive_suspected": "no",
        "report_image": "![report](https://user-images.githubusercontent.com/123/report.png)",
        "report_artifact": (
            "[report-redacted.md](https://github.com/user-attachments/files/123/report-redacted.md)"
        ),
        "report_hash": f"sha256:{REPORT_HASH}",
        "red_flags": "- \U0001f534 Token injection: +3200 tokens",
        "notes": "Test submission",
    }
    defaults.update(overrides)
    return (
        f"### Relay Domain / 中转站域名\n\n{defaults['relay_domain']}\n\n"
        f"### Audit Profile / 审计配置\n\n{defaults['profile']}\n\n"
        f"### Claimed Provider / 声称供应商\n\n{defaults['claimed_provider']}\n\n"
        f"### API Format / API 格式\n\n{defaults['api_format']}\n\n"
        f"### Model Tested / 测试模型\n\n{defaults['model_tested']}\n\n"
        f"### Tool Version / 工具版本\n\n{defaults['tool_version']}\n\n"
        f"### Tool Commit / 工具提交\n\n{defaults['tool_commit']}\n\n"
        f"### Tested At / 审计时间\n\n{defaults['tested_at']}\n\n"
        f"### Overall Rating / 总体评级\n\n{defaults['overall_rating']}\n\n"
        f"### Evidence Level / 证据等级\n\n{defaults['evidence_level']}\n\n"
        f"### Step Summary / 步骤摘要\n\n{defaults['step_summary']}\n\n"
        f"### Operator Contacted / 是否联系运营方\n\n{defaults['operator_contacted']}\n\n"
        f"### False Positive Suspected / 是否怀疑误报\n\n{defaults['false_positive_suspected']}\n\n"
        f"### Report Screenshot / 报告截图\n\n{defaults['report_image']}\n\n"
        f"### Report Artifact / 报告文件\n\n{defaults['report_artifact']}\n\n"
        f"### Report Hash / 报告哈希\n\n{defaults['report_hash']}\n\n"
        f"### Key Findings / 主要发现\n\n{defaults['red_flags']}\n\n"
        f"### Additional Notes / 补充说明\n\n{defaults['notes']}\n"
    )


def test_domain_with_path_traversal():
    """relay_domain containing '../' or '/' should be rejected by validation."""
    for bad_domain in ["../etc/passwd", "foo/bar", "a\\b"]:
        fields = parse_issue_body(_make_body(relay_domain=bad_domain))
        errors = validate_fields(fields)
        domain_errors = [e for e in errors if "relay_domain" in e and "hostname" in e]
        assert domain_errors, f"Expected hostname error for domain {bad_domain!r}"


def test_domain_with_special_chars():
    """relay_domain with spaces, unicode, angle brackets should be rejected."""
    for bad_domain in ["has space.com", "domäin.ü.com", "<script>alert(1)</script>"]:
        fields = parse_issue_body(_make_body(relay_domain=bad_domain))
        errors = validate_fields(fields)
        domain_errors = [e for e in errors if "relay_domain" in e and "hostname" in e]
        assert domain_errors, f"Expected hostname error for domain {bad_domain!r}"


def test_domain_must_be_canonical_hostname():
    """relay_domain must be a hostname, not a host:port or invalid label."""
    bad_domains = [
        "api.example.com:443",
        "bad_domain.com",
        "-bad.com",
        "bad-.com",
        ".",
        "api..example.com",
    ]
    for bad_domain in bad_domains:
        fields = parse_issue_body(_make_body(relay_domain=bad_domain))
        errors = validate_fields(fields)
        domain_errors = [e for e in errors if "relay_domain" in e and "hostname" in e]
        assert domain_errors, f"Expected hostname error for domain {bad_domain!r}"


def test_domain_allows_case_and_trailing_dot():
    """Case and trailing dot are canonicalized before hostname validation."""
    fields = parse_issue_body(_make_body(relay_domain="API.Example.COM."))
    errors = validate_fields(fields)
    assert [e for e in errors if "relay_domain" in e] == []
    entry = build_evidence_record(fields, "tester", "100")
    assert entry["relayDomain"] == "api.example.com"


def test_massive_body():
    """A very large issue body (>100 KB) should not crash parse_issue_body."""
    body = _make_body(notes="x" * 120_000)
    assert len(body.encode("utf-8")) > 100_000
    fields = parse_issue_body(body)
    assert fields["relay_domain"] == "api.example.com"
    assert fields["overall_rating"] == "HIGH"
    assert validate_fields(fields) == []


def test_multiple_images():
    """report_image field with 3+ images should all be extracted."""
    multi_img = (
        "![a](https://img.com/1.png) "
        "![b](https://img.com/2.png) "
        "![c](https://img.com/3.png) "
        "![d](https://img.com/4.jpg)"
    )
    fields = parse_issue_body(_make_body(report_image=multi_img))
    entry = build_evidence_record(fields, "tester", "99")
    assert len(entry["reportImages"]) == 4
    assert "https://img.com/3.png" in entry["reportImages"]


def test_report_images_must_be_https_without_markdown_title():
    """Report image extraction accepts only strict HTTPS markdown image URLs."""
    assert extract_image_urls("![x](http://img.com/a.png)") == []
    assert extract_image_urls("![x](https://img.com/a.png title)") == []
    assert extract_image_urls("![x](https://img.com/a.png)") == ["https://img.com/a.png"]

    for bad_image in [
        "![x](http://img.com/a.png)",
        "![x](https://img.com/a.png title)",
    ]:
        fields = parse_issue_body(_make_body(report_image=bad_image))
        errors = validate_fields(fields)
        image_errors = [e for e in errors if "report_image" in e]
        assert image_errors, f"Expected report_image error for {bad_image!r}"


def test_missing_report_image():
    """Missing report_image should produce a validation error."""
    fields = {
        "relay_domain": "api.example.com",
        "profile": "full",
        "tool_version": "v2.3",
        "tool_commit": "040676c",
        "tested_at": "2026-06-01",
        "overall_rating": "HIGH",
        "report_hash": f"sha256:{REPORT_HASH}",
        "report_artifact": "https://example.com/report-redacted.md",
    }
    errors = validate_fields(fields)
    image_errors = [e for e in errors if "report_image" in e]
    assert image_errors


def test_missing_report_artifact():
    """Missing report_artifact should produce a validation error."""
    fields = {
        "relay_domain": "api.example.com",
        "profile": "full",
        "tool_version": "v2.3",
        "tool_commit": "040676c",
        "tested_at": "2026-06-01",
        "overall_rating": "HIGH",
        "report_hash": f"sha256:{REPORT_HASH}",
        "report_image": "![report](https://user-images.githubusercontent.com/123/report.png)",
    }
    errors = validate_fields(fields)
    artifact_errors = [e for e in errors if "report_artifact" in e]
    assert artifact_errors


def test_report_artifact_must_be_https():
    """The report artifact is the hashable evidence object and must be HTTPS."""
    for bad_artifact in ["report-redacted.md", "http://example.com/report.md"]:
        fields = parse_issue_body(_make_body(report_artifact=bad_artifact))
        errors = validate_fields(fields)
        artifact_errors = [e for e in errors if "report_artifact" in e]
        assert artifact_errors, f"Expected report_artifact error for {bad_artifact!r}"


def test_report_artifact_written_separately_from_screenshot():
    fields = parse_issue_body(
        _make_body(
            report_image="![report](https://example.com/report.png)",
            report_artifact="https://example.com/report-redacted.md",
        )
    )
    entry = build_evidence_record(fields, "tester", "101")
    assert entry["reportImages"] == ["https://example.com/report.png"]
    assert entry["reportArtifactUrl"] == "https://example.com/report-redacted.md"
    assert entry["reportImages"][0] != entry["reportArtifactUrl"]


def test_optional_provider_profile_feedback_defaults_for_legacy_body():
    """Older issue bodies without growth feedback fields remain accepted."""
    legacy_body = f"""### Relay Domain / 中转站域名

api.example.com

### Audit Profile / 审计配置

general

### Tool Version / 工具版本

v2.3

### Tool Commit / 工具提交

040676c

### Tested At / 审计时间

2026-06-01T12:00:00Z

### Overall Rating / 总体评级

LOW

### Report Screenshot / 报告截图

![report](https://user-images.githubusercontent.com/123/report.png)

### Report Artifact / 报告文件

https://github.com/user-attachments/files/123/report-redacted.md

### Report Hash / 报告哈希

sha256:{REPORT_HASH}
"""
    fields = parse_issue_body(legacy_body)
    assert validate_fields(fields) == []

    entry = build_evidence_record(fields, "legacy-user", "77")
    assert entry["claimedProvider"] == "unknown"
    assert entry["apiFormat"] == "unknown"
    assert entry["modelTested"] == ""
    assert entry["evidenceLevel"] == "unknown"
    assert entry["stepSummary"] == ""
    assert entry["operatorContacted"] == "unknown"
    assert entry["falsePositiveSuspected"] == "unsure"


def test_provider_profile_feedback_values_are_validated():
    bad_fields = parse_issue_body(
        _make_body(
            api_format="bad-format",
            evidence_level="private-dump",
            operator_contacted="maybe",
            false_positive_suspected="definitely",
        )
    )
    errors = validate_fields(bad_fields)
    assert any("api_format" in e for e in errors)
    assert any("evidence_level" in e for e in errors)
    assert any("operator_contacted" in e for e in errors)
    assert any("false_positive_suspected" in e for e in errors)


def test_version_formats():
    """Valid version strings should pass; invalid ones should fail."""
    valid_versions = ["v2.3", "2.3", "v10.0.1"]
    for ver in valid_versions:
        fields = parse_issue_body(_make_body(tool_version=ver))
        errors = validate_fields(fields)
        assert [e for e in errors if "tool_version" in e] == []

    invalid_versions = ["abc"]
    for ver in invalid_versions:
        fields = parse_issue_body(_make_body(tool_version=ver))
        errors = validate_fields(fields)
        assert [e for e in errors if "tool_version" in e]


def test_tool_commit_required_and_validated():
    fields = parse_issue_body(_make_body(tool_commit="040676c"))
    assert [e for e in validate_fields(fields) if "tool_commit" in e] == []

    fields = parse_issue_body(_make_body(tool_commit="not-a-commit"))
    assert [e for e in validate_fields(fields) if "tool_commit" in e]


def test_report_hash_required_and_normalized():
    assert normalize_report_hash(REPORT_HASH) == f"sha256:{REPORT_HASH}"
    assert normalize_report_hash(f"sha256:{REPORT_HASH.upper()}") == f"sha256:{REPORT_HASH}"

    fields = parse_issue_body(_make_body(report_hash=REPORT_HASH))
    assert [e for e in validate_fields(fields) if "report_hash" in e] == []
    entry = build_evidence_record(fields, "tester", "12")
    assert entry["reportHash"] == f"sha256:{REPORT_HASH}"

    fields = parse_issue_body(_make_body(report_hash="abc"))
    assert [e for e in validate_fields(fields) if "report_hash" in e]


def test_tested_at_date_or_datetime():
    for value in ["2026-06-01", "2026-06-01T12:00:00Z"]:
        fields = parse_issue_body(_make_body(tested_at=value))
        assert [e for e in validate_fields(fields) if "tested_at" in e] == []

    fields = parse_issue_body(_make_body(tested_at="last week"))
    assert [e for e in validate_fields(fields) if "tested_at" in e]


def test_tested_at_future_is_rejected():
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    fields = parse_issue_body(_make_body(tested_at=future))
    errors = validate_fields(fields)
    assert any("tested_at cannot be in the future" in e for e in errors)


def test_stale_evidence_needs_review():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert evidence_needs_staleness_review("2026-03-01T00:00:00Z", now=now) is True
    assert evidence_needs_staleness_review("2026-05-01T00:00:00Z", now=now) is False


def test_evidence_branch_name_is_canonical():
    assert (
        build_evidence_branch_name("API.Example.COM.", "0042")
        == "community/evidence-api.example.com-issue-42"
    )
    for domain, issue in [
        ("api.example.com/path", "42"),
        ("bad_domain.com", "42"),
        ("api.example.com", "42;rm"),
    ]:
        with pytest.raises(ValueError):
            build_evidence_branch_name(domain, issue)


def test_build_entry_low_rating_preserves_tool_reported_rating():
    """LOW is a tool-reported result, not a platform safety endorsement."""
    fields = parse_issue_body(_make_body(overall_rating="LOW"))
    entry = build_evidence_record(fields, "user1", "10")
    assert entry["toolReportedOverallRating"] == "LOW"
    assert "rating" not in entry
    assert "ratingLabel" not in entry


def test_build_entry_medium_rating_preserves_tool_reported_rating():
    fields = parse_issue_body(_make_body(overall_rating="MEDIUM"))
    entry = build_evidence_record(fields, "user2", "20")
    assert entry["toolReportedOverallRating"] == "MEDIUM"


def test_rate_limit_old_entries():
    """Entries from >24h ago should NOT count toward the rate limit."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old_time = (now - timedelta(hours=25)).isoformat()
    recent_time = now.isoformat()

    old_data = [{"relayDomain": "test.com", "submittedAt": old_time} for _ in range(15)]
    assert check_rate_limit("test.com", old_data) is False

    mixed_data = old_data + [
        {"relayDomain": "test.com", "submittedAt": recent_time} for _ in range(9)
    ]
    assert check_rate_limit("test.com", mixed_data) is False

    mixed_data_trigger = old_data + [
        {"relayDomain": "test.com", "submittedAt": recent_time} for _ in range(10)
    ]
    assert check_rate_limit("test.com", mixed_data_trigger) is True


def test_rate_limit_normalizes_existing_domains():
    """Legacy/manual evidence domains should be normalized before comparison."""
    now_iso = datetime.now(timezone.utc).isoformat()
    fake_data = [{"relayDomain": "TEST.com.", "submittedAt": now_iso} for _ in range(10)]
    assert check_rate_limit("test.com", fake_data) is True


def test_rate_limit_accepts_legacy_domain_key():
    now_iso = datetime.now(timezone.utc).isoformat()
    fake_data = [{"domain": "TEST.com.", "submittedAt": now_iso} for _ in range(10)]
    assert check_rate_limit("test.com", fake_data) is True


def test_pending_evidence_prs_count_toward_rate_limit(tmp_path):
    now_iso = datetime.now(timezone.utc).isoformat()
    pending_prs = [
        {
            "headRefName": f"community/evidence-test.com-issue-{i}",
            "createdAt": now_iso,
        }
        for i in range(10)
    ]
    pending_file = tmp_path / "pending-prs.json"
    pending_file.write_text(json.dumps(pending_prs), encoding="utf-8")

    entries = load_pending_evidence_pr_entries(str(pending_file))

    assert len(entries) == 10
    assert check_rate_limit("test.com", entries) is True


def test_pending_evidence_pr_parser_ignores_unrelated_branches(tmp_path):
    now_iso = datetime.now(timezone.utc).isoformat()
    pending_prs = [
        {"headRefName": "community/evidence-other.com-issue-1", "createdAt": now_iso},
        {"headRefName": "community/evidence-issue-2", "createdAt": now_iso},
        {"headRefName": "community/evidence-bad_domain.com-issue-3", "createdAt": now_iso},
        {"headRefName": "feature/test", "createdAt": now_iso},
        {"headRefName": "community/evidence-test.com-issue-4", "createdAt": ""},
        {
            "headRefName": "community/evidence-test.com-issue-5",
            "createdAt": now_iso,
            "isCrossRepository": True,
        },
    ]
    pending_file = tmp_path / "pending-prs.json"
    pending_file.write_text(json.dumps(pending_prs), encoding="utf-8")

    entries = load_pending_evidence_pr_entries(str(pending_file))

    assert entries == [{"relayDomain": "other.com", "submittedAt": now_iso}]
    assert check_rate_limit("test.com", entries) is False


def test_main_creates_evidence_json(tmp_path, monkeypatch):
    """If evidence.json does not exist yet, the script should create it."""
    import process_submission as mod

    fake_evidence = tmp_path / "web" / "data" / "evidence.json"
    output_file = tmp_path / "github-output.txt"
    assert not fake_evidence.exists()
    monkeypatch.setattr(mod, "EVIDENCE_JSON", fake_evidence)

    monkeypatch.setenv("ISSUE_BODY", _make_body(tested_at=datetime.now(timezone.utc).isoformat()))
    monkeypatch.setenv("ISSUE_AUTHOR", "testbot")
    monkeypatch.setenv("ISSUE_NUMBER", "1")
    monkeypatch.setenv("AUTHOR_CREATED_AT", "2020-01-01T00:00:00Z")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    mod.main()

    assert fake_evidence.exists(), "evidence.json should have been created"
    data = json.loads(fake_evidence.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["relayDomain"] == "api.example.com"
    assert data[0]["evidenceStatus"] == "accepted_unverified"

    output = output_file.read_text(encoding="utf-8")
    assert "status=SHAPE_VALID" in output
    assert "relay_domain=api.example.com" in output
    assert f"report_hash=sha256:{REPORT_HASH}" in output
    assert "report_artifact_url=https://github.com/user-attachments/files/123/report-redacted.md" in output
    assert "tool_commit=040676c" in output
    assert "evidence_branch=community/evidence-api.example.com-issue-1" in output
    assert "evidence_action=created" in output


def test_main_rerun_updates_existing_evidence_without_duplicate(tmp_path, monkeypatch):
    import process_submission as mod

    fake_evidence = tmp_path / "web" / "data" / "evidence.json"
    output_file = tmp_path / "github-output.txt"
    monkeypatch.setattr(mod, "EVIDENCE_JSON", fake_evidence)

    old_fields = parse_issue_body(_make_body(overall_rating="HIGH"))
    old_entry = build_evidence_record(old_fields, "testbot", "1")
    fake_evidence.parent.mkdir(parents=True, exist_ok=True)
    fake_evidence.write_text(
        json.dumps([old_entry], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "ISSUE_BODY",
        _make_body(
            overall_rating="MEDIUM",
            tested_at=datetime.now(timezone.utc).isoformat(),
        ),
    )
    monkeypatch.setenv("ISSUE_AUTHOR", "testbot")
    monkeypatch.setenv("ISSUE_NUMBER", "1")
    monkeypatch.setenv("AUTHOR_CREATED_AT", "2020-01-01T00:00:00Z")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    mod.main()

    data = json.loads(fake_evidence.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["issueNumber"] == 1
    assert data[0]["toolReportedOverallRating"] == "MEDIUM"
    assert "evidence_action=updated" in output_file.read_text(encoding="utf-8")


def test_main_routes_stale_evidence_to_review_without_writing(tmp_path, monkeypatch):
    import process_submission as mod

    fake_evidence = tmp_path / "web" / "data" / "evidence.json"
    output_file = tmp_path / "github-output.txt"
    monkeypatch.setattr(mod, "EVIDENCE_JSON", fake_evidence)
    monkeypatch.setenv("ISSUE_BODY", _make_body(tested_at="2000-01-01T00:00:00Z"))
    monkeypatch.setenv("ISSUE_AUTHOR", "testbot")
    monkeypatch.setenv("ISSUE_NUMBER", "1")
    monkeypatch.setenv("AUTHOR_CREATED_AT", "2020-01-01T00:00:00Z")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    with pytest.raises(SystemExit) as exc:
        mod.main()

    assert exc.value.code == 3
    assert not fake_evidence.exists()
    assert "status=NEEDS_REVIEW" in output_file.read_text(encoding="utf-8")


def test_workflow_uses_draft_evidence_pr_contract():
    workflow = (
        Path(__file__).resolve().parent.parent
        / ".github"
        / "workflows"
        / "process-submission.yml"
    ).read_text(encoding="utf-8")

    assert "EVIDENCE_BRANCH: ${{ steps.process.outputs.evidence_branch }}" in workflow
    assert 'BRANCH="${EVIDENCE_BRANCH}"' in workflow
    assert "gh pr edit" in workflow
    assert "gh pr create" in workflow
    assert "--draft" in workflow
    assert "github.event.action == 'opened'" in workflow
    assert "github.event.action == 'labeled'" in workflow
    assert "github.event.label.name == 'audit-submission'" in workflow
    assert "contains(github.event.issue.labels.*.name, 'audit-submission')" in workflow
    assert 'git ls-remote --heads origin "${BRANCH}"' in workflow
    assert '--force-with-lease="refs/heads/${BRANCH}:${REMOTE_SHA}"' in workflow
    assert "web/data/evidence.json" in workflow
    assert "web/data/relays.json" not in workflow
    for forbidden in [
        "leaderboard",
        "trusted-relay",
        "certification",
        "safety endorsement",
        "relay recommendation",
    ]:
        assert forbidden not in workflow
