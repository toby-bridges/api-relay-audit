"""Unit tests for scripts/process_submission.py"""

import sys
import os
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from process_submission import (
    parse_issue_body,
    validate_fields,
    build_relay_entry,
    check_account_age,
    extract_image_urls,
    check_rate_limit,
)

SAMPLE_BODY = """### Relay Domain / 中转站域名

api.example.com

### Audit Profile / 审计配置

full

### Tool Version / 工具版本

v2.3

### Overall Rating / 总体评级

HIGH

### Report Screenshot / 报告截图

![report](https://user-images.githubusercontent.com/123/report.png)

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
    assert fields["tool_version"] == "v2.3"
    assert fields["overall_rating"] == "HIGH"
    assert "report.png" in fields["report_image"]


def test_validate_fields_valid():
    fields = parse_issue_body(SAMPLE_BODY)
    errors = validate_fields(fields)
    assert errors == []


def test_validate_fields_rejects_bad():
    bad = {"relay_domain": "", "profile": "xxx", "overall_rating": "MAYBE"}
    errors = validate_fields(bad)
    assert len(errors) > 0


def test_build_relay_entry():
    fields = parse_issue_body(SAMPLE_BODY)
    entry = build_relay_entry(fields, "testuser", "42")
    assert entry["domain"] == "api.example.com"
    assert entry["rating"] == "red"
    assert entry["source"] == "community"
    assert len(entry["redFlags"]) == 2
    assert len(entry["reportImages"]) == 1


def test_check_account_age():
    assert check_account_age("2026-05-29T00:00:00Z") is True
    assert check_account_age("2020-01-01T00:00:00Z") is False
    assert check_account_age("") is True
    assert check_account_age(None) is True


def test_extract_image_urls():
    assert extract_image_urls("![x](https://img.com/a.png)") == ["https://img.com/a.png"]
    assert extract_image_urls("no image") == []
    assert len(extract_image_urls("![a](https://a.com/1.png) ![b](https://b.com/2.jpg)")) == 2


def test_check_rate_limit():
    now_iso = datetime.now(timezone.utc).isoformat()
    fake_data = [{"domain": "test.com", "submittedAt": now_iso} for _ in range(10)]
    assert check_rate_limit("test.com", fake_data) is True
    assert check_rate_limit("other.com", fake_data) is False
    assert check_rate_limit("test.com", []) is False


def test_empty_body_rejected():
    fields = parse_issue_body("")
    errors = validate_fields(fields)
    assert len(errors) >= 4


# ---------------------------------------------------------------------------
# Edge-case tests (appended)
# ---------------------------------------------------------------------------

def _make_body(**overrides):
    """Build a valid issue body, then override specific field values."""
    defaults = {
        "relay_domain": "api.example.com",
        "profile": "full",
        "tool_version": "v2.3",
        "overall_rating": "HIGH",
        "report_image": "![report](https://user-images.githubusercontent.com/123/report.png)",
        "red_flags": "- \U0001f534 Token injection: +3200 tokens",
        "notes": "Test submission",
    }
    defaults.update(overrides)
    return (
        f"### Relay Domain / 中转站域名\n\n{defaults['relay_domain']}\n\n"
        f"### Audit Profile / 审计配置\n\n{defaults['profile']}\n\n"
        f"### Tool Version / 工具版本\n\n{defaults['tool_version']}\n\n"
        f"### Overall Rating / 总体评级\n\n{defaults['overall_rating']}\n\n"
        f"### Report Screenshot / 报告截图\n\n{defaults['report_image']}\n\n"
        f"### Key Findings / 主要发现\n\n{defaults['red_flags']}\n\n"
        f"### Additional Notes / 补充说明\n\n{defaults['notes']}\n"
    )


def test_domain_with_path_traversal():
    """relay_domain containing '../' or '/' should be rejected by validation."""
    for bad_domain in ["../etc/passwd", "foo/bar", "a\\b"]:
        body = _make_body(relay_domain=bad_domain)
        fields = parse_issue_body(body)
        errors = validate_fields(fields)
        domain_errors = [e for e in errors if "relay_domain" in e and "hostname" in e]
        assert len(domain_errors) > 0, f"Expected hostname error for domain {bad_domain!r}"


def test_domain_with_special_chars():
    """relay_domain with spaces, unicode, angle brackets should be rejected."""
    for bad_domain in ["has space.com", "domäin.ü.com", "<script>alert(1)</script>"]:
        body = _make_body(relay_domain=bad_domain)
        fields = parse_issue_body(body)
        errors = validate_fields(fields)
        domain_errors = [e for e in errors if "relay_domain" in e and "hostname" in e]
        assert len(domain_errors) > 0, f"Expected hostname error for domain {bad_domain!r}"


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
        body = _make_body(relay_domain=bad_domain)
        fields = parse_issue_body(body)
        errors = validate_fields(fields)
        domain_errors = [e for e in errors if "relay_domain" in e and "hostname" in e]
        assert len(domain_errors) > 0, f"Expected hostname error for domain {bad_domain!r}"


def test_domain_allows_case_and_trailing_dot():
    """Case and trailing dot are canonicalized before hostname validation."""
    body = _make_body(relay_domain="API.Example.COM.")
    fields = parse_issue_body(body)
    errors = validate_fields(fields)
    domain_errors = [e for e in errors if "relay_domain" in e]
    assert domain_errors == []
    entry = build_relay_entry(fields, "tester", "100")
    assert entry["domain"] == "api.example.com"


def test_massive_body():
    """A very large issue body (>100 KB) should not crash parse_issue_body."""
    huge_notes = "x" * 120_000
    body = _make_body(notes=huge_notes)
    assert len(body.encode("utf-8")) > 100_000
    fields = parse_issue_body(body)
    # Should still parse the structured fields correctly
    assert fields["relay_domain"] == "api.example.com"
    assert fields["overall_rating"] == "HIGH"
    errors = validate_fields(fields)
    assert errors == []


def test_multiple_images():
    """report_image field with 3+ images should all be extracted."""
    multi_img = (
        "![a](https://img.com/1.png) "
        "![b](https://img.com/2.png) "
        "![c](https://img.com/3.png) "
        "![d](https://img.com/4.jpg)"
    )
    body = _make_body(report_image=multi_img)
    fields = parse_issue_body(body)
    entry = build_relay_entry(fields, "tester", "99")
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
        body = _make_body(report_image=bad_image)
        fields = parse_issue_body(body)
        errors = validate_fields(fields)
        image_errors = [e for e in errors if "report_image" in e]
        assert image_errors, f"Expected report_image error for {bad_image!r}"


def test_missing_report_image():
    """Missing report_image should produce a validation error."""
    fields = {
        "relay_domain": "api.example.com",
        "profile": "full",
        "tool_version": "v2.3",
        "overall_rating": "HIGH",
        # report_image intentionally omitted
    }
    errors = validate_fields(fields)
    image_errors = [e for e in errors if "report_image" in e]
    assert len(image_errors) > 0


def test_version_formats():
    """Valid version strings should pass; invalid ones should fail."""
    valid_versions = ["v2.3", "2.3", "v10.0.1"]
    for ver in valid_versions:
        body = _make_body(tool_version=ver)
        fields = parse_issue_body(body)
        errors = validate_fields(fields)
        ver_errors = [e for e in errors if "tool_version" in e]
        assert ver_errors == [], f"Version {ver!r} should be valid but got: {ver_errors}"

    invalid_versions = ["abc"]
    for ver in invalid_versions:
        body = _make_body(tool_version=ver)
        fields = parse_issue_body(body)
        errors = validate_fields(fields)
        ver_errors = [e for e in errors if "tool_version" in e]
        assert len(ver_errors) > 0, f"Version {ver!r} should be invalid"

    # Empty version triggers "Missing required field" instead of format error
    fields_empty = {
        "relay_domain": "api.example.com",
        "profile": "full",
        "tool_version": "",
        "overall_rating": "HIGH",
        "report_image": "![r](https://img.com/r.png)",
    }
    errors = validate_fields(fields_empty)
    missing_errors = [e for e in errors if "Missing" in e and "tool_version" in e]
    assert len(missing_errors) > 0, "Empty version should trigger missing-field error"


def test_build_entry_low_rating():
    """LOW overall rating should map to green."""
    body = _make_body(overall_rating="LOW")
    fields = parse_issue_body(body)
    entry = build_relay_entry(fields, "user1", "10")
    assert entry["rating"] == "green"
    assert "Low Risk" in entry["ratingLabel"]


def test_build_entry_medium_rating():
    """MEDIUM overall rating should map to yellow."""
    body = _make_body(overall_rating="MEDIUM")
    fields = parse_issue_body(body)
    entry = build_relay_entry(fields, "user2", "20")
    assert entry["rating"] == "yellow"
    assert "Medium Risk" in entry["ratingLabel"]


def test_rate_limit_old_entries():
    """Entries from >24h ago should NOT count toward the rate limit."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old_time = (now - timedelta(hours=25)).isoformat()
    recent_time = now.isoformat()

    # 10 old entries (>24h) — should NOT trigger rate limit
    old_data = [{"domain": "test.com", "submittedAt": old_time} for _ in range(15)]
    assert check_rate_limit("test.com", old_data) is False, (
        "Old entries (>24h) should not count toward rate limit"
    )

    # Mix: 9 recent + 15 old — should NOT trigger (only 9 within window)
    mixed_data = old_data + [
        {"domain": "test.com", "submittedAt": recent_time} for _ in range(9)
    ]
    assert check_rate_limit("test.com", mixed_data) is False

    # Mix: 10 recent + 15 old — SHOULD trigger (10 within window)
    mixed_data_trigger = old_data + [
        {"domain": "test.com", "submittedAt": recent_time} for _ in range(10)
    ]
    assert check_rate_limit("test.com", mixed_data_trigger) is True


def test_rate_limit_normalizes_existing_domains():
    """Legacy/manual relays.json domains should be normalized before comparison."""
    now_iso = datetime.now(timezone.utc).isoformat()
    fake_data = [{"domain": "TEST.com.", "submittedAt": now_iso} for _ in range(10)]
    assert check_rate_limit("test.com", fake_data) is True


def test_concurrent_json_write_safety(tmp_path, monkeypatch):
    """If relays.json does not exist yet, the script should create it."""
    import json as _json

    fake_relays = tmp_path / "web" / "data" / "relays.json"
    assert not fake_relays.exists()

    # Monkeypatch the module-level constant so main() writes to tmp_path
    import process_submission as mod
    monkeypatch.setattr(mod, "RELAYS_JSON", fake_relays)

    body = _make_body()
    monkeypatch.setenv("ISSUE_BODY", body)
    monkeypatch.setenv("ISSUE_AUTHOR", "testbot")
    monkeypatch.setenv("ISSUE_NUMBER", "1")
    monkeypatch.setenv("AUTHOR_CREATED_AT", "2020-01-01T00:00:00Z")

    mod.main()

    assert fake_relays.exists(), "relays.json should have been created"
    data = _json.loads(fake_relays.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["domain"] == "api.example.com"
