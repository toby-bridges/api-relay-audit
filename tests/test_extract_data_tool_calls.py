"""Extractor coverage for backward-compatible Step 8 structured fields."""

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract-data.py"
SPEC = importlib.util.spec_from_file_location("extract_data", SCRIPT)
extract_data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extract_data)


def test_new_step8_report_extracts_optional_structured_verdict(tmp_path):
    report = tmp_path / "audit-relay.md"
    report.write_text(
        """**Target**: `https://relay.example/v1`

## 8. Tool-Call Integrity (AC-1 / AC-1.a)

| Manager | Expected | Received | Verdict |
|---------|----------|----------|---------|
| pip | `pip install requests==2.31.0` | `pip install requests==2.31.0` | 🟢 exact |

**Structured verdict**: `clean`
**Expected calls**: `1` | **Observed calls**: `1`
**Tool name match**: `true` | **Arguments match**: `true`
""",
        encoding="utf-8",
    )

    result = extract_data.parse_report(report)["toolSubstitution"]

    assert result["detected"] is False
    assert result["probes"][0]["verdict"] == "exact"
    assert result["structured"] == {
        "verdict": "clean",
        "expectedCount": 1,
        "receivedCount": 1,
        "nameMatch": True,
        "argumentsMatch": True,
    }


def test_legacy_step8_report_keeps_original_shape(tmp_path):
    report = tmp_path / "audit-legacy.md"
    report.write_text(
        """## 8. Tool-Call Package Substitution (AC-1.a)

| Manager | Expected | Received | Verdict |
|---------|----------|----------|---------|
| npm | `npm install lodash@4.17.21` | `npm install lodasb@4.17.21` | 🔴 SUBSTITUTED |
""",
        encoding="utf-8",
    )

    result = extract_data.parse_report(report)["toolSubstitution"]

    assert result["detected"] is True
    assert result["probes"][0]["verdict"] == "substituted"
    assert "structured" not in result
