"""Tests for api_relay_audit.reporter.Reporter."""

from unittest.mock import patch

import pytest

from api_relay_audit.reporter import Reporter


@pytest.fixture
def rpt():
    return Reporter()


# ---------------------------------------------------------------------------
# Section methods
# ---------------------------------------------------------------------------

class TestSectionMethods:
    def test_h1(self, rpt):
        rpt.h1("Title")
        assert rpt.sections == ["\n# Title\n"]

    def test_h2(self, rpt):
        rpt.h2("Subtitle")
        assert rpt.sections == ["\n## Subtitle\n"]

    def test_h3(self, rpt):
        rpt.h3("Sub-sub")
        assert rpt.sections == ["\n### Sub-sub\n"]

    def test_p(self, rpt):
        rpt.p("Paragraph text.")
        assert rpt.sections == ["Paragraph text.\n"]

    def test_code_default_lang(self, rpt):
        rpt.code("print('hi')")
        assert rpt.sections == ["```\nprint('hi')\n```\n"]

    def test_code_with_lang(self, rpt):
        rpt.code('{"key": "val"}', lang="json")
        assert rpt.sections == ['```json\n{"key": "val"}\n```\n']

    def test_sections_accumulate_in_order(self, rpt):
        rpt.h1("A")
        rpt.p("B")
        rpt.h2("C")
        assert len(rpt.sections) == 3
        assert "# A" in rpt.sections[0]
        assert "B" in rpt.sections[1]
        assert "## C" in rpt.sections[2]


# ---------------------------------------------------------------------------
# flag method
# ---------------------------------------------------------------------------

class TestFlag:
    @pytest.mark.parametrize("level,expected_icon", [
        ("red", "\U0001f534"),
        ("yellow", "\U0001f7e1"),
        ("green", "\U0001f7e2"),
        ("unknown", "\u26aa"),
    ])
    def test_flag_icons(self, rpt, level, expected_icon):
        rpt.flag(level, "Some finding")
        assert rpt.sections[-1].startswith(expected_icon)

    def test_flag_adds_to_summary(self, rpt):
        rpt.flag("red", "Critical issue")
        assert len(rpt.summary) == 1
        assert rpt.summary[0] == ("red", "Critical issue")

    def test_flag_bold_message(self, rpt):
        rpt.flag("green", "All good")
        assert "**All good**" in rpt.sections[-1]

    def test_multiple_flags_accumulate(self, rpt):
        rpt.flag("red", "Bad")
        rpt.flag("yellow", "Meh")
        rpt.flag("green", "Good")
        assert len(rpt.summary) == 3


# ---------------------------------------------------------------------------
# Summary collection
# ---------------------------------------------------------------------------

class TestSummary:
    def test_empty_summary(self, rpt):
        assert rpt.summary == []

    def test_summary_preserves_order(self, rpt):
        rpt.flag("green", "A")
        rpt.flag("red", "B")
        rpt.flag("yellow", "C")
        levels = [s[0] for s in rpt.summary]
        assert levels == ["green", "red", "yellow"]

    def test_summary_contains_messages(self, rpt):
        rpt.flag("red", "Auth bypass")
        rpt.flag("green", "TLS ok")
        msgs = [s[1] for s in rpt.summary]
        assert "Auth bypass" in msgs
        assert "TLS ok" in msgs


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

class TestRender:
    @patch("api_relay_audit.reporter.datetime")
    def test_render_header(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        output = rpt.render()
        assert "# API Relay Security Audit Report" in output
        assert "2026-03-30 12:00" in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_with_target_and_model(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        output = rpt.render(target_url="https://relay.test", model="claude-3")
        assert "`https://relay.test`" in output
        assert "`claude-3`" in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_without_target_and_model(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        output = rpt.render()
        assert "**Target**" not in output
        assert "**Model**" not in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_includes_risk_summary(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        rpt.flag("red", "Found vulnerability")
        rpt.flag("green", "Encryption ok")
        output = rpt.render()
        assert "## Risk Summary" in output
        assert "Found vulnerability" in output
        assert "Encryption ok" in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_includes_sections(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        rpt.h1("Test Section")
        rpt.p("Some details.")
        output = rpt.render()
        assert "# Test Section" in output
        assert "Some details." in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_separator(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        output = rpt.render()
        assert "---" in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_empty_report(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        output = rpt.render()
        # Should still produce valid output with header
        assert "# API Relay Security Audit Report" in output
        assert "## Risk Summary" in output

    @patch("api_relay_audit.reporter.datetime")
    def test_render_summary_icons_match_flag_icons(self, mock_dt, rpt):
        mock_dt.now.return_value.strftime.return_value = "2026-03-30 12:00"
        rpt.flag("red", "Red item")
        rpt.flag("yellow", "Yellow item")
        rpt.flag("green", "Green item")
        output = rpt.render()
        # Red circle appears twice: once in sections, once in summary
        assert output.count("\U0001f534") == 2
        assert output.count("\U0001f7e1") == 2
        assert output.count("\U0001f7e2") == 2
