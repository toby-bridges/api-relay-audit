"""Markdown report generator for audit results."""

import json
from datetime import datetime


class Reporter:
    """Builds a structured Markdown audit report with a risk summary header.

    Sections are accumulated via helper methods (``h1``, ``h2``, ``p``,
    ``code``, ``flag``, etc.) and rendered into a single Markdown string
    by ``render()``.

    Attributes:
        sections: Accumulated Markdown fragments (body of the report).
        summary: List of ``(level, message)`` tuples collected by ``flag()``.
    """

    def __init__(self):
        """Initialise an empty report."""
        self.sections = []
        self.summary = []

    def h1(self, t):
        """Append a level-1 heading.

        Args:
            t: Heading text.
        """
        self.sections.append(f"\n# {t}\n")

    def h2(self, t):
        """Append a level-2 heading.

        Args:
            t: Heading text.
        """
        self.sections.append(f"\n## {t}\n")

    def h3(self, t):
        """Append a level-3 heading.

        Args:
            t: Heading text.
        """
        self.sections.append(f"\n### {t}\n")

    def p(self, t):
        """Append a paragraph of text.

        Args:
            t: Paragraph content (plain text or inline Markdown).
        """
        self.sections.append(f"{t}\n")

    def code(self, t, lang=""):
        """Append a fenced code block.

        Args:
            t: Code content.
            lang: Optional language hint for syntax highlighting
                (e.g. ``"json"``). Defaults to ``""``.
        """
        self.sections.append(f"```{lang}\n{t}\n```\n")

    def flag(self, level, msg):
        """Record a risk finding and append a coloured flag line.

        The finding is added both to the ``summary`` list (used in the
        report header) and inline in the body.

        Args:
            level: Severity string -- ``"red"``, ``"yellow"``, or
                ``"green"``.
            msg: Human-readable description of the finding.
        """
        icon = {"red": "\U0001f534", "yellow": "\U0001f7e1", "green": "\U0001f7e2"}.get(level, "\u26aa")
        self.summary.append((level, msg))
        self.sections.append(f"{icon} **{msg}**\n")

    def render(self, target_url="", model=""):
        """Render the complete Markdown report.

        Produces a header block (title, metadata, risk summary) followed
        by all accumulated sections joined with newlines.

        Args:
            target_url: The relay URL under test. Shown in the report
                metadata when provided.
            model: The model identifier used for the audit. Shown in the
                report metadata when provided.

        Returns:
            A single Markdown string containing the full report.

        Examples:
            >>> rpt = Reporter()
            >>> rpt.h2("Authentication")
            >>> rpt.flag("green", "API key accepted")
            >>> print(rpt.render(target_url="https://relay.example.com"))
        """
        header = (
            f"# API Relay Security Audit Report\n\n"
            f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        )
        if target_url:
            header += f"**Target**: `{target_url}`\n"
        if model:
            header += f"**Model**: `{model}`\n"

        header += "\n## Risk Summary\n\n"
        for level, msg in self.summary:
            icon = {"red": "\U0001f534", "yellow": "\U0001f7e1", "green": "\U0001f7e2"}.get(level, "\u26aa")
            header += f"- {icon} {msg}\n"
        header += "\n---\n"
        return header + "\n".join(self.sections)

    def to_json(self, target_url="", model="", test_results=None):
        """Render the report as a structured JSON dict.

        Args:
            target_url: The relay URL under test.
            model: The model identifier used.
            test_results: Dict of test result data collected during the audit.

        Returns:
            A dict suitable for ``json.dumps()``.
        """
        red_flags = [msg for level, msg in self.summary if level == "red"]
        yellow_flags = [msg for level, msg in self.summary if level == "yellow"]
        green_flags = [msg for level, msg in self.summary if level == "green"]

        # Determine overall risk level
        if red_flags:
            risk_level = "HIGH"
        elif yellow_flags:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        result = {
            "target": target_url,
            "model": model,
            "timestamp": datetime.now().isoformat(),
            "risk_level": risk_level,
            "tests": test_results or {},
            "flags": {
                "red": red_flags,
                "yellow": yellow_flags,
                "green": green_flags,
            },
        }
        return result
