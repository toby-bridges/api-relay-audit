"""Markdown report generator for audit results."""

from datetime import datetime


class Reporter:
    """Builds a structured Markdown audit report with risk summary."""

    def __init__(self):
        self.sections = []
        self.summary = []

    def h1(self, t):
        self.sections.append(f"\n# {t}\n")

    def h2(self, t):
        self.sections.append(f"\n## {t}\n")

    def h3(self, t):
        self.sections.append(f"\n### {t}\n")

    def p(self, t):
        self.sections.append(f"{t}\n")

    def code(self, t, lang=""):
        self.sections.append(f"```{lang}\n{t}\n```\n")

    def flag(self, level, msg):
        icon = {"red": "\U0001f534", "yellow": "\U0001f7e1", "green": "\U0001f7e2"}.get(level, "\u26aa")
        self.summary.append((level, msg))
        self.sections.append(f"{icon} **{msg}**\n")

    def render(self, target_url="", model=""):
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
