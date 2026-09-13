"""Regression checks for the GitHub Pages static site."""

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ET


REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_ROOT = REPO_ROOT / "web"
PAGES_BASE = "https://toby-bridges.github.io/api-relay-audit/"
GITHUB_REPO = "https://github.com/toby-bridges/api-relay-audit"


class SiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = set()
        self.canonicals = []
        self.alternates = []
        self.json_ld = []
        self._in_json_ld = False
        self._json_ld_parts = []
        self.elements = []
        self._ancestors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs, tuple(self._ancestors)))
        if tag not in {
            "area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr",
        }:
            self._ancestors.append((tag, attrs))
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for key in ("href", "src"):
            if key in attrs:
                self.links.append((tag, key, attrs[key]))
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonicals.append(attrs.get("href", ""))
        if tag == "link" and attrs.get("rel") == "alternate":
            self.alternates.append((attrs.get("hreflang", ""), attrs.get("href", "")))
        if tag == "script" and attrs.get("type") == "application/ld+json":
            self._in_json_ld = True
            self._json_ld_parts = []

    def handle_data(self, data):
        if self._in_json_ld:
            self._json_ld_parts.append(data)

    def handle_endtag(self, tag):
        for index in range(len(self._ancestors) - 1, -1, -1):
            if self._ancestors[index][0] == tag:
                del self._ancestors[index:]
                break
        if tag == "script" and self._in_json_ld:
            self.json_ld.append("".join(self._json_ld_parts))
            self._in_json_ld = False
            self._json_ld_parts = []


def _parse_html(path):
    parser = SiteParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def _html_pages():
    return sorted(WEB_ROOT.glob("**/*.html"))


def _local_path_for_url(url):
    parsed = urlparse(url)
    assert parsed.scheme == "https"
    assert parsed.netloc == "toby-bridges.github.io"
    assert parsed.path.startswith("/api-relay-audit/")
    suffix = parsed.path.removeprefix("/api-relay-audit/")
    if suffix in ("", "/"):
        return WEB_ROOT / "index.html"
    path = WEB_ROOT / unquote(suffix)
    if parsed.path.endswith("/"):
        return path / "index.html"
    return path


def _target_file_for_relative_link(source, href):
    path_part, _, fragment = href.partition("#")
    if not path_part:
        return source, fragment
    target = (source.parent / unquote(path_part)).resolve()
    assert str(target).startswith(str(WEB_ROOT.resolve()))
    if target.is_dir():
        target = target / "index.html"
    return target, fragment


def test_all_pages_parse_and_json_ld_is_valid():
    for path in _html_pages():
        parser = _parse_html(path)
        for item in parser.json_ld:
            json.loads(item)
        if path.parent == WEB_ROOT / "guides":
            _assert_conversion_links(parser, "guide-end", path)
            assert any(
                tag == "a" and attrs.get("href") == GITHUB_REPO
                and any(parent == "header" for parent, _ in ancestors)
                for tag, attrs, ancestors in parser.elements
            ), f"{path}: missing header GitHub link"
        elif path == WEB_ROOT / "index.html":
            _assert_conversion_links(parser, "after-demo", path)


def _assert_conversion_links(parser, placement, path):
    containers = [
        (attrs, ancestors) for tag, attrs, ancestors in parser.elements
        if attrs.get("data-cta-placement") == placement
    ]
    assert len(containers) == 1, f"{path}: expected one {placement} CTA"
    if placement == "after-demo":
        assert any(attrs.get("id") == "demo" for _, attrs in containers[0][1])
    else:
        assert any(tag == "main" for tag, _ in containers[0][1])
    links = [
        attrs for tag, attrs, ancestors in parser.elements
        if tag == "a" and any(
            parent_attrs.get("data-cta-placement") == placement
            for _, parent_attrs in ancestors
        )
    ]
    legacy = path.name == "openclaw-hermes-skill-api-relay-audit.html"
    assert [(link.get("data-cta"), link.get("href")) for link in links] == [
        ("retained-files", GITHUB_REPO + "/blob/master/SKILL.md") if legacy
        else ("run-locally", GITHUB_REPO + "#quick-start"),
        ("star", GITHUB_REPO),
    ], f"{path}: missing or duplicated run/Star links"
    assert sum(
        attrs.get("data-cta") == "star" for _, attrs, _ in parser.elements
    ) == 1, f"{path}: repeated Star CTA"


def test_relative_links_and_fragments_resolve():
    parsers = {path: _parse_html(path) for path in _html_pages()}
    for source, parser in parsers.items():
        for _tag, _key, href in parser.links:
            parsed = urlparse(href)
            if parsed.scheme or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            if href == "#":
                continue
            target, fragment = _target_file_for_relative_link(source, href)
            assert target.exists(), f"{source} links to missing {href}"
            if fragment:
                target_parser = parsers.get(target) or _parse_html(target)
                assert fragment in target_parser.ids, f"{source} links to missing fragment {href}"


def test_sitemap_urls_map_to_committed_pages():
    root = ET.parse(WEB_ROOT / "sitemap.xml").getroot()
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = [item.text for item in root.findall("sm:url/sm:loc", namespace)]
    expected = {
        "https://toby-bridges.github.io/api-relay-audit/",
        "https://toby-bridges.github.io/api-relay-audit/zh/",
        *{
            PAGES_BASE + path.relative_to(WEB_ROOT).as_posix()
            for path in WEB_ROOT.glob("guides/*.html")
        },
    }
    assert set(urls) == expected
    for url in urls:
        assert _local_path_for_url(url).exists(), url


def test_robots_points_to_sitemap():
    robots = (WEB_ROOT / "robots.txt").read_text(encoding="utf-8")
    assert "User-agent: *" in robots
    assert f"Sitemap: {PAGES_BASE}sitemap.xml" in robots


def test_homepage_and_chinese_page_have_reciprocal_hreflang():
    expected = {
        ("en", "https://toby-bridges.github.io/api-relay-audit/"),
        ("zh-CN", "https://toby-bridges.github.io/api-relay-audit/zh/"),
        ("x-default", "https://toby-bridges.github.io/api-relay-audit/"),
    }
    for path, canonical in [
        (WEB_ROOT / "index.html", "https://toby-bridges.github.io/api-relay-audit/"),
        (WEB_ROOT / "zh" / "index.html", "https://toby-bridges.github.io/api-relay-audit/zh/"),
    ]:
        parser = _parse_html(path)
        assert parser.canonicals == [canonical]
        assert set(parser.alternates) == expected


def test_release_copy_avoids_stale_numeric_and_key_flow_claims():
    public_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            REPO_ROOT / "README.md",
            WEB_ROOT / "index.html",
            WEB_ROOT / "zh" / "index.html",
        ]
    )
    forbidden = [
        "2,847 lines",
        "2,847 行",
        "24 keywords",
        "24 个关键词",
        "key stays local",
        "Key 留在本地",
        "never sent to a third-party server",
    ]
    for phrase in forbidden:
        assert phrase not in public_text
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.lower().count("[star the repository]") == 1
    assert readme.index("[Star the repository]") > readme.index("## Quick Start")
    guide = (WEB_ROOT / "guides" / (
        "claude-code-anthropic-base-url-prompt-steganography.html"
    )).read_text(encoding="utf-8")
    assert re.search(r"AUDIT_SCRIPT_REF=v\d+\.\d+\.\d+\b", guide)
    assert "has not independently reproduced" in guide
    assert "does not inspect the Claude Code binary" in guide
