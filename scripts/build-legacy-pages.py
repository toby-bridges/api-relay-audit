#!/usr/bin/env python3
"""Build static compatibility pages for historical GitHub Pages URLs.

Authored website source is maintained in toby-bridges/apirelayaudit-site.
This builder has no network or credential access. Its website input must be a
checkout of the fixed public website commit selected by the Pages workflow.
"""

from __future__ import annotations

import argparse
import html
import json
import shutil
from pathlib import Path, PurePosixPath

CANONICAL_ORIGIN = "https://apirelayaudit.com"
LEGACY_PREFIX = "/api-relay-audit/"


def safe_relative(value):
    if not isinstance(value, str) or not value:
        raise ValueError("Expected a nonempty relative public path")
    path = PurePosixPath(value)
    if (path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/"))
            or any(char in value for char in "\\:%?#\x00")):
        raise ValueError(f"Unsafe public path: {value!r}")
    return value


def load_manifest(path):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if (manifest.get("schema_version") != 1
            or manifest.get("canonical_origin") != CANONICAL_ORIGIN
            or manifest.get("legacy_path_prefix") != LEGACY_PREFIX):
        raise ValueError("Unsupported legacy URL manifest")
    for field in ("pages", "public_files"):
        values = manifest.get(field)
        if not isinstance(values, list) or not values or len(set(values)) != len(values):
            raise ValueError(f"Expected unique nonempty {field}")
        for value in values:
            safe_relative(value)
            if field == "pages" and not value.endswith(".html"):
                raise ValueError("Redirect pages must end in .html")
    if "index.html" not in manifest["pages"]:
        raise ValueError("The legacy homepage must be present")
    if set(manifest["pages"]) & set(manifest["public_files"]):
        raise ValueError("A public path cannot be both a redirect and an asset")
    return manifest


def canonical_url(page):
    safe_relative(page)
    suffix = page.removesuffix("index.html") if (page == "index.html" or page.endswith("/index.html")) else page
    return CANONICAL_ORIGIN + "/" + suffix


def redirect_html(destination):
    escaped = html.escape(destination, quote=True)
    # JSON encoding is sufficient for the fixed-origin, validated manifest URL.
    js_target = json.dumps(destination)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API Relay Audit — page moved</title>
<link rel="canonical" href="{escaped}">
</head><body><p>This page has moved to <a href="{escaped}">{escaped}</a>.</p>
<script>
if (window.location.hostname === "toby-bridges.github.io") {{
  const destination = new URL({js_target});
  destination.search = window.location.search;
  destination.hash = window.location.hash;
  window.location.replace(destination.href);
}}
</script></body></html>
"""


def output_path(output, relative):
    safe_relative(relative)
    target = output / relative
    if output.is_symlink() or target.is_symlink():
        raise ValueError("Compatibility output must not contain symlinks")
    if not target.resolve().is_relative_to(output.resolve()):
        raise ValueError("Compatibility path escapes output directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def build(manifest_path, website_root, evidence_path, output):
    manifest = load_manifest(manifest_path)
    website_root = website_root.resolve(strict=True)
    # Verify all public inputs before writing any output.
    sources = []
    for relative in manifest["public_files"]:
        source = website_root / relative
        if (source.is_symlink() or not source.is_file()
                or not source.resolve().is_relative_to(website_root)):
            raise ValueError(f"Missing or unsafe public asset: {relative}")
        sources.append((relative, source))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if not isinstance(evidence, list):
        raise ValueError("The reviewed evidence registry must be a JSON array")
    for page in manifest["pages"]:
        output_path(output, page).write_text(redirect_html(canonical_url(page)), encoding="utf-8")
    for relative, source in sources:
        shutil.copyfile(source, output_path(output, relative))
    output_path(output, "data/evidence.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    output_path(output, "robots.txt").write_text(
        "User-agent: *\nAllow: /\nSitemap: https://apirelayaudit.com/sitemap.xml\n",
        encoding="utf-8",
    )
    urls = [canonical_url(page) for page in manifest["pages"]]
    sitemap = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
               + "".join(f"  <url><loc>{html.escape(url)}</loc></url>\n" for url in urls)
               + "</urlset>\n")
    output_path(output, "sitemap.xml").write_text(sitemap, encoding="utf-8")
    output_path(output, ".nojekyll").write_text("", encoding="utf-8")
    return {"redirect_pages": len(urls), "public_assets": len(sources), "evidence_records": len(evidence)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--website-root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.manifest, args.website_root, args.evidence, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
