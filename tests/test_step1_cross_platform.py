"""Regression tests for Step 1 cross-platform infrastructure recon.

The old implementation shell-piped through ``dig``, ``whois``, ``openssl``,
``curl``, and ``head``. On Windows hosts missing those POSIX tools, the
report surfaced raw shell failure text like ``The system cannot find the
path specified.`` instead of a human-readable fallback.
"""

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def modular():
    return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_step1_xplat")


@pytest.fixture(scope="module")
def standalone():
    return _load(REPO_ROOT / "audit.py", "standalone_audit_step1_xplat")


def _render_step1(mod, monkeypatch):
    monkeypatch.setattr(
        mod,
        "_resolve_dns_records",
        lambda domain: {
            "A": "203.0.113.10",
            "CNAME": "nslookup not available on this host",
            "NS": "nslookup not available on this host",
        },
    )
    monkeypatch.setattr(mod, "_lookup_whois", lambda domain: None)
    monkeypatch.setattr(mod, "_fetch_tls_certificate_summary", lambda domain: None)

    def fake_http_snapshot(url, method="GET", max_body_chars=500):
        if method == "HEAD":
            return {"error": "method not allowed"}
        return {
            "status": 200,
            "url": url,
            "headers": {"server": "Caddy", "content-type": "text/html"},
            "body_preview": "<html><title>relay</title></html>",
        }

    monkeypatch.setattr(mod, "_fetch_http_snapshot", fake_http_snapshot)

    reporter = mod.Reporter()
    mod.test_infrastructure("https://relay.example.com/v1", reporter)
    return reporter.render(target_url="https://relay.example.com/v1", model="claude-opus-4-6")


def test_modular_step1_uses_human_fallbacks(monkeypatch, modular):
    md = _render_step1(modular, monkeypatch)
    assert "whois not available on this host" in md
    assert "nslookup not available on this host" in md
    assert "Unable to retrieve SSL certificate" in md
    assert "HTTP 200 https://relay.example.com/v1" in md
    assert "<html><title>relay</title></html>" in md
    assert "The system cannot find the path specified." not in md


def test_standalone_step1_uses_human_fallbacks(monkeypatch, standalone):
    md = _render_step1(standalone, monkeypatch)
    assert "whois not available on this host" in md
    assert "nslookup not available on this host" in md
    assert "Unable to retrieve SSL certificate" in md
    assert "HTTP 200 https://relay.example.com/v1" in md
    assert "<html><title>relay</title></html>" in md
    assert "The system cannot find the path specified." not in md
