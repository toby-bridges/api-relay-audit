"""Internal HTTP transport helpers for the modular API client.

This is deliberately an internal facade-preserving extraction: APIClient
still owns format detection, logging, and fallback policy. These helpers
only centralize the low-level httpx/curl request mechanics.
"""

from contextlib import contextmanager
import json
import os
import subprocess
import tempfile
from urllib.parse import urlparse

import httpx

LOOPBACK_NO_PROXY = "localhost,127.0.0.1,::1"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def curl_loopback_no_proxy_args(url: str) -> list:
    """Return curl args that keep loopback URLs out of proxy env routing."""
    if urlparse(url).hostname in LOOPBACK_HOSTS:
        return ["--noproxy", LOOPBACK_NO_PROXY]
    return []


def curl_header_config(headers: dict) -> str:
    """Pass headers through curl config stdin, never through process argv."""
    return "\n".join(
        f"header = {json.dumps(f'{key}: {value}', ensure_ascii=False)}"
        for key, value in headers.items()
    )


@contextmanager
def curl_body_file(body: bytes):
    """Make a private, short-lived body file while stdin carries headers."""
    path = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, prefix="api-relay-body-", suffix=".bin"
        ) as tmp:
            path = tmp.name
            tmp.write(body)
        yield path
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def curl_post_json(url: str, headers: dict, body: dict, timeout: int,
                   subprocess_module=subprocess) -> dict:
    """POST JSON through curl while keeping headers out of argv.

    Headers are passed through ``--config -`` so credentials do not show up
    in process listings. The JSON body is written to a short-lived file and
    sent via ``--data-binary @file`` so very large prompts do not hit Windows'
    32 KB command-line limit.
    """
    body_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, prefix="api-relay-body-", suffix=".json"
        ) as tmp:
            json.dump(body, tmp)
            body_path = tmp.name

        cmd = ["curl", "-sk", *curl_loopback_no_proxy_args(url), "-X", "POST", url,
               "--max-time", str(timeout), "--config", "-", "--data-binary", f"@{body_path}"]
        config = curl_header_config(headers)
        r = subprocess_module.run(cmd, capture_output=True, text=True, input=config,
                                  timeout=timeout + 10)
    finally:
        if body_path:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    if r.returncode != 0:
        raise RuntimeError(f"curl failed: {r.stderr[:200]}")
    return json.loads(r.stdout)


def httpx_post_json(url: str, headers: dict, body: dict, timeout: int,
                    httpx_module=httpx) -> dict:
    """POST JSON through httpx and preserve the existing error shape."""
    r = httpx_module.post(url, headers=headers, json=body, timeout=timeout)
    if r.status_code != 200:
        return {"_http_error": f"HTTP {r.status_code}: {r.text[:200]}"}
    return r.json()


def curl_get_json_data(url: str, headers: dict, timeout: int = 15,
                       subprocess_module=subprocess) -> list:
    """GET JSON through curl and return the top-level ``data`` list."""
    cmd = ["curl", "-sk", *curl_loopback_no_proxy_args(url), url,
           "--max-time", str(timeout), "--config", "-"]
    config = curl_header_config(headers)
    r = subprocess_module.run(cmd, capture_output=True, text=True, input=config,
                              timeout=timeout + 10)
    if r.returncode != 0:
        return []
    return json.loads(r.stdout).get("data", [])


def httpx_get_json_data(url: str, headers: dict, timeout: int = 15,
                        httpx_module=httpx):
    """GET JSON through httpx.

    Returns ``(status_code, data, text, headers)`` so APIClient can keep
    its transparent-log behavior unchanged.
    """
    r = httpx_module.get(url, headers=headers, timeout=timeout)
    data = r.json().get("data", []) if r.status_code == 200 else []
    return r.status_code, data, r.text, dict(r.headers)


def httpx_raw_request(method: str, url: str, headers: dict, body: bytes,
                      content_type: str, timeout: int,
                      httpx_module=httpx) -> dict:
    """Raw request through httpx, preserving body and headers."""
    r = httpx_module.request(
        method=method,
        url=url,
        headers={**headers, "content-type": content_type},
        content=body,
        timeout=timeout,
    )
    return {
        "status": r.status_code,
        "headers": dict(r.headers),
        "body": r.text,
        "error": None,
    }


def curl_raw_request(method: str, url: str, headers: dict, body: bytes,
                     content_type: str, timeout: int, parser,
                     subprocess_module=subprocess) -> dict:
    """Raw request through curl and parse ``curl -i`` output with ``parser``."""
    all_headers = {**headers, "content-type": content_type}
    try:
        with curl_body_file(body) as body_path:
            cmd = ["curl", "-sk", *curl_loopback_no_proxy_args(url), "-i", "-X", method, url,
                   "--max-time", str(timeout), "--config", "-",
                   "--data-binary", f"@{body_path}"]
            r = subprocess_module.run(
                cmd, capture_output=True, input=curl_header_config(all_headers).encode("utf-8"),
                timeout=timeout + 10,
            )
        if r.returncode != 0:
            err = r.stderr.decode("utf-8", errors="replace")[:200]
            return {"status": 0, "headers": {}, "body": "",
                    "error": f"curl failed: {err}"}
        output = r.stdout.decode("utf-8", errors="replace")
        return parser(output)
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}
