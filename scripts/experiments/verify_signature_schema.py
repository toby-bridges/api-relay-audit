#!/usr/bin/env python3
"""One-shot verification for ROADMAP item 5 (channel fingerprint).

Goal: empirically test whether the Claude thinking-block `signature`
field is protobuf wire-format and whether its decoded content varies
across channels (direct / bedrock / vertex / reverse-proxy).

Usage:
    set ANTHROPIC_API_KEY=sk-ant-...
    python scripts/experiments/verify_signature_schema.py

Output: `reports/signature-schema-probe.txt` (hex dumps + parsed field
tuples + 3-run stability diff). Read the report and decide:

  - If parseable as protobuf AND fields vary meaningfully across runs
    or carry a channel discriminator → proceed with item 5.
  - If opaque high-entropy ciphertext (no parseable tag structure)
    → abandon item 5, fall back to header-presence fingerprinting.

Zero deps: stdlib only, curl-free (uses urllib). Python 3.7+.

Status: archived under ``scripts/experiments/`` on 2026-04-20 as a
one-shot investigation artifact. Not part of the production audit
pipeline; no module imports it. Kept in-tree so the investigation is
reproducible; move to a separate gist or delete if/when ROADMAP item
5 closes definitively.
"""

import base64
import json
import os
import re
import ssl
import sys
import urllib.request
from collections import Counter
from pathlib import Path


ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-5"  # any thinking-capable model is fine
# Archival note (2026-04-20): file lives at
# ``scripts/experiments/<this file>`` so repo root is 3 levels up
# (was 2 before the move; Codex review flagged the drift).
# Keeps the report at ``<repo_root>/reports/signature-schema-probe.txt``
# regardless of where the script is invoked from.
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "reports"
OUT_FILE = OUT_DIR / "signature-schema-probe.txt"

# A prompt that reliably triggers extended-thinking content blocks.
PROMPT = (
    "Think step by step about whether 1009 is prime. "
    "Explain your reasoning and give the final answer."
)


def send_thinking_request(api_key: str, run_id: int):
    """Send one thinking-enabled request; return the full parsed JSON
    plus the raw response headers dict."""
    payload = {
        "model": MODEL,
        "max_tokens": 2048,
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "messages": [{"role": "user", "content": PROMPT}],
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        headers = dict(resp.headers.items())
        raw = resp.read().decode("utf-8")
    return headers, json.loads(raw)


def extract_signatures(resp_json):
    """Pull every `signature` string out of content blocks."""
    sigs = []
    for block in resp_json.get("content", []):
        sig = block.get("signature")
        if sig:
            sigs.append((block.get("type", "?"), sig))
    return sigs


# ---------- protobuf wire-format parser (zero-dep sketch) ----------
# Wire types: 0=varint, 1=fixed64, 2=length-delimited, 5=fixed32
# (3/4 are deprecated groups — we raise on them.)

def _read_varint(buf, pos):
    shift = 0
    result = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def parse_protobuf(buf, depth=0, max_depth=4):
    """Best-effort protobuf parse. Returns list of tuples:
    (field_number, wire_type, value_repr, raw_bytes). Unknown wire
    types 3/4 raise. Length-delimited payloads that themselves parse
    cleanly are recursed (to max_depth).
    """
    out = []
    pos = 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire = tag & 7
        if wire == 0:
            val, pos = _read_varint(buf, pos)
            out.append((field_num, 0, val, None))
        elif wire == 1:
            val = int.from_bytes(buf[pos:pos + 8], "little")
            out.append((field_num, 1, val, buf[pos:pos + 8]))
            pos += 8
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            payload = buf[pos:pos + length]
            pos += length
            sub = None
            if depth < max_depth:
                try:
                    sub = parse_protobuf(payload, depth + 1, max_depth)
                except Exception:
                    sub = None
            # decide repr
            try:
                as_str = payload.decode("utf-8")
                if all(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in as_str):
                    repr_val = f"utf8:{as_str!r}"
                else:
                    raise ValueError
            except Exception:
                repr_val = f"bytes[{len(payload)}]"
            if sub is not None:
                repr_val = f"nested({len(sub)} fields) | {repr_val}"
            out.append((field_num, 2, repr_val, payload))
        elif wire == 5:
            val = int.from_bytes(buf[pos:pos + 4], "little")
            out.append((field_num, 5, val, buf[pos:pos + 4]))
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire} (group?)")
    return out


def shannon_entropy_bits(buf):
    """Rough entropy measure. High-entropy ciphertext → ~7.9+ bits/byte."""
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    import math
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hex_dump(buf, width=32):
    lines = []
    for i in range(0, len(buf), width):
        chunk = buf[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"  {i:04x}  {hex_part}")
    return "\n".join(lines)


def summarize_run(run_id, headers, sigs, log):
    log(f"\n{'=' * 70}\nRUN {run_id}\n{'=' * 70}")
    log("\n-- response headers of interest --")
    for h in ("request-id", "anthropic-organization-id",
              "anthropic-ratelimit-requests-limit", "anthropic-version",
              "cf-ray", "x-cloud-trace-context", "x-amzn-requestid"):
        v = headers.get(h) or headers.get(h.title())
        if v is not None:
            log(f"  {h}: {v}")

    log(f"\n-- {len(sigs)} signature(s) found --")
    for idx, (block_type, sig) in enumerate(sigs):
        log(f"\n  [{idx}] block type={block_type!r} len(b64)={len(sig)}")
        try:
            raw = base64.b64decode(sig, validate=True)
        except Exception as e:
            log(f"      base64 decode failed: {e}")
            continue
        log(f"      decoded len={len(raw)} bytes  "
            f"entropy={shannon_entropy_bits(raw):.2f} bits/byte")
        log("      first 64 bytes:")
        log(hex_dump(raw[:64]))
        try:
            fields = parse_protobuf(raw)
            log(f"      protobuf parse OK — {len(fields)} top-level fields:")
            for f_num, wire, val_repr, _payload in fields:
                log(f"        field {f_num} (wire {wire}): {val_repr}")
        except Exception as e:
            log(f"      protobuf parse FAILED: {e}")
            log("      → likely opaque ciphertext; item 5 hypothesis DEAD")
    return [s for _, s in sigs]


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: set ANTHROPIC_API_KEY env var", file=sys.stderr)
        sys.exit(2)

    OUT_DIR.mkdir(exist_ok=True)
    lines = []
    log = lambda s="": lines.append(s)

    log(f"Channel-fingerprint signature-schema verification")
    log(f"Target: {ANTHROPIC_URL}  model={MODEL}  3 runs, identical prompt")

    all_b64 = []
    for run_id in (1, 2, 3):
        try:
            headers, resp = send_thinking_request(api_key, run_id)
        except Exception as e:
            log(f"\nRUN {run_id} FAILED: {e}")
            break
        sigs = extract_signatures(resp)
        b64s = summarize_run(run_id, headers, sigs, log)
        all_b64.append(b64s)

    # cross-run stability
    log(f"\n{'=' * 70}\nCROSS-RUN STABILITY\n{'=' * 70}")
    if len(all_b64) >= 2:
        for i in range(len(all_b64)):
            for j in range(i + 1, len(all_b64)):
                log(f"\nRun {i + 1} vs Run {j + 1}:")
                if len(all_b64[i]) != len(all_b64[j]):
                    log(f"  different signature counts ({len(all_b64[i])} vs "
                        f"{len(all_b64[j])}) — can't align, skipping")
                    continue
                for k, (a, b) in enumerate(zip(all_b64[i], all_b64[j])):
                    if a == b:
                        log(f"  sig[{k}] IDENTICAL across runs")
                    else:
                        ra = base64.b64decode(a)
                        rb = base64.b64decode(b)
                        log(f"  sig[{k}] differs  len {len(ra)} vs {len(rb)}")
                        if len(ra) == len(rb):
                            diff = sum(1 for x, y in zip(ra, rb) if x != y)
                            log(f"           {diff}/{len(ra)} bytes differ")

    log(f"\n{'=' * 70}\nDECISION CRITERIA\n{'=' * 70}")
    log("  PROCEED with item 5 if:")
    log("    - protobuf parse OK on at least 2 of 3 runs")
    log("    - at least one stable field across runs (candidate channel ID)")
    log("    - entropy ≲ 7.5 bits/byte (suggests structure, not cipher)")
    log("  ABANDON item 5 if:")
    log("    - all parses fail or fields look like random bytes")
    log("    - entropy ≈ 7.9+ bits/byte across the whole payload")
    log("    - all bytes differ across identical-prompt runs (pure HMAC/nonce)")

    OUT_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report written: {OUT_FILE}")
    print(f"Lines: {len(lines)}")


if __name__ == "__main__":
    main()
