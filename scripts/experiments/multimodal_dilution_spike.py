#!/usr/bin/env python3
"""Informational multimodal dilution spike helper.

This builds self-owned tiny PNG/PDF fixtures and request payload shapes for
future vision/document experiments. It does not call any API by default and is
not wired into the main audit pipeline.
"""

import base64
import json
import struct
import sys
import zlib


DEFAULT_PROMPT = "Describe the image in one word. If it is a color block, name the color."
NO_VISION_MARKERS = (
    "cannot see images",
    "can't see images",
    "cannot view images",
    "can't view images",
    "i do not have access to images",
    "i don't have access to images",
    "text-only",
)


def _png_chunk(kind, data):
    kind_bytes = kind.encode("ascii")
    body = kind_bytes + data
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + body + struct.pack(">I", crc)


def make_red_png(width=8, height=8):
    """Return a small self-generated RGB PNG."""
    if width <= 0 or height <= 0:
        raise ValueError("width and height must be positive")

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = b"\x00" + (b"\xff\x00\x00" * width)
    raw = row * height
    return (
        signature
        + _png_chunk("IHDR", ihdr)
        + _png_chunk("IDAT", zlib.compress(raw))
        + _png_chunk("IEND", b"")
    )


def make_keyword_pdf(keyword="AUDIT_RED"):
    """Return a tiny self-generated PDF-like fixture containing keyword text."""
    safe_keyword = "".join(ch for ch in keyword if ch.isalnum() or ch in " _-")[:40]
    stream = f"BT /F1 12 Tf 72 720 Td ({safe_keyword}) Tj ET"
    return (
        "%PDF-1.1\n"
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        "/Contents 4 0 R >> endobj\n"
        f"4 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj\n"
        "%%EOF\n"
    ).encode("ascii")


def b64(data):
    return base64.b64encode(data).decode("ascii")


def data_url(media_type, data):
    return f"data:{media_type};base64,{b64(data)}"


def build_anthropic_image_message(image_bytes, prompt=DEFAULT_PROMPT):
    return [
        {
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": b64(image_bytes),
                    },
                },
                {"type": "text", "text": prompt},
            ],
        }
    ]


def build_openai_image_message(image_bytes, prompt=DEFAULT_PROMPT):
    return [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": data_url("image/png", image_bytes)},
                },
            ],
        }
    ]


def classify_multimodal_result(text=None, error=None, expected_keywords=("red",)):
    """Classify a response without making safety claims.

    Transport/schema failures are inconclusive. Text responses that explicitly
    cannot see images, or do not contain expected deterministic keywords, are
    only dilution suspects and remain outside the risk matrix.
    """
    if error:
        return {
            "verdict": "inconclusive",
            "reason": "transport_or_format_error",
            "riskMatrixImpact": "none",
        }

    normalized = (text or "").strip().lower()
    if not normalized:
        return {
            "verdict": "inconclusive",
            "reason": "empty_response",
            "riskMatrixImpact": "none",
        }

    if any(marker in normalized for marker in NO_VISION_MARKERS):
        return {
            "verdict": "dilution_suspected",
            "reason": "model_claims_no_vision_access",
            "riskMatrixImpact": "none",
        }

    expected = [kw.lower() for kw in expected_keywords]
    if expected and all(kw in normalized for kw in expected):
        return {"verdict": "passed", "reason": "expected_keywords_found", "riskMatrixImpact": "none"}

    return {
        "verdict": "dilution_suspected",
        "reason": "expected_keywords_missing",
        "riskMatrixImpact": "none",
    }


def main():
    image = make_red_png()
    payload = {
        "recordType": "multimodal-dilution-spike-fixtures",
        "riskMatrixImpact": "none",
        "pngBytes": len(image),
        "pdfBytes": len(make_keyword_pdf()),
        "anthropicMessages": build_anthropic_image_message(image),
        "openaiMessages": build_openai_image_message(image),
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
