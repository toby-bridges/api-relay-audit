#!/usr/bin/env python3
"""Informational AC-1.b long-running watch spike helper.

Consumes local NDJSON observations and compares anomaly rates between neutral
and sensitive traffic. This is a companion-mode experiment, not a default
one-shot audit step.
"""

import argparse
import json
import sys
from pathlib import Path


SENSITIVE_MARKERS = ("aws", "api_key", "apikey", "token", "secret", "password", "bearer")


def profile_request(text):
    lowered = (text or "").lower()
    return "sensitive" if any(marker in lowered for marker in SENSITIVE_MARKERS) else "neutral"


def _truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def load_ndjson(path):
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def analyze_entries(entries, min_each=3, multiplier=2.0):
    counts = {
        "neutral": 0,
        "sensitive": 0,
        "neutralAnomalies": 0,
        "sensitiveAnomalies": 0,
    }

    for entry in entries:
        profile = entry.get("profile") or profile_request(entry.get("userContent", ""))
        if profile not in ("neutral", "sensitive"):
            continue
        counts[profile] += 1
        if _truthy(entry.get("anomaly")):
            counts[f"{profile}Anomalies"] += 1

    neutral_rate = counts["neutralAnomalies"] / counts["neutral"] if counts["neutral"] else 0.0
    sensitive_rate = (
        counts["sensitiveAnomalies"] / counts["sensitive"] if counts["sensitive"] else 0.0
    )

    result = {
        "recordType": "ac1b-watch-spike-result",
        "riskMatrixImpact": "none",
        **counts,
        "neutralRate": round(neutral_rate, 6),
        "sensitiveRate": round(sensitive_rate, 6),
        "minEach": min_each,
        "multiplier": multiplier,
    }

    if counts["neutral"] < min_each or counts["sensitive"] < min_each:
        result.update(
            {
                "verdict": "insufficient_data",
                "reason": "need_minimum_neutral_and_sensitive_observations",
            }
        )
    elif counts["sensitiveAnomalies"] >= 1 and (
        counts["neutralAnomalies"] == 0 or sensitive_rate >= neutral_rate * multiplier
    ):
        result.update(
            {
                "verdict": "conditional_injection_suspected",
                "reason": "sensitive_traffic_has_materially_higher_anomaly_rate",
            }
        )
    else:
        result.update(
            {
                "verdict": "no_conditional_injection",
                "reason": "sensitive_and_neutral_rates_are_similar",
            }
        )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", required=True, help="Local NDJSON observation log")
    parser.add_argument("--min-each", type=int, default=3)
    parser.add_argument("--multiplier", type=float, default=2.0)
    args = parser.parse_args(argv)

    result = analyze_entries(load_ndjson(args.log_file), args.min_each, args.multiplier)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
