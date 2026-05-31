#!/usr/bin/env python3
"""Informational model-substitution spike helper.

This is intentionally not wired into scripts/audit.py or audit.py. It compares
two small capability reports with matching item ids and reports whether the
candidate endpoint shows a large accuracy delta from a known-honest baseline.
"""

import argparse
import json
import re
import sys
from pathlib import Path


DEFAULT_MIN_ITEMS = 5
DEFAULT_SUSPICIOUS_DELTA = 0.25
BASELINE_PASS_FLOOR = 0.80


def normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _items(report):
    return report.get("items") or report.get("answers") or []


def _index_items(report):
    indexed = {}
    for item in _items(report):
        item_id = str(item.get("id", "")).strip()
        if item_id:
            indexed[item_id] = item
    return indexed


def item_passed(item):
    """Return True/False for a scored item, or None when it cannot be scored."""
    if "passed" in item:
        return bool(item["passed"])

    expected = item.get("expected")
    actual = item.get("actual")
    if expected is None or actual is None:
        return None

    return normalize_text(expected) in normalize_text(actual)


def score_report(report, item_ids):
    passed = 0
    total = 0
    indexed = _index_items(report)
    skipped = []

    for item_id in item_ids:
        result = item_passed(indexed[item_id])
        if result is None:
            skipped.append(item_id)
            continue
        total += 1
        if result:
            passed += 1

    score = passed / total if total else None
    return {"score": score, "passed": passed, "total": total, "skipped": skipped}


def compare_reports(
    baseline,
    candidate,
    min_items=DEFAULT_MIN_ITEMS,
    suspicious_delta=DEFAULT_SUSPICIOUS_DELTA,
):
    baseline_items = _index_items(baseline)
    candidate_items = _index_items(candidate)
    common_ids = sorted(set(baseline_items) & set(candidate_items))

    result = {
        "recordType": "model-substitution-spike-result",
        "riskMatrixImpact": "none",
        "baselineModel": baseline.get("model"),
        "candidateModel": candidate.get("model"),
        "commonItemCount": len(common_ids),
        "minItems": min_items,
        "suspiciousDelta": suspicious_delta,
    }

    if len(common_ids) < min_items:
        result.update(
            {
                "classification": "inconclusive",
                "reason": "insufficient_common_items",
            }
        )
        return result

    baseline_score = score_report(baseline, common_ids)
    candidate_score = score_report(candidate, common_ids)
    result["baseline"] = baseline_score
    result["candidate"] = candidate_score

    if baseline_score["total"] < min_items or candidate_score["total"] < min_items:
        result.update(
            {
                "classification": "inconclusive",
                "reason": "insufficient_scored_items",
            }
        )
        return result

    if baseline_score["score"] < BASELINE_PASS_FLOOR:
        result.update(
            {
                "classification": "inconclusive",
                "reason": "baseline_too_weak",
            }
        )
        return result

    delta = baseline_score["score"] - candidate_score["score"]
    result["delta"] = round(delta, 6)
    if delta >= suspicious_delta:
        result.update(
            {
                "classification": "capability_delta_observed",
                "reason": "candidate_score_materially_below_baseline",
            }
        )
    else:
        result.update(
            {
                "classification": "no_delta_observed",
                "reason": "candidate_score_close_to_baseline",
            }
        )
    return result


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="Known-honest baseline report JSON")
    parser.add_argument("--candidate", required=True, help="Candidate endpoint report JSON")
    parser.add_argument("--min-items", type=int, default=DEFAULT_MIN_ITEMS)
    parser.add_argument("--suspicious-delta", type=float, default=DEFAULT_SUSPICIOUS_DELTA)
    args = parser.parse_args(argv)

    result = compare_reports(
        _read_json(args.baseline),
        _read_json(args.candidate),
        min_items=args.min_items,
        suspicious_delta=args.suspicious_delta,
    )
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
