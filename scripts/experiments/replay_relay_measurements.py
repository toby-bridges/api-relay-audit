"""Offline summaries for the protocol in docs/measurements/relay-comparison.md."""
import argparse
import csv
import json
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from pathlib import Path
from statistics import median


ARMS = ("official_a", "official_b", "transparent", "relay")
OUTCOMES = ("answer", "refusal", "error", "unparseable", "missing")
PERMISSIONS = ("disabled", "undeclared", "forced")
CATEGORIES = {"ordinary_input", "cache_read", "cache_write", "output"}


def quantity(value):
    number = int(value)
    if number < 0:
        raise ValueError("token and call counts must be nonnegative")
    return number


def dollars(value):
    amount = Decimal(value)
    if not amount.is_finite() or amount < 0:
        raise ValueError("expected a finite, nonnegative amount")
    return amount


def billing(rows, deduction):
    categories = defaultdict(dict)
    for row in rows:
        group = categories[row["model"]]
        category = row["category"]
        if category not in CATEGORIES or category in group:
            raise ValueError("unknown or duplicate billing category")
        group[category] = quantity(row["tokens"]) * dollars(row["usd_per_million"]) / 1000000
    if not categories or any(set(group) != CATEGORIES for group in categories.values()):
        raise ValueError("include all four categories for each model, using explicit zeroes")
    subtotals = {model: sum(group.values()) for model, group in categories.items()}
    total = sum(subtotals.values())
    return {"model_usd": {k: format(v, "f") for k, v in subtotals.items()},
            "calculated_usd": format(total, "f"), "deduction_usd": str(deduction),
            "deduction_minus_calculated_usd": format(deduction - total, "f")}


def measurements(rows):
    blocks = defaultdict(dict)
    for row in rows:
        block = (row["round"], row["case"], row["trial"], row["permission"])
        arm, outcome = row["arm"], row["outcome"]
        if not all(block) or block[-1] not in PERMISSIONS or arm not in ARMS or outcome not in OUTCOMES:
            raise ValueError("invalid block, arm, permission or outcome")
        group = blocks[block]
        if arm in group:
            raise ValueError("duplicate slot in block")
        calls = quantity(row["tool_calls"]) if row["tool_calls"] else None
        tokens = quantity(row["input_total"]) if row["input_total"] else None
        if outcome == "missing" and (calls is not None or tokens is not None):
            raise ValueError("a missing request has no response fields")
        group[arm] = outcome, calls, tokens

    if not blocks or any(set(group) != set(ARMS) for group in blocks.values()):
        raise ValueError("each scheduled block requires an explicit row for every arm")

    counts = defaultdict(Counter)
    differences = defaultdict(list)
    for (round_id, _, _, permission), group in blocks.items():
        ref_outcome, _, ref_tokens = group["official_a"]
        for arm, (outcome, calls, tokens) in group.items():
            key = (round_id, permission, arm)
            summary = counts[key]
            summary["scheduled"] += 1
            summary[outcome] += 1
            if calls is not None:
                summary["tool_fields_observed"] += 1
                if permission in ("disabled", "undeclared") and calls:
                    summary["unexpected_call_records"] += calls
                    summary["slots_with_unexpected_calls"] += 1
            if (outcome in ("answer", "refusal") and ref_outcome in ("answer", "refusal")
                    and tokens is not None and ref_tokens is not None):
                differences[key].append(tokens - ref_tokens)

    result = []
    for key, summary in sorted(counts.items()):
        round_id, permission, arm = key
        deltas = differences[key]
        result.append({"round": round_id, "permission": permission, "arm": arm,
                       **{k: summary[k] for k in ("scheduled", *OUTCOMES, "tool_fields_observed",
                                                   "slots_with_unexpected_calls", "unexpected_call_records")},
                       "matched_input_pairs": len(deltas),
                       "median_input_minus_official_a": median(deltas) if deltas else None})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bill = commands.add_parser("billing", help="reconcile category totals in one currency (USD)")
    bill.add_argument("csv", type=Path)
    bill.add_argument("--deduction-usd", required=True)
    measure = commands.add_parser("measurements", help="compare scheduled slots with an official reference")
    measure.add_argument("csv", type=Path)
    args = parser.parse_args()
    try:
        with args.csv.open(encoding="utf-8", newline="") as source:
            rows = csv.DictReader(source)
            if args.command == "billing":
                result = billing(rows, dollars(args.deduction_usd))
            else:
                result = measurements(rows)
    except (OSError, ValueError, InvalidOperation, KeyError, TypeError, csv.Error) as exc:
        parser.exit(2, f"Invalid measurement input: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
