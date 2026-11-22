"""Recount the published round-to-round flags and primary price test in Table III."""

import csv
from collections import Counter
from fractions import Fraction
from math import comb
from pathlib import Path


def flagged(code, index):
    if not code:
        return None
    if len(code) not in (1, 4) or set(code) - set("CSN"):
        raise ValueError(f"Unexpected Table III code: {code!r}")
    return code[index if len(code) == 4 else 0] in "CS"


def fisher_price_p(low, other):
    """Two-sided exact p, conditional on row and column totals."""
    flagged_low, n_low = low
    flagged_other, n_other = other
    positives = flagged_low + flagged_other
    def weight(i):
        return comb(n_low, i) * comb(n_other, positives - i)

    support = range(max(0, positives - n_other), min(n_low, positives) + 1)
    observed = weight(flagged_low)
    tail = sum(weight(i) for i in support if weight(i) <= observed)
    return Fraction(tail, comb(n_low + n_other, positives))


def main():
    with Path(__file__).with_name("table-iii.csv").open(newline="") as source:
        rows = list(csv.DictReader(source))
    specs = ("primary/miss", "primary/exclude", "alternate/miss", "alternate/exclude")

    print("scoring             paired  both  lost  gained  neither")
    for index, spec in enumerate(specs):
        transitions = Counter()
        for row in rows:
            for model in ("astra", "opus"):
                first = flagged(row[f"{model}_r1"], index)
                second = flagged(row[f"{model}_r2"], index)
                if first is not None and second is not None:
                    transitions[first, second] += 1
        counts = [transitions[pair] for pair in ((True, True), (True, False),
                                                  (False, True), (False, False))]
        print(f"{spec:<19} {sum(counts):>6} {counts[0]:>5} {counts[1]:>5} "
              f"{counts[2]:>7} {counts[3]:>8}")

    groups = {"low": [], "same/higher": []}
    for row in rows:
        labels = [flagged(row[f"{model}_r1"], 0) for model in ("astra", "opus")]
        if any(x is not None for x in labels):
            group = "low" if row["price_group"] == "low" else "same/higher"
            groups[group].append(any(labels))
    low, other = [(sum(flags), len(flags)) for flags in groups.values()]
    print(f"Round 1 primary, services: low {low[0]}/{low[1]}, "
          f"same/higher {other[0]}/{other[1]}, Fisher p={float(fisher_price_p(low, other)):.4f}")


if __name__ == "__main__":
    main()
