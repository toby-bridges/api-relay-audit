"""Regression checks for the offline R11 and matched-slot replays."""
import csv
import unittest
from decimal import Decimal
from pathlib import Path

from scripts.experiments.replay_relay_measurements import ARMS, billing, measurements


class MeasurementReplayTests(unittest.TestCase):
    def test_published_r11_collection(self):
        table = Path(__file__).resolve().parents[1] / "docs/measurements/wu-2026-r11.csv"
        with table.open() as f:
            rows = list(csv.DictReader(f))
        result = billing(rows, Decimal("1.2011"))
        self.assertEqual(Decimal(result["model_usd"]["Astra"]), Decimal("0.39640320"))
        self.assertEqual(result["model_usd"]["Opus"], "0.80467075")
        self.assertEqual(result["calculated_usd"], "1.20107395")
        self.assertEqual(result["deduction_minus_calculated_usd"], "0.00002605")
        with self.assertRaises(ValueError):
            billing(rows[:-1], Decimal("1.2011"))
        with self.assertRaises(ValueError):
            billing(rows + rows[:1], Decimal("1.2011"))

    def test_paired_usage_and_returned_records_have_distinct_coverage(self):
        rows = []
        for trial in ("1", "2"):
            for arm in ARMS:
                row = dict(round="r1", case="echo", trial=trial, permission="disabled",
                           arm=arm, outcome="answer", tool_calls="0", input_total="10")
                if arm == "relay":
                    row.update(outcome="unparseable" if trial == "1" else "refusal",
                               tool_calls="2" if trial == "1" else "", input_total="18")
                elif arm == "transparent":
                    row.update(outcome="missing", tool_calls="", input_total="")
                rows.append(row)
        result = {item["arm"]: item for item in measurements(rows)}
        relay = result["relay"]
        self.assertEqual((relay["scheduled"], relay["refusal"], relay["unparseable"]), (2, 1, 1))
        self.assertEqual((relay["tool_fields_observed"], relay["slots_with_unexpected_calls"],
                          relay["unexpected_call_records"]), (1, 1, 2))
        self.assertEqual((relay["matched_input_pairs"], relay["median_input_minus_official_a"]), (1, 8))
        self.assertIsNone(result["transparent"]["median_input_minus_official_a"])
        self.assertEqual(result["transparent"]["missing"], 2)
        for invalid in (rows[:-1], rows + rows[:1]):
            with self.assertRaises(ValueError):
                measurements(invalid)
