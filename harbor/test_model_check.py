"""Test the model comparison report without a model server.

From the repository root, run:
    python3 -m unittest discover -s harbor -p test_model_check.py -v
"""

from __future__ import annotations

import unittest

import model_check


def model(label: str, decisions: list[str]) -> dict:
    return {
        "label": label,
        "cases": [
            {"case": f"case-{index}", "passed": True, "failures": [],
             "seconds": 1.0, "records": [{"decision": decision}]}
            for index, decision in enumerate(decisions)
        ],
    }


class ComparisonTests(unittest.TestCase):
    def test_identical_decisions_agree_on_every_case(self) -> None:
        comparison = model_check.compare([
            model("a", ["accept", "reject"]),
            model("b", ["accept", "reject"]),
        ])
        self.assertEqual(comparison["agreement"], 2)
        self.assertEqual(comparison["differences"], 0)
        self.assertTrue(all(row["agrees"] for row in comparison["cases"]))

    def test_different_decisions_are_named_per_case(self) -> None:
        comparison = model_check.compare([
            model("a", ["accept", "escalate"]),
            model("b", ["reject", "escalate"]),
        ])
        self.assertEqual(comparison["agreement"], 1)
        self.assertEqual(comparison["differences"], 1)
        first = comparison["cases"][0]
        self.assertFalse(first["agrees"])
        self.assertEqual(first["decisions"], {"a": ["accept"], "b": ["reject"]})
        self.assertEqual(comparison["seconds"], {"a": 2.0, "b": 2.0})

    def test_different_case_orders_are_refused(self) -> None:
        first = model("a", ["accept"])
        second = model("b", ["accept"])
        second["cases"][0]["case"] = "another-case"
        with self.assertRaises(RuntimeError):
            model_check.compare([first, second])

    def test_failures_stay_with_their_model(self) -> None:
        first = model("a", ["accept"])
        second = model("b", ["accept"])
        second["cases"][0]["failures"] = ["main must keep the change"]
        comparison = model_check.compare([first, second])
        self.assertEqual(comparison["failures"], {
            "a": [],
            "b": ["case-0: main must keep the change"],
        })


if __name__ == "__main__":
    unittest.main()
