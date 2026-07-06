"""Offline unit tests for the phase_recall metric and the scoring plumbing.

Pure functions of a ScoringContext — no Django, no live services — so they run in
the normal offline suite.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, _ROOT)

from benchmark import scoring  # noqa: E402
from benchmark.scoring import ScenarioSpec, ScoringContext  # noqa: E402
from benchmark.pipeline import report as report_stage  # noqa: E402
from benchmark.pipeline.score import metric_rows  # noqa: E402

# A minimal two-phase scenario built inline, independent of fox.yaml, so the logic
# is tested in isolation from the (evolving) real spec.
_SCENARIO = ScenarioSpec.from_dict({
    "name": "toy",
    "phases": [
        {"name": "webshell", "start": "2022-01-18T12:38:00Z", "end": "2022-01-18T12:38:30Z",
         "agent_id": "27", "marker_event_ids": ["1700000000.110408"]},
        {"name": "privilege_escalation", "start": "2022-01-18T13:14:30Z", "end": "2022-01-18T13:14:53Z",
         "agent_id": "27", "marker_event_ids": ["1700000000.110417"]},
    ],
})


def _phase_result(report_text: str):
    ctx = ScoringContext.build(_SCENARIO, report_text, entry_point="recon")
    (result,) = scoring.run_all(ctx, ["phase_recall"])
    return result


class PhaseRecallTest(unittest.TestCase):
    def test_timestamp_in_window_reaches_phase(self):
        report = "## Confirmed Timeline\n- `2022-01-18T12:38:29Z` — web hit (`w2X30PYVatKFcWqVUjiG`)."
        r = _phase_result(report)
        self.assertEqual(r.kind, "per_key")
        self.assertTrue(r.value["webshell"])                 # ts inside webshell window
        self.assertFalse(r.value["privilege_escalation"])    # nothing in privesc window
        self.assertEqual(r.detail["reached"], 1)
        self.assertEqual(r.detail["missed"], ["privilege_escalation"])

    def test_marker_event_id_reaches_phase(self):
        # No timestamp at all — only the discriminating AMiner marker id is cited.
        report = "Confirmed privilege escalation via `1700000000.110417`."
        r = _phase_result(report)
        self.assertTrue(r.value["privilege_escalation"])
        self.assertFalse(r.value["webshell"])

    def test_recon_only_report_misses_post_exploitation(self):
        # The canonical Fox failure: cites only the recon alert, reaches neither phase.
        report = "## Confirmed Timeline\n- `2022-01-18T12:19:10Z` — scan alert (`~449101824`)."
        r = _phase_result(report)
        self.assertEqual(r.detail["reached"], 0)
        self.assertFalse(any(r.value.values()))

    def test_rule_numbers_do_not_over_credit(self):
        # Mentioning a rule number in passing must NOT mark a phase reached (rules are
        # shared across phases; only event-ids / windows count).
        report = "The webshell rule 31108 is noisy but nothing was confirmed."
        r = _phase_result(report)
        self.assertEqual(r.detail["reached"], 0)


class FoxSpecTest(unittest.TestCase):
    def test_fox_scenario_loads(self):
        path = os.path.join(_ROOT, "benchmark", "config", "scenarios", "fox.yaml")
        spec = ScenarioSpec.from_yaml(path)
        self.assertEqual(spec.name, "fox")
        self.assertEqual(len(spec.phases), 10)
        # every phase parsed a valid window
        self.assertTrue(all(p.start and p.end and p.end >= p.start for p in spec.phases))
        # entry points tagged organic vs synthetic
        kinds = {e.id: e.kind for e in spec.entry_points}
        self.assertEqual(kinds["recon"], "organic")
        self.assertEqual(kinds["privilege_escalation"], "synthetic")


class PandasFriendlyOutputTest(unittest.TestCase):
    def test_metric_rows_flattens_per_key_values(self):
        r = _phase_result("Confirmed via `2022-01-18T12:38:29Z`.")
        card = {
            "scenario": "toy",
            "entry_point": "recon",
            "trial": 1,
            "status": "completed",
            "results": [
                {
                    "name": r.name,
                    "kind": r.kind,
                    "value": r.value,
                    "detail": r.detail,
                }
            ],
        }

        rows = metric_rows(card)

        self.assertEqual(len(rows), 2)
        by_key = {row["key"]: row for row in rows}
        self.assertTrue(by_key["webshell"]["value"])
        self.assertFalse(by_key["privilege_escalation"]["value"])
        self.assertEqual(by_key["webshell"]["metric"], "phase_recall")
        self.assertEqual(by_key["webshell"]["detail_recall"], 0.5)
        self.assertEqual(by_key["webshell"]["detail_missed"], '["privilege_escalation"]')

    def test_report_writes_scenario_csv(self):
        cards = [
            {
                "scenario": "toy",
                "entry_point": "recon",
                "trial": 1,
                "status": "completed",
                "results": [
                    {
                        "name": "phase_recall",
                        "kind": "per_key",
                        "value": {"webshell": True, "privilege_escalation": False},
                        "detail": {"reached": 1, "total": 2, "recall": 0.5, "missed": ["privilege_escalation"]},
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            report_stage.run(cards, tmp)
            csv_text = (Path(tmp) / "toy.csv").read_text(encoding="utf-8")

        self.assertIn("metric", csv_text)
        self.assertIn("phase_recall", csv_text)
        self.assertIn("webshell", csv_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
