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


class AnchorEchoTest(unittest.TestCase):
    """The harness injects an incident timestamp into the agent's question; a bare
    restatement of it must NOT credit phase_recall for the phase whose window contains
    it. Regression: fox privesc/2 concluded FP with zero retrieved evidence yet scored
    the privilege_escalation phase 'reached' purely from echoing 2022-01-18T13:14:31Z.
    """

    ANCHOR = "2022-01-18T13:14:31Z"  # falls inside the privilege_escalation window

    def _score(self, report_text: str):
        ctx = ScoringContext.build(
            _SCENARIO, report_text, entry_point="privilege_escalation",
            meta={"anchor_timestamp": self.ANCHOR},
        )
        (result,) = scoring.run_all(ctx, ["phase_recall"])
        return result

    def test_bare_anchor_echo_does_not_credit_phase(self):
        # The echoed question line: anchor timestamp, no event id → hollow, not reached.
        report = ("**Question:** Triage and investigate alert ~1. The alert corresponds "
                  "to activity observed around 2022-01-18T13:14:31Z.")
        self.assertFalse(self._score(report).value["privilege_escalation"])

    def test_anchor_cited_with_event_id_still_credits_phase(self):
        # A genuine retrieval: the anchor instant alongside a real event id → reached.
        report = "- `2022-01-18T13:14:31Z` — `eYzntgXUZwhw5Nh_-HUS`: su/UID change to phopkins."
        self.assertTrue(self._score(report).value["privilege_escalation"])

    def test_distinct_in_window_event_still_credits_despite_echo(self):
        # Echoed anchor (no id) PLUS a distinct in-window event (with id) → reached via the real one.
        report = ("**Question:** …activity observed around 2022-01-18T13:14:31Z.\n"
                  "- `2022-01-18T13:14:49Z` — `3kp8gZqt29xgUPf7VD3i`: sudo cat /etc/shadow.")
        self.assertTrue(self._score(report).value["privilege_escalation"])

    def test_no_anchor_meta_preserves_legacy_behavior(self):
        # Without an injected anchor, a bare in-window timestamp still counts (unchanged).
        report = "- 2022-01-18T13:14:31Z — activity noted."
        ctx = ScoringContext.build(_SCENARIO, report, entry_point="privilege_escalation")
        (result,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertTrue(result.value["privilege_escalation"])


class InvalidTrialExclusionTest(unittest.TestCase):
    """A trial where the requested agent failed (trial_valid=False) must be excluded
    from the recall roll-up — regression: an infra Connection error fell back to the
    triage report and was scored as a real recall-0 trial (privesc/3)."""

    def _card(self, *, trial, valid, webshell_hit):
        r = _phase_result(
            "Confirmed via `2022-01-18T12:38:29Z` (`w2X30PYVatKFcWqVUjiG`)." if webshell_hit else "nothing."
        )
        return {
            "scenario": "toy", "entry_point": "recon", "trial": trial,
            "status": "completed" if valid else "failed", "trial_valid": valid,
            "results": [{"name": r.name, "kind": r.kind, "value": r.value, "detail": r.detail}],
        }

    def test_invalid_trial_excluded_from_rollup(self):
        from benchmark.pipeline.report import aggregate_cards
        cards = [
            self._card(trial=1, valid=True, webshell_hit=True),   # real hit
            self._card(trial=2, valid=False, webshell_hit=False),  # infra failure → must not count
        ]
        agg = aggregate_cards(cards)["toy"]["recon"]
        self.assertEqual(agg["trials"], 1)            # only the valid trial
        self.assertEqual(agg["excluded_trials"], 1)
        self.assertEqual(agg["metrics"]["phase_recall"]["per_key"]["webshell"], 1.0)  # not diluted to 0.5


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
