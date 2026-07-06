"""Unit tests for the deterministic evidence-floor signal (nodes_flow).

The investigation gating node re-injects a "query the SIEM" correction whenever a
task concluded with zero evidence queries. That backstop is only as good as the
`_count_evidence_queries` signal it reads: if an orientation tool were ever
miscounted as evidence, the floor would silently stop firing. This reproduces the
live failure on session e235b354 — tasks that called only `get_case` / `get_board`
/ `search_patterns` / `ls` and were wrongly allowed to conclude — and pins the
orientation-vs-evidence boundary so it cannot regress.
"""
from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import ToolMessage  # noqa: E402

from agent.runtime.graph.nodes_flow import (  # noqa: E402
    _MAX_INVESTIGATION_RETRIES,
    _count_evidence_queries,
    _progress_gated_decision,
)


def _tool(name: str, content: str = "{}") -> ToolMessage:
    return ToolMessage(name=name, tool_call_id=name, content=content)


class CountEvidenceQueriesTest(unittest.TestCase):
    def test_orientation_only_history_counts_zero(self):
        # The exact orientation set the live zero-query tasks used.
        msgs = [
            _tool("get_case"), _tool("list_case_alerts"), _tool("get_board"),
            _tool("list_tasks"), _tool("search_patterns"), _tool("search_feedback"),
            _tool("ls"), _tool("cat"), _tool("whoami"), _tool("home"),
        ]
        self.assertEqual(_count_evidence_queries(msgs), 0)

    def test_each_siem_tool_counts(self):
        for name in ("search", "search_keyword", "profile_field", "get_event_volume",
                     "correlate_entity", "correlate_techniques", "get_event"):
            self.assertEqual(_count_evidence_queries([_tool(name)]), 1, name)

    def test_errored_evidence_result_is_not_credited(self):
        # A failed query is not investigation — the floor must still fire.
        self.assertEqual(
            _count_evidence_queries([_tool("search", '{"error": "parse failed"}')]), 0
        )

    def test_mixed_history_counts_only_evidence(self):
        msgs = [
            _tool("get_case"), _tool("search_patterns"), _tool("ls"),
            _tool("get_event_volume", '{"total": 100}'),
            _tool("search", '{"total": 5, "events": [{"_id": "e1"}]}'),
        ]
        self.assertEqual(_count_evidence_queries(msgs), 2)


class ProgressGatedDecisionTest(unittest.TestCase):
    """Investigation keep-working is progress-gated, not flat-capped: continue while the
    task converges and budget remains, stop when it stalls or budget runs out."""

    def _decide(self, **over):
        base = dict(
            reflection_retries=1, evidence_queries=3, last_nudge_ev=1,
            tool_calls_made=40, max_tool_calls=100, steps=20, max_steps=60,
        )
        base.update(over)
        return _progress_gated_decision(**base)

    def test_continues_while_making_progress_and_budget_left(self):
        # 3 evidence queries now vs 1 at the last nudge → new evidence → keep going.
        keep, reason = self._decide(evidence_queries=3, last_nudge_ev=1)
        self.assertTrue(keep)
        self.assertEqual(reason, "")

    def test_deep_cycle_still_continues_if_progressing(self):
        # Cycle 5 — well past the old flat cap of 2 — still continues when converging.
        keep, _ = self._decide(reflection_retries=5, evidence_queries=6, last_nudge_ev=4)
        self.assertTrue(keep)

    def test_stalls_when_no_new_evidence_since_last_nudge(self):
        keep, reason = self._decide(reflection_retries=2, evidence_queries=3, last_nudge_ev=3)
        self.assertFalse(keep)
        self.assertIn("no new evidence", reason)

    def test_first_cycle_is_never_a_stall(self):
        # retry 0: no prior nudge to compare against → progress assumed.
        keep, _ = self._decide(reflection_retries=0, evidence_queries=0, last_nudge_ev=-1)
        self.assertTrue(keep)

    def test_stops_when_global_call_budget_exhausted(self):
        keep, reason = self._decide(tool_calls_made=100, max_tool_calls=100)
        self.assertFalse(keep)
        self.assertIn("budget exhausted", reason)

    def test_stops_when_global_step_budget_exhausted(self):
        keep, reason = self._decide(steps=60, max_steps=60)
        self.assertFalse(keep)
        self.assertIn("budget exhausted", reason)

    def test_safety_backstop_caps_runaway_loops(self):
        keep, reason = self._decide(reflection_retries=_MAX_INVESTIGATION_RETRIES,
                                    evidence_queries=99, last_nudge_ev=1)
        self.assertFalse(keep)
        self.assertIn("safety cap", reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
