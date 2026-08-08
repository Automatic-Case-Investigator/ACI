"""The deterministic evidence floor that vetoes a hollow completion.

A task that retrieved nothing has not investigated anything, so its vote to conclude
is not credible. The floor is a routing predicate in `_route_interpret` — it can only
VETO a completion decision, never initiate one. It used to be a retry loop inside the
`assess` node, which made `assess` a second completion judge alongside `interpret`.

The floor is only as good as the `_count_evidence_queries` signal it reads: if an
orientation tool were ever miscounted as evidence, it would silently stop firing. This
reproduces the live failure on session e235b354 — tasks that called only `get_case` /
`get_board` / `search_patterns` / `ls` and were wrongly allowed to conclude — and pins
the orientation-vs-evidence boundary so it cannot regress.
"""

from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import ToolMessage  # noqa: E402

from agent.runtime.graph.builder import _route_interpret  # noqa: E402
from agent.runtime.graph.nodes_flow import _count_evidence_queries  # noqa: E402


def _tool(name: str, content: str = "{}") -> ToolMessage:
    return ToolMessage(name=name, tool_call_id=name, content=content)


class CountEvidenceQueriesTest(unittest.TestCase):
    def test_orientation_only_history_counts_zero(self):
        # The exact orientation set the live zero-query tasks used.
        msgs = [
            _tool("get_case"),
            _tool("list_case_alerts"),
            _tool("get_board"),
            _tool("list_tasks"),
            _tool("search_patterns"),
            _tool("search_feedback"),
            _tool("ls"),
            _tool("cat"),
            _tool("whoami"),
            _tool("home"),
        ]
        self.assertEqual(_count_evidence_queries(msgs), 0)

    def test_each_siem_tool_counts(self):
        for name in (
            "search",
            "search_keyword",
            "profile_field",
            "get_event_volume",
            "correlate_entity",
            "correlate_techniques",
            "get_event",
        ):
            self.assertEqual(_count_evidence_queries([_tool(name)]), 1, name)

    def test_errored_evidence_result_is_not_credited(self):
        # A failed query is not investigation — the floor must still fire.
        self.assertEqual(
            _count_evidence_queries([_tool("search", '{"error": "parse failed"}')]), 0
        )

    def test_mixed_history_counts_only_evidence(self):
        msgs = [
            _tool("get_case"),
            _tool("search_patterns"),
            _tool("ls"),
            _tool("get_event_volume", '{"total": 100}'),
            _tool("search", '{"total": 5, "events": [{"_id": "e1"}]}'),
        ]
        self.assertEqual(_count_evidence_queries(msgs), 2)


class RouteInterpretEvidenceFloorTest(unittest.TestCase):
    """`interpret` owns the completion decision; the floor can only veto it."""

    def _state(self, **over):
        base = dict(
            agent_name="investigation",
            status="ready_to_assess",
            messages=[_tool("search", '{"total": 3}')],
            steps=5,
            max_steps=40,
            tool_calls_made=10,
            max_tool_calls=60,
        )
        base.update(over)
        return base

    def test_a_grounded_completion_is_accepted(self):
        self.assertEqual(_route_interpret(self._state()), "assess")

    def test_a_zero_evidence_completion_is_sent_back(self):
        state = self._state(messages=[_tool("get_case"), _tool("get_board")])
        self.assertEqual(_route_interpret(state), "think")

    def test_an_errored_query_does_not_satisfy_the_floor(self):
        state = self._state(messages=[_tool("search", '{"error": "boom"}')])
        self.assertEqual(_route_interpret(state), "think")

    def test_the_floor_never_initiates_completion(self):
        # Evidence present but interpret has NOT voted to conclude — stay in the loop.
        self.assertEqual(
            _route_interpret(self._state(status="needs_more_work")), "think"
        )

    def test_budget_exhaustion_still_wins_over_the_floor(self):
        # A run out of budget must finish, not loop back for evidence it cannot gather.
        state = self._state(messages=[_tool("get_case")], tool_calls_made=60)
        self.assertEqual(_route_interpret(state), "finish")

    def test_cancellation_wins_over_the_floor(self):
        state = self._state(status="cancelled", messages=[_tool("get_case")])
        self.assertEqual(_route_interpret(state), "finish")

    def test_the_floor_is_investigation_only(self):
        # Triage never reaches this router, and other agents keep the plain contract.
        state = self._state(agent_name="seeder", messages=[_tool("get_case")])
        self.assertEqual(_route_interpret(state), "assess")


if __name__ == "__main__":
    unittest.main(verbosity=2)
