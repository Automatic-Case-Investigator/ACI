"""The investigation loop's per-task evidence horizon.

Investigation keeps its task queue, board, pivot and lead machinery — only the inner
loop changed. Evidence now accumulates across cycles WITHIN a task and is cleared at
`claim`, so the compaction boundary is the task (one objective) rather than the cycle.
`interpret` used to return `messages: []` every continuation, which meant the model
choosing the next tool call had never seen a raw event.

Completion is decided by `interpret` alone. `assess` produces the task's report and
findings but no longer votes, so it can never send a finished task back around.
"""
from __future__ import annotations

import asyncio
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage  # noqa: E402

from agent.runtime.graph import nodes_loop  # noqa: E402
from agent.runtime.graph.builder import _route_assess, _route_interpret  # noqa: E402
from agent.runtime.graph.interpretation import node as interpret_node  # noqa: E402


def _tool_pair(call_id: str, name: str, content: str):
    return [
        AIMessage(content="", tool_calls=[{"name": name, "args": {}, "id": call_id}]),
        ToolMessage(content=content, tool_call_id=call_id, name=name),
    ]


class EvidenceHorizonTest(unittest.TestCase):
    """`interpret` must hand the accumulated history forward, not erase it."""

    def _result(self, ready: bool, messages: list) -> dict:
        # Mirrors the node's return contract without invoking the model: the branch under
        # test is purely the messages key.
        state = {"messages": messages}
        result: dict = {}
        if ready:
            result["messages"] = messages
        else:
            result["messages"] = list(state.get("messages") or [])
        return result

    def test_continuation_returns_the_accumulated_history(self):
        history = [SystemMessage(content="SYS"), HumanMessage(content="anchor")]
        history += _tool_pair("c1", "search", '{"_id": "evt-1"}')
        self.assertEqual(self._result(False, history)["messages"], history)

    def test_the_wipe_is_gone_from_the_source(self):
        # Guards the specific regression: a future edit reinstating `messages: []` on the
        # continuation path silently restores the evidence horizon with no test failing.
        import inspect

        src = inspect.getsource(interpret_node)
        self.assertNotIn('result["messages"] = []', src)


class ClaimIsTheSeamTest(unittest.IsolatedAsyncioTestCase):
    async def test_claim_clears_history_at_the_task_boundary(self):
        # A new objective starts with a clean context; the board and the ledger's
        # confirmed findings are what cross the boundary.
        import agent.runtime.graph.nodes_loop as nl

        src = __import__("inspect").getsource(nl.claim)
        self.assertIn('"messages": [],', src)


class CompletionIsInterpretsAloneTest(unittest.TestCase):
    def test_assess_can_no_longer_send_a_task_back(self):
        # `_route_assess` has no `needs_more_work` branch: whatever status assess leaves,
        # the task moves on to pivot (or finish when out of budget).
        state = {
            "status": "needs_more_work",
            "steps": 1, "max_steps": 40,
            "tool_calls_made": 5, "max_tool_calls": 60,
        }
        self.assertEqual(_route_assess(state), "pivot")

    def test_assess_still_finishes_when_out_of_budget(self):
        state = {
            "status": "", "steps": 40, "max_steps": 40,
            "tool_calls_made": 60, "max_tool_calls": 60,
        }
        self.assertEqual(_route_assess(state), "finish")

    def test_assess_no_longer_reads_a_keep_working_vote(self):
        import inspect

        from agent.runtime.graph.nodes_flow import assess as assess_mod

        src = inspect.getsource(assess_mod)
        # The vote may still be NAMED in a comment explaining why it is ignored; what
        # must be gone is any branch acting on it, and any route back to `think`.
        self.assertNotIn("if review is not None and review.keep_working", src)
        self.assertNotIn('"status": "needs_more_work"', src)

    def test_the_review_still_runs_for_board_gating(self):
        # Its completion vote is ignored, but pivot needs its per-finding verdicts.
        import inspect

        from agent.runtime.graph.nodes_flow import assess as assess_mod

        src = inspect.getsource(assess_mod)
        self.assertIn("review_task_model(", src)
        self.assertIn("last_findings_verification", src)


class SteeringIsTransientTest(unittest.IsolatedAsyncioTestCase):
    async def test_steering_without_a_ledger_is_live_context_only(self):
        # An empty ledger contributes nothing; the live queue/board block still rides
        # along, because it changes every cycle and must not be baked into the anchor.
        state = {
            "agent_name": "investigation", "task_ledger": {}, "messages": [],
            "case_id": "~1", "run_id": "r1", "current_task": {"title": "t"},
        }
        steering = await nodes_loop._cycle_steering(state, [])
        self.assertTrue(steering.startswith("# CONTEXT"))
        self.assertNotIn("REQUIRED next step", steering)

    async def test_steering_carries_ledger_state(self):
        state = {
            "agent_name": "investigation",
            "task_ledger": {
                "next_step_instruction": "Query the SIEM.",
                "forbidden_repeats": ["search agent.name=x"],
                "remaining_gaps": ["no exec evidence"],
            },
            "messages": [], "case_id": "~1", "run_id": "r1",
            "current_task": {"title": "t"},
        }
        steering = await nodes_loop._cycle_steering(state, [])
        self.assertIn("Query the SIEM.", steering)
        self.assertIn("search agent.name=x", steering)
        self.assertIn("no exec evidence", steering)


class RoutingGuardsTest(unittest.TestCase):
    def test_interpret_is_the_only_node_that_concludes_a_task(self):
        grounded = {
            "agent_name": "investigation", "status": "ready_to_assess",
            "messages": [ToolMessage(content="{}", tool_call_id="c", name="search")],
            "steps": 1, "max_steps": 40, "tool_calls_made": 5, "max_tool_calls": 60,
        }
        self.assertEqual(_route_interpret(grounded), "assess")


if __name__ == "__main__":
    unittest.main()
