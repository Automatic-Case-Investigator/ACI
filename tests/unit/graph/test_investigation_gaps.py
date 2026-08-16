"""The three gaps session 6b96293a exposed.

1. The evidence floor only covered the `interpret → assess` completion path. A reply
   with no tool calls routes `think → assess` directly, so three tasks concluded on
   orientation alone and the board dropped every bullet as restated.
2. `_unqueried_time_ranges` / `_unqueried_post_peak_clusters` were computed for a
   reviewer whose vote no longer gates completion — the volume tool handed the agent
   `2022-01-18T13:00` as an unqueried post-peak bin and nothing acted on it.
3. Kill-chain gap leads are written straight to the queue, bypassing the lead
   validator. Four of them duplicated the triage plan at priority 88, outranking the
   plan items they duplicated.
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)  # noqa: E402

from agent.runtime.analysis.kill_chain import drop_covered_specs  # noqa: E402
from agent.runtime.graph import nodes_loop  # noqa: E402
from agent.runtime.graph.interpretation.prompt import _coverage_block  # noqa: E402

# ── 1. the evidence floor on the think → assess path ────────────────────────────


class _StubBound:
    def __init__(self, tools):
        self.tools = tools


class _StubModel:
    def bind_tools(self, tools):
        return _StubBound(tools)


def _orientation_history():
    """A task that only oriented: no evidence tool anywhere in its history."""
    return [
        SystemMessage(content="SYS"),
        HumanMessage(content="# USER\nanchor"),
        AIMessage(
            content="", tool_calls=[{"name": "list_tasks", "args": {}, "id": "c1"}]
        ),
        ToolMessage(content="[]", tool_call_id="c1", name="list_tasks"),
    ]


class ThinkEvidenceFloorTest(unittest.TestCase):
    def setUp(self):
        self._replies = []
        self._sent = []

        async def _capture(bound, messages, agent_name):
            self._sent.append(messages)
            return self._replies.pop(0)

        self._orig = nodes_loop.nodes._invoke_bound_model
        nodes_loop.nodes._invoke_bound_model = _capture

    def tearDown(self):
        nodes_loop.nodes._invoke_bound_model = self._orig

    def _state(self, **over):
        base = dict(
            agent_name="investigation",
            messages=_orientation_history(),
            current_task={"title": "t", "description": "d"},
            task_ledger={},
            tool_calls_made=4,
            task_call_floor=0,
            max_tool_calls=60,
            ctx_tokens=0,
            steps=3,
            default_vicinity_window_hours=24,
            case_id="~1",
            run_id="r1",
        )
        base.update(over)
        return base

    def _config(self):
        return {
            "configurable": {"model": _StubModel(), "tools": [], "system_prompt": "SYS"}
        }

    def test_a_zero_evidence_conclusion_is_pushed_back_to_the_siem(self):
        self._replies = [
            AIMessage(content="## Findings\n- restated from an earlier task"),
            AIMessage(
                content="", tool_calls=[{"name": "search", "args": {}, "id": "c2"}]
            ),
        ]
        out = asyncio.run(nodes_loop.think(self._state(), self._config()))
        self.assertTrue(
            getattr(out["messages"][-1], "tool_calls", None),
            "floor must convert the conclusion into an evidence query",
        )
        nudge = "\n".join(str(getattr(m, "content", "")) for m in self._sent[-1])
        self.assertIn("without having run a single SIEM evidence query", nudge)

    def test_it_gives_up_after_one_retry(self):
        # A model that insists on concluding must not loop the node forever.
        self._replies = [
            AIMessage(content="## Findings\n- none"),
            AIMessage(content="## Findings\n- still none"),
        ]
        out = asyncio.run(nodes_loop.think(self._state(), self._config()))
        self.assertEqual(len(self._sent), 2)
        self.assertFalse(getattr(out["messages"][-1], "tool_calls", None))

    def test_a_task_with_evidence_is_left_alone(self):
        history = _orientation_history() + [
            AIMessage(
                content="", tool_calls=[{"name": "search", "args": {}, "id": "c9"}]
            ),
            ToolMessage(content='{"total": 2}', tool_call_id="c9", name="search"),
        ]
        self._replies = [AIMessage(content="## Findings\n- grounded")]
        asyncio.run(nodes_loop.think(self._state(messages=history), self._config()))
        self.assertEqual(len(self._sent), 1, "no floor retry when evidence exists")

    def test_triage_is_not_subject_to_this_floor(self):
        # Triage runs its own flat loop with its own floor.
        self._replies = [AIMessage(content="## Triage Summary\n- x")]
        asyncio.run(nodes_loop.think(self._state(agent_name="triage"), self._config()))
        self.assertEqual(len(self._sent), 1)


# ── 2. coverage gaps reach the completion judge ─────────────────────────────────


class CoverageBlockTest(unittest.TestCase):
    def test_unqueried_spans_are_stated_as_blocking_completion(self):
        text = _coverage_block(
            {
                "unqueried_time_ranges": ["2022-01-18T13:00:00Z..2022-01-18T18:00:00Z"],
                "unqueried_post_peak_clusters": [],
            }
        )
        self.assertIn("2022-01-18T13:00:00Z", text)
        self.assertIn("NOT done", text)

    def test_post_peak_clusters_are_named(self):
        text = _coverage_block({"unqueried_clusters": ["2022-01-18T13:00:00Z"]})
        self.assertIn("post-peak", text)
        self.assertIn("2022-01-18T13:00:00Z", text)

    def test_nothing_is_rendered_when_coverage_is_complete(self):
        self.assertEqual(_coverage_block({}), "")
        self.assertEqual(_coverage_block(None), "")
        self.assertEqual(
            _coverage_block({"unqueried_clusters": [], "unqueried_time_ranges": []}), ""
        )


# ── 3. gap leads do not duplicate the queued plan ───────────────────────────────


class GapLeadDedupTest(unittest.TestCase):
    def _specs(self):
        return [
            {
                "tactic": "Execution",
                "priority": 88,
                "title": "Trace forward to Execution on h",
            },
            {
                "tactic": "Command and Control",
                "priority": 88,
                "title": "Trace forward to C2 on h",
            },
            {
                "tactic": "Exfiltration",
                "priority": 88,
                "title": "Trace forward to Exfiltration on h",
            },
            {
                "tactic": "Impact",
                "priority": 88,
                "title": "Trace forward to Impact on h",
            },
        ]

    def test_the_live_duplication_is_dropped(self):
        # The triage plan already queued an execution item and a C2/callback item.
        queued = [
            {
                "title": "Confirm or refute execution after the SSH successes",
                "description": "",
            },
            {
                "title": "Trace C2 or outbound callback from 172.17.130.196",
                "description": "",
            },
        ]
        kept = [s["tactic"] for s in drop_covered_specs(self._specs(), queued)]
        self.assertEqual(kept, ["Exfiltration", "Impact"])

    def test_a_synonym_in_the_description_counts_as_covered(self):
        queued = [{"title": "Check host", "description": "look for privesc via sudo"}]
        specs = [{"tactic": "Privilege Escalation", "priority": 88, "title": "x"}]
        self.assertEqual(drop_covered_specs(specs, queued), [])

    def test_an_empty_queue_drops_nothing(self):
        self.assertEqual(len(drop_covered_specs(self._specs(), [])), 4)

    def test_unrelated_tasks_drop_nothing(self):
        queued = [
            {"title": "Retrieve syscheck diff for /etc/passwd", "description": ""}
        ]
        self.assertEqual(len(drop_covered_specs(self._specs(), queued)), 4)


if __name__ == "__main__":
    unittest.main()
