"""The flat triage loop.

Triage was reworked from the ledger loop (`think → use_tools → interpret → assess`,
which wiped `messages` to `[]` every cycle) to an orchestrator-style flat loop that
keeps one growing history. These tests pin the property that motivated the change —
raw evidence stays visible across cycles — plus the guards rebuilt in its place.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest

project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
os.environ.setdefault("TASKQUEUE_DB_PATH", tempfile.mktemp(suffix=".db"))
os.environ.setdefault("BOARD_DB_PATH", tempfile.mktemp(suffix=".db"))

import django

django.setup()

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage

from agent.runtime.graph.agent_graphs import (
    build_investigation_graph,
    build_triage_graph,
)
from agent.runtime.graph.agent_graphs.investigation import (
    _route_use_tools as _route_investigation_use_tools,
)
from agent.runtime.graph.agent_graphs.triage import _route_triage_think
from agent.runtime.graph.state import AgentState
from agent.runtime.graph.triage_flat import (
    _MIN_EVIDENCE_CALLS,
    _deficiency,
    _evidence_call_count,
    build_triage_objective,
    triage_think,
)

_GOOD_REPORT = (
    "## Triage Summary\nA su session opened for phopkins.\n\n"
    "## Key Evidence\n- Event `evt-1` shows `sudo /bin/cat /etc/shadow`.\n\n"
    "## Investigation Plan\n1. Trace the access path from 2022-01-18T12:00:00Z to 2022-01-18T14:00:00Z.\n"
)


class _Tool:
    def __init__(self, name, payload=None):
        self.name = name
        self._payload = payload if payload is not None else {"ok": True}

    async def ainvoke(self, args):
        return json.dumps(self._payload)


class _ScriptedModel(BaseChatModel):
    """Replays scripted AIMessages, recording what it was shown on each call."""

    def __init__(self, script):
        super().__init__()
        object.__setattr__(self, "_script", list(script))
        object.__setattr__(self, "seen", [])

    @property
    def _llm_type(self):
        return "scripted"

    def _generate(self, *a, **k):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        self.seen.append(list(messages))
        if self._script:
            return self._script.pop(0)
        return AIMessage(content=_GOOD_REPORT)


def _state(**over):
    base = dict(
        run_id="r1",
        case_id="~1",
        source_entity_id="~1",
        source_entity_type="alert",
        agent_name="triage",
        question="What happened in alert ~1?",
        handoff=None,
        current_task=None,
        last_completed_task=None,
        messages=[],
        steps=0,
        tool_calls_made=0,
        max_steps=16,
        max_tool_calls=40,
        default_vicinity_window_hours=24,
        status="running",
        final_answer="",
        ctx_tokens=0,
        verdict=None,
    )
    base.update(over)
    return AgentState(**base)


def _config(model, tools=None):
    return {
        "configurable": {
            "model": model,
            "tools": (
                tools if tools is not None else [_Tool("search"), _Tool("get_event")]
            ),
            "system_prompt": "You are a triage agent.",
        }
    }


class AnchorTests(unittest.TestCase):
    def test_objective_leads_with_the_analysts_literal_question(self):
        objective = build_triage_objective(_state())
        self.assertIn("What happened in alert ~1?", objective)
        # The stop condition must be framed on answering, not on running steps.
        self.assertIn("answered", objective.lower())

    def test_objective_carries_the_configured_vicinity_window(self):
        self.assertIn(
            "±48 hours",
            build_triage_objective(_state(default_vicinity_window_hours=48)),
        )


class EvidenceFloorTests(unittest.TestCase):
    def test_counts_only_evidence_tools(self):
        msgs = [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "search", "args": {}, "id": "1"},
                    {"name": "write", "args": {}, "id": "2"},
                ],
            ),
            AIMessage(
                content="", tool_calls=[{"name": "get_event", "args": {}, "id": "3"}]
            ),
        ]
        self.assertEqual(_evidence_call_count(msgs), 2)

    def test_well_formed_report_is_rejected_without_enough_evidence(self):
        problem = _deficiency(_GOOD_REPORT, [])
        self.assertIn("not enough to ground", problem)

    def test_report_shape_is_checked_once_evidence_is_sufficient(self):
        msgs = [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "search", "args": {}, "id": str(i)},
                ],
            )
            for i in range(_MIN_EVIDENCE_CALLS)
        ]
        self.assertEqual(_deficiency(_GOOD_REPORT, msgs), "")
        self.assertIn("missing", _deficiency("just a blob", msgs))


class FlatHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_raw_tool_results_survive_into_the_next_cycle(self):
        """The core property: the model choosing the next call sees prior raw events.

        The old ledger loop returned `messages: []` from `interpret`, so this
        history was destroyed every cycle and only ≤8 prose bullets survived.
        """
        model = _ScriptedModel(
            [
                AIMessage(content="intent"),  # per-cycle public intent
                AIMessage(content=_GOOD_REPORT),
            ]
        )
        raw = '{"_id": "evt-1", "full_log": "sudo /bin/cat /etc/shadow"}'
        prior = [
            AIMessage(
                content="", tool_calls=[{"name": "search", "args": {}, "id": "c1"}]
            ),
            ToolMessage(content=raw, tool_call_id="c1", name="search"),
        ]
        await triage_think(
            _state(messages=prior, steps=1, tool_calls_made=3), _config(model)
        )

        # The final model call must still contain the raw event text verbatim.
        shown = "\n".join(str(getattr(m, "content", "")) for m in model.seen[-1])
        self.assertIn("sudo /bin/cat /etc/shadow", shown)

    async def test_tool_calls_route_onward_without_a_final_answer(self):
        model = _ScriptedModel(
            [
                AIMessage(content="intent"),
                AIMessage(
                    content="", tool_calls=[{"name": "search", "args": {}, "id": "c1"}]
                ),
            ]
        )
        out = await triage_think(_state(), _config(model))
        self.assertNotIn("final_answer", out)
        self.assertEqual(
            _route_triage_think({**_state(), **out, "status": "running"}), "use_tools"
        )

    async def test_ungrounded_conclusion_is_pushed_back_to_evidence(self):
        """Concluding with no evidence must not end the run."""
        model = _ScriptedModel(
            [
                AIMessage(content="intent"),
                AIMessage(content=_GOOD_REPORT),  # premature conclusion
                AIMessage(
                    content="",
                    tool_calls=[  # correction sends it back
                        {"name": "search", "args": {}, "id": "c9"},
                    ],
                ),
            ]
        )
        out = await triage_think(_state(), _config(model))
        self.assertNotIn("final_answer", out)
        self.assertTrue(getattr(out["messages"][-1], "tool_calls", None))


def _edges_from(graph, source: str) -> list[str]:
    """Targets reachable from `source` in a compiled graph's topology."""
    return [e.target for e in graph.get_graph().edges if e.source == source]


class RoutingTests(unittest.TestCase):
    def test_seed_sends_triage_to_the_flat_loop_and_others_to_the_queue(self):
        # This used to be a `_route_seed(state)` dispatch on agent_name. Each agent now
        # owns its own graph module, so the same guarantee is static topology.
        self.assertEqual(_edges_from(build_triage_graph(), "seed"), ["triage_think"])
        self.assertEqual(_edges_from(build_investigation_graph(), "seed"), ["claim"])

    def test_investigation_still_routes_through_interpret(self):
        self.assertEqual(
            _route_investigation_use_tools({"status": "", "agent_name": "investigation"}),
            "interpret",
        )

    def test_budget_exhaustion_finishes(self):
        self.assertEqual(
            _route_triage_think(
                {
                    "status": "running",
                    "steps": 16,
                    "max_steps": 16,
                    "tool_calls_made": 0,
                    "max_tool_calls": 40,
                    "messages": [],
                }
            ),
            "finish",
        )


if __name__ == "__main__":
    unittest.main()
