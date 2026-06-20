"""
Offline test: runs the triage and investigation graph queue behavior with stub tools.
No real Wazuh, TheHive, LLM, or AVFS needed.

Run with: python tests/test_graph_stub.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci_backend.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from aci_taskqueue.store import init_db, list_tasks, create_task as sq_create
from agent.runtime.graph import GRAPH, AgentState
from langchain_core.messages import AIMessage
from langchain_core.language_models import BaseChatModel


# ── Stub LLM ──────────────────────────────────────────────────────────────────

class StubModel(BaseChatModel):
    """
    Turn 1: emit create_task tool calls.
    Turn 2: emit a plain text response (no tool calls) so the graph routes to assess.
    assess() then auto-calls complete_task using state["current_task"]["id"].
    """

    def __init__(self, inv_run_id: str, case_id: str):
        super().__init__()
        self._inv_run_id = inv_run_id
        self._case_id = case_id
        self._turn = 0

    @property
    def _llm_type(self):
        return "stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        self._turn += 1
        if self._turn == 1:
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "tc1",
                        "name": "create_task",
                        "args": {
                            "case_id": self._case_id,
                            "run_id": self._inv_run_id,
                            "agent_name": "investigation",
                            "title": "Investigate SSH brute-force from 1.2.3.4",
                            "description": "Query wazuh-alerts-* for srcip=1.2.3.4 in last 24h.",
                            "priority": 90,
                        },
                    },
                    {
                        "id": "tc2",
                        "name": "create_task",
                        "args": {
                            "case_id": self._case_id,
                            "run_id": self._inv_run_id,
                            "agent_name": "investigation",
                            "title": "Enrich actor IP 1.2.3.4",
                            "description": "Look up context for 1.2.3.4.",
                            "priority": 50,
                        },
                    },
                ],
            )
        # Turn 2+: plain response → graph routes to assess → auto-completes task
        return AIMessage(content="Task complete.")


class StaticIntentModel(BaseChatModel):
    @property
    def _llm_type(self):
        return "intent-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    async def ainvoke(self, messages, **kwargs):
        return AIMessage(content="I will perform the next task action using the available tools.")


class EmptyCompletionModel(BaseChatModel):
    """Returns no text or tool calls, including during completion recovery."""

    @property
    def _llm_type(self):
        return "empty-completion-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        return AIMessage(content="")


# ── Real-store task queue tools ───────────────────────────────────────────────

class TQTool:
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    async def ainvoke(self, args: dict):
        result = self._fn(**args)
        return json.dumps(result, default=str) if result is not None else "null"


def _make_triage_tools(case_id: str, inv_run_id: str):
    from aci_taskqueue.store import (
        create_task, claim_next, complete_task, list_tasks,
    )
    return [
        TQTool("create_task", create_task),
        TQTool("claim_next",  claim_next),
        TQTool("complete_task", lambda task_id, summary, avfs_paths=None:
               complete_task(task_id, summary, avfs_paths)),
        TQTool("list_tasks",  list_tasks),
        # Dummy AVFS tools (triage may call write/mkdir)
        _DummyTool("write"),
        _DummyTool("mkdir"),
    ]


class _DummyTool:
    def __init__(self, name):
        self.name = name
    async def ainvoke(self, args):
        return json.dumps({"ok": True})


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestTriageHandoff(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        init_db()
        # Tests share one taskqueue DB; purge so cases that reuse case/run ids
        # don't see each other's tasks (these tests run in one process).
        import sqlite3
        con = sqlite3.connect(os.environ["TASKQUEUE_DB_PATH"])
        con.execute("DELETE FROM tasks")
        con.commit()
        con.close()

    async def test_triage_does_not_seed_investigation_queue(self):
        """Triage should produce a report task only, not downstream investigation tasks."""
        triage_run_id = "triage-run-001"
        inv_run_id    = "inv-run-001"
        case_id       = "~001"

        tools = _make_triage_tools(case_id, inv_run_id)
        model = StubModel(inv_run_id, case_id)

        state = AgentState(
            run_id=triage_run_id,
            case_id=case_id,
            agent_name="triage",
            question="What happened?",
            handoff=None,
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=10,
            max_tool_calls=30,
            status="running",
            final_answer="",
            ctx_tokens=0,
        )

        config = {
            "configurable": {
                "model": model,
                "intent_model": StaticIntentModel(),
                "tools": tools,
                "system_prompt": "You are a triage agent.",
            }
        }

        final = await GRAPH.ainvoke(state, config=config)

        inv_tasks = list_tasks(case_id, inv_run_id, "investigation")
        triage_tasks = list_tasks(case_id, triage_run_id, "triage")

        self.assertEqual(inv_tasks, [], "Triage must not create investigation queue tasks")
        self.assertEqual(len(triage_tasks), 1)
        self.assertEqual(triage_tasks[0]["status"], "completed")
        print(f"Triage final status: {final['status']}")

    async def test_investigation_seeds_queue_from_handoff(self):
        """Investigation should convert the orchestrator handoff into its own queue."""
        inv_run_id = "inv-run-001"
        case_id = "~001"

        tools = _make_triage_tools(case_id, inv_run_id)
        model = StubModel(inv_run_id, case_id)

        state = AgentState(
            run_id=inv_run_id,
            case_id=case_id,
            agent_name="investigation",
            question=(
                "Orchestrator handoff to investigation.\n\n"
                "## Triage report\n\n"
                "- Proposed work: investigate SSH brute-force from 1.2.3.4.\n"
                "- Proposed work: enrich actor IP 1.2.3.4."
            ),
            handoff=None,
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=10,
            max_tool_calls=30,
            status="running",
            final_answer="",
            ctx_tokens=0,
        )

        config = {
            "configurable": {
                "model": model,
                "intent_model": StaticIntentModel(),
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        final = await GRAPH.ainvoke(state, config=config)

        inv_tasks = list_tasks(case_id, inv_run_id, "investigation")
        titles = {t["title"] for t in inv_tasks}

        # The seed task is now a handoff task (string-embedded triage report path),
        # alongside the two tasks the model extracted from the plan.
        self.assertIn("Populate investigation queue from triage handoff", titles)
        self.assertIn("Investigate SSH brute-force from 1.2.3.4", titles)
        self.assertIn("Enrich actor IP 1.2.3.4", titles)
        print(f"Investigation seeded from handoff. Final status: {final['status']}")

    async def test_investigation_seeds_from_structured_handoff(self):
        """A1: a structured Handoff (state['handoff']) seeds the queue without
        relying on a magic '## Triage report' string in the question."""
        inv_run_id = "inv-run-h1"
        case_id = "~00h"

        tools = _make_triage_tools(case_id, inv_run_id)
        model = StubModel(inv_run_id, case_id)

        state = AgentState(
            run_id=inv_run_id,
            case_id=case_id,
            agent_name="investigation",
            question="What happened in this case?",  # no embedded triage string
            handoff={
                "analyst_request": "What happened in this case?",
                "triage_report": "Plan: 1) brute-force from 1.2.3.4  2) enrich 1.2.3.4",
                "source_run_id": "triage-run-h1",
                "artifacts": {"ip": "1.2.3.4"},
            },
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=10,
            max_tool_calls=30,
            status="running",
            final_answer="",
            ctx_tokens=0,
        )
        config = {
            "configurable": {
                "model": model,
                "intent_model": StaticIntentModel(),
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        await GRAPH.ainvoke(state, config=config)
        titles = {t["title"] for t in list_tasks(case_id, inv_run_id, "investigation")}
        self.assertIn("Populate investigation queue from triage handoff", titles)
        # The two tasks the stub model extracted from the handoff are present.
        self.assertIn("Investigate SSH brute-force from 1.2.3.4", titles)
        self.assertIn("Enrich actor IP 1.2.3.4", titles)

    async def test_investigation_skips_seed_when_queue_populated(self):
        """Investigation seed should not add a fallback task when its queue is populated."""
        inv_run_id = "inv-run-002"
        case_id    = "~002"

        # Pre-seed the investigation queue (simulating what triage did)
        sq_create(case_id, inv_run_id, "investigation",
                  "Investigate lateral movement", priority=85)

        class InvModel(BaseChatModel):
            """Processes one task then stops."""
            def __init__(self): super().__init__(); self._turn = 0
            @property
            def _llm_type(self): return "stub"
            def _generate(self, *a, **kw): raise NotImplementedError
            def bind_tools(self, tools): return self
            async def ainvoke(self, messages, **kwargs):
                self._turn += 1
                return AIMessage(content="Investigation complete.")

        from aci_taskqueue.store import list_tasks as _lt
        tools = _make_triage_tools(case_id, "")
        # Adjust tools for investigation (same underlying store, different agent_name)
        model = InvModel()

        state = AgentState(
            run_id=inv_run_id,
            case_id=case_id,
            agent_name="investigation",
            question="Investigate the lateral movement",
            handoff=None,
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=10,
            max_tool_calls=30,
            status="running",
            final_answer="",
            ctx_tokens=0,
        )

        config = {
            "configurable": {
                "model": model,
                "intent_model": StaticIntentModel(),
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        final = await GRAPH.ainvoke(state, config=config)

        all_tasks = _lt(case_id, inv_run_id, "investigation")
        # Should have exactly 1 task (the existing one), not 2
        self.assertEqual(len(all_tasks), 1,
            f"Expected 1 task (no duplicate seed), got {[t['title'] for t in all_tasks]}")
        print(f"\nInvestigation skipped seed, processed 1 existing task.")
        print(f"Investigation status: {final['status']}")

    async def test_empty_agent_response_still_records_completion_summary(self):
        run_id = "inv-run-empty-summary"
        case_id = "~empty"
        sq_create(
            case_id,
            run_id,
            "investigation",
            "Check a task that returns no narrative",
            priority=80,
        )

        final = await GRAPH.ainvoke(
            AgentState(
                run_id=run_id,
                case_id=case_id,
                agent_name="investigation",
                question="Complete the queued task",
                handoff=None,
                current_task=None,
                messages=[],
                steps=0,
                tool_calls_made=0,
                max_steps=10,
                max_tool_calls=30,
                status="running",
                final_answer="",
                ctx_tokens=0,
                current_intent="",
                intent_sequence=0,
                model_calls_made=0,
            ),
            config={
                "configurable": {
                    "model": EmptyCompletionModel(),
                    "intent_model": StaticIntentModel(),
                    "tools": _make_triage_tools(case_id, run_id),
                    "system_prompt": "Complete the task without inventing results.",
                }
            },
        )

        task = list_tasks(case_id, run_id, "investigation")[0]
        self.assertEqual(task["status"], "completed")
        self.assertTrue(task["summary"].strip())
        self.assertIn("without a final narrative", task["summary"])
        self.assertIn(task["summary"], final["final_answer"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
