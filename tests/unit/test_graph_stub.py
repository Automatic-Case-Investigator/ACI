"""
Offline test: runs the triage and investigation graph queue behavior with stub tools.
No real Wazuh, TheHive, LLM, or AVFS needed.

Run from project root with: python .claude/skills/run-aci-backend/tests/test_graph_stub.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest

# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from aci_taskqueue.store import init_db, list_tasks, create_task as sq_create
from agent.runtime.graph import GRAPH, AgentState
from agent.runtime.analysis.verdict import parse_verdict
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
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "canonical verdict JSON contract" in text:
            return AIMessage(content=(
                "```json\n"
                "{"
                "\"verdict\":\"needs_investigation\","
                "\"confidence\":\"medium\","
                "\"classification_basis\":\"insufficient_evidence\","
                "\"impact_state\":\"unknown\","
                "\"scope_state\":\"unknown\","
                "\"matched_patterns\":[],"
                "\"supporting_evidence\":[],"
                "\"contradicting_evidence\":[],"
                "\"blocking_gaps\":[\"Stub model did not perform a substantive investigation.\"],"
                "\"nonblocking_gaps\":[],"
                "\"missing_evidence\":[\"Stub model did not perform a substantive investigation.\"],"
                "\"recommended_action\":\"Run with real tools and model for a substantive verdict.\""
                "}\n"
                "```"
            ))
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


class TriageNearbyEventsGuardModel(BaseChatModel):
    """First skips SIEM, then follows the guard correction and queries nearby events."""

    def __init__(self):
        super().__init__()
        self.turns = 0

    @property
    def _llm_type(self):
        return "triage-nearby-events-guard-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        self.turns += 1
        if self.turns == 1:
            return AIMessage(content="## Confirmed Facts\n- Case loaded.\n\n## Findings\n- Done.")
        if self.turns == 2:
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "triage-siem-1",
                        "name": "search_keyword",
                        "args": {
                            "query": "kali user 80792 nano",
                            "time_range": {
                                "from": "2025-04-20T02:54:10Z",
                                "to": "2025-04-20T04:54:10Z",
                            },
                            "max_results": 20,
                        },
                    }
                ],
            )
        return AIMessage(content=(
            "## Confirmed Facts\n"
            "- Case loaded.\n"
            "- Nearby SIEM events were checked with `search_keyword` for `kali user 80792 nano` "
            "from 2025-04-20T02:54:10Z to 2025-04-20T04:54:10Z.\n\n"
            "## Findings\n"
            "- No corroborating nearby SIEM event was returned by the stub search.\n\n"
            "## Hypotheses\n"
            "- Needs deeper investigation if higher-fidelity telemetry is required.\n\n"
            "## Evidence Gaps\n"
            "- Stub SIEM result has no real production telemetry.\n\n"
            "## Investigation Plan\n"
            "1. Review real nearby Wazuh events for the same host and user.\n\n"
            "```json\n"
            "{"
            "\"verdict\":\"needs_investigation\","
            "\"confidence\":\"medium\","
            "\"classification_basis\":\"insufficient_evidence\","
            "\"impact_state\":\"unknown\","
            "\"scope_state\":\"unknown\","
            "\"matched_patterns\":[],"
            "\"supporting_evidence\":[],"
            "\"contradicting_evidence\":[],"
            "\"blocking_gaps\":[\"Production SIEM telemetry was not available in this stub.\"],"
            "\"nonblocking_gaps\":[],"
            "\"missing_evidence\":[],"
            "\"recommended_action\":\"open investigation\""
            "}\n"
            "```"
        ))


class TriageContractModel(BaseChatModel):
    """Writes a triage report without JSON, then returns the contract JSON."""

    def __init__(self):
        super().__init__()
        self.turns = 0

    @property
    def _llm_type(self):
        return "triage-contract-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        self.turns += 1
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "canonical verdict JSON contract" in text:
            return AIMessage(content=(
                "```json\n"
                "{\n"
                '  "verdict": "needs_investigation",\n'
                '  "confidence": "medium",\n'
                '  "classification_basis": "insufficient_evidence",\n'
                '  "impact_state": "unknown",\n'
                '  "scope_state": "unknown",\n'
                '  "matched_patterns": [],\n'
                '  "supporting_evidence": [],\n'
                '  "contradicting_evidence": [],\n'
                '  "blocking_gaps": ["Crontab contents were not retrieved"],\n'
                '  "nonblocking_gaps": [],\n'
                '  "missing_evidence": ["Crontab contents were not retrieved"],\n'
                '  "recommended_action": "Open investigation to retrieve crontab contents."\n'
                "}\n"
                "```"
            ))
        return AIMessage(content=(
            "## Confirmed Facts\n"
            "- Case and alert summary were loaded.\n\n"
            "## Findings\n"
            "- Nano opened a temporary crontab path, but crontab contents were not retrieved.\n\n"
            "## Investigation Plan\n"
            "1. Retrieve crontab diff or contents around the alert timestamp.\n"
        ))


class InvestigationContractModel(BaseChatModel):
    """Completes one task, writes a narrative, then returns a verdict contract."""

    @property
    def _llm_type(self):
        return "investigation-contract-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "canonical verdict JSON contract" in text:
            return AIMessage(content=(
                "```json\n"
                "{\n"
                '  "verdict": "tp",\n'
                '  "confidence": "high",\n'
                '  "classification_basis": "malicious_evidence",\n'
                '  "impact_state": "active",\n'
                '  "scope_state": "isolated",\n'
                '  "matched_patterns": [],\n'
                '  "supporting_evidence": [\n'
                '    "Syscheck modified /var/spool/cron/crontabs/user with reverse-shell cron entry"\n'
                "  ],\n"
                '  "contradicting_evidence": [],\n'
                '  "blocking_gaps": ["Initial access source IP not retrieved from telemetry"],\n'
                '  "nonblocking_gaps": ["No direct network telemetry confirming callback"],\n'
                '  "missing_evidence": ["Initial access source IP not retrieved from telemetry"],\n'
                '  "recommended_action": "Isolate kali and remove the malicious crontab."\n'
                "}\n"
                "```"
            ))
        if "Write the final report in markdown" in text:
            return AIMessage(content=(
                "## Verdict\n"
                "compromise confirmed; critical; active\n\n"
                "## Executive Summary\n"
                "Syscheck confirmed a malicious reverse-shell cron entry on kali.\n\n"
                "## Timeline\n"
                "- 2025-04-20T03:49:57.127Z syscheck modified /var/spool/cron/crontabs/user.\n\n"
                "## Scope & Impact\n"
                "| Asset | Type | Role | Attacker access / impact |\n"
                "|---|---|---|---|\n"
                "| kali | host | affected endpoint | malicious cron persistence |\n\n"
                "## Initial Access\n"
                "Initial access vector not established — source IP missing from telemetry.\n\n"
                "## Recommended Actions\n"
                "1. Isolate kali.\n\n"
                "## Open Gaps\n"
                "- Initial access source IP not retrieved from telemetry.\n"
            ))
        return AIMessage(content=(
            "## Confirmed Facts\n"
            "- Syscheck modified /var/spool/cron/crontabs/user with reverse-shell cron entry.\n\n"
            "## Findings\n"
            "- The cron entry runs sh -i to /dev/tcp/10.0.2.5/5555 every minute.\n\n"
            "## Hypotheses\n"
            "- [confirmed/high] Cron persistence was installed on kali.\n"
        ))


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


class _RecorderTool:
    def __init__(self, name):
        self.name = name
        self.calls = []

    async def ainvoke(self, args):
        self.calls.append(args)
        if self.name == "read":
            return json.dumps({"content": ""})
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

    async def test_triage_requires_nearby_siem_events_when_siem_available(self):
        """Triage cannot complete without a SIEM lookup for time-nearby events."""
        triage_run_id = "triage-run-siem-guard"
        case_id = "~siemguard"

        tools = _make_triage_tools(case_id, "")
        tools.append(_DummyTool("search_keyword"))
        model = TriageNearbyEventsGuardModel()

        final = await GRAPH.ainvoke(
            AgentState(
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
            ),
            config={
                "configurable": {
                    "model": model,
                    "tools": tools,
                    "system_prompt": "You are a triage agent.",
                }
            },
        )

        triage_tasks = list_tasks(case_id, triage_run_id, "triage")
        self.assertEqual(final["status"], "completed")
        self.assertEqual(model.turns, 4)
        self.assertEqual(triage_tasks[0]["status"], "completed")
        self.assertIn("Nearby SIEM events were checked", triage_tasks[0]["summary"])

    async def test_triage_verdict_contract_node_appends_canonical_json(self):
        triage_run_id = "triage-run-contract"
        case_id = "~triagecontract"
        model = TriageContractModel()

        final = await GRAPH.ainvoke(
            AgentState(
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
            ),
            config={
                "configurable": {
                    "model": model,
                    "tools": _make_triage_tools(case_id, ""),
                    "system_prompt": "You are a triage agent.",
                }
            },
        )

        self.assertEqual(final["status"], "completed")
        self.assertEqual(model.turns, 2)
        self.assertEqual(final["verdict"]["verdict"], "needs_investigation")
        self.assertEqual(final["final_answer"].count("```json"), 1)
        self.assertEqual(parse_verdict(final["final_answer"]), final["verdict"])
        self.assertIn("Nano opened a temporary crontab path", final["final_answer"])

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
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        final = await GRAPH.ainvoke(state, config=config)

        inv_tasks = list_tasks(case_id, inv_run_id, "investigation")
        titles = {t["title"] for t in inv_tasks}

        # The seed task is a handoff task; the model extracts the two plan tasks.
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

    async def test_investigation_model_seeds_from_handoff(self):
        """Model creates tasks during the seed task from the triage handoff."""
        inv_run_id = "inv-run-det"
        case_id = "~00det"

        tools = _make_triage_tools(case_id, inv_run_id)
        model = StubModel(inv_run_id, case_id)

        state = AgentState(
            run_id=inv_run_id,
            case_id=case_id,
            agent_name="investigation",
            question="Investigate this case.",
            handoff={
                "analyst_request": "Investigate this case.",
                "triage_report": (
                    "## Investigation Plan\n"
                    "1. Investigate SSH brute-force from 1.2.3.4\n"
                    "2. Enrich actor IP 1.2.3.4\n"
                ),
                "source_run_id": "triage-run-det",
                "artifacts": {},
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
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        await GRAPH.ainvoke(state, config=config)
        titles = {t["title"] for t in list_tasks(case_id, inv_run_id, "investigation")}
        # Seed task is created; model creates sub-tasks from the handoff.
        self.assertIn("Populate investigation queue from triage handoff", titles)
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

    async def test_seed_guard_retries_when_no_tasks_created(self):
        """Seed guard: if the seed task completes without create_task calls, the graph
        re-injects a correction and routes back to think rather than finishing early."""
        inv_run_id = "inv-run-sg"
        case_id = "~sg"

        class SeedGuardModel(BaseChatModel):
            """Turn 1: completes seed task without creating any tasks.
            Turn 2+: creates two tasks after receiving the seed-guard correction."""
            def __init__(self):
                super().__init__()
                self._turn = 0

            @property
            def _llm_type(self):
                return "seed-guard-stub"

            def _generate(self, *a, **kw):
                raise NotImplementedError

            def bind_tools(self, tools):
                return self

            async def ainvoke(self, messages, **kwargs):
                self._turn += 1
                if self._turn == 1:
                    # Skip create_task — returns a plain text answer for the seed task
                    return AIMessage(content="Queue populated (incorrectly — no tasks created).")
                if self._turn == 2:
                    # Correction received; now create the tasks
                    return AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": "tc-sg1",
                                "name": "create_task",
                                "args": {
                                    "case_id": case_id,
                                    "run_id": inv_run_id,
                                    "agent_name": "investigation",
                                    "title": "Investigate SSH brute-force",
                                    "description": "Check for brute-force.",
                                    "priority": 90,
                                },
                            },
                        ],
                    )
                # Subsequent turns: complete the task
                return AIMessage(content="SSH investigation complete.")

        tools = _make_triage_tools(case_id, inv_run_id)
        model = SeedGuardModel()
        state = AgentState(
            run_id=inv_run_id,
            case_id=case_id,
            agent_name="investigation",
            question="Investigate SSH brute-force.",
            handoff={
                "analyst_request": "Investigate SSH brute-force.",
                "triage_report": "Plan: 1) investigate SSH brute-force",
                "source_run_id": "triage-run-sg",
                "artifacts": {},
            },
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=20,
            max_tool_calls=60,
            status="running",
            final_answer="",
            ctx_tokens=0,
        )
        config = {
            "configurable": {
                "model": model,
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        await GRAPH.ainvoke(state, config=config)
        titles = {t["title"] for t in list_tasks(case_id, inv_run_id, "investigation")}
        self.assertIn("Populate investigation queue from triage handoff", titles,
                      "Seed task should exist")
        self.assertIn("Investigate SSH brute-force", titles,
                      "Seed guard should have prompted the model to create investigation tasks")

    async def test_seed_guard_retries_until_all_handoff_leads_created(self):
        """Seed guard must not accept a partially populated queue when the handoff
        contains multiple investigation items."""
        inv_run_id = "inv-run-sg-partial"
        case_id = "~sg-partial"

        class PartialSeedModel(BaseChatModel):
            def __init__(self):
                super().__init__()
                self._turn = 0

            @property
            def _llm_type(self):
                return "seed-guard-partial-stub"

            def _generate(self, *a, **kw):
                raise NotImplementedError

            def bind_tools(self, tools):
                return self

            async def ainvoke(self, messages, **kwargs):
                self._turn += 1
                if self._turn == 1:
                    return AIMessage(content=(
                        "Only one task is needed.\n\n"
                        "## New Leads\n"
                        "- title: Verify crontab contents changed during the nano session\n"
                        "  pivots: host=kali\n"
                        "  evidence: event=evt-1\n"
                        "  priority: 70"
                    ))
                if self._turn == 2:
                    return AIMessage(
                        content="",
                        tool_calls=[{
                            "id": "tc-one",
                            "name": "create_task",
                            "args": {
                                "case_id": case_id,
                                "run_id": inv_run_id,
                                "agent_name": "investigation",
                                "title": "Verify crontab contents changed during the nano session",
                                "description": "Check cron content.",
                                "priority": 70,
                            },
                        }],
                    )
                if self._turn == 3:
                    return AIMessage(content="Queue is complete.")
                if self._turn == 4:
                    return AIMessage(
                        content="",
                        tool_calls=[{
                            "id": "tc-two",
                            "name": "create_task",
                            "args": {
                                "case_id": case_id,
                                "run_id": inv_run_id,
                                "agent_name": "investigation",
                                "title": "Check for surrounding cron persistence or follow-on execution on kali",
                                "description": "Check follow-on cron execution.",
                                "priority": 60,
                            },
                        }],
                    )
                return AIMessage(content="Investigation queue is now fully populated.")

        tools = _make_triage_tools(case_id, inv_run_id)
        model = PartialSeedModel()
        state = AgentState(
            run_id=inv_run_id,
            case_id=case_id,
            agent_name="investigation",
            question="Investigate cron persistence.",
            handoff={
                "analyst_request": "Investigate cron persistence.",
                "triage_report": (
                    "## New Leads\n"
                    "- title: Verify crontab contents changed during the nano session\n"
                    "  pivots: host `kali`\n"
                    "  evidence: event=evt-1\n"
                    "  priority: 70\n"
                    "- title: Check for surrounding cron persistence or follow-on execution on kali\n"
                    "  pivots: host `kali`\n"
                    "  evidence: event=evt-2\n"
                    "  priority: 60\n"
                ),
                "source_run_id": "triage-run-sg-partial",
                "artifacts": {},
            },
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=20,
            max_tool_calls=60,
            status="running",
            final_answer="",
            ctx_tokens=0,
        )
        config = {
            "configurable": {
                "model": model,
                "tools": tools,
                "system_prompt": "You are an investigation agent.",
            }
        }

        await GRAPH.ainvoke(state, config=config)
        titles = {t["title"] for t in list_tasks(case_id, inv_run_id, "investigation")}
        self.assertIn("Verify crontab contents changed during the nano session", titles)
        self.assertIn("Check for surrounding cron persistence or follow-on execution on kali", titles)

    async def test_investigation_verdict_contract_publishes_reassessed_tp(self):
        run_id = "inv-run-contract"
        case_id = "~contract"
        sq_create(
            case_id,
            run_id,
            "investigation",
            "Confirm whether crontab edit installed persistence",
            priority=90,
        )

        write_tool = _RecorderTool("write")
        mkdir_tool = _RecorderTool("mkdir")
        read_tool = _RecorderTool("read")
        post_tool = _RecorderTool("post_case_report")
        tools = [
            t for t in _make_triage_tools(case_id, run_id)
            if t.name not in {"write", "mkdir"}
        ] + [write_tool, mkdir_tool, read_tool, post_tool]

        triage_report = (
            "Triage required more investigation.\n\n"
            "```json\n"
            "{"
            "\"verdict\":\"needs_investigation\","
            "\"confidence\":\"medium\","
            "\"classification_basis\":\"insufficient_evidence\","
            "\"impact_state\":\"unknown\","
            "\"scope_state\":\"unknown\","
            "\"matched_patterns\":[],"
            "\"supporting_evidence\":[],"
            "\"contradicting_evidence\":[],"
            "\"blocking_gaps\":[\"Crontab contents were not retrieved\"],"
            "\"nonblocking_gaps\":[],"
            "\"missing_evidence\":[],"
            "\"recommended_action\":\"investigate crontab contents\""
            "}\n"
            "```"
        )

        final = await GRAPH.ainvoke(
            AgentState(
                run_id=run_id,
                case_id=case_id,
                agent_name="investigation",
                question="Investigate crontab persistence.",
                handoff={
                    "analyst_request": "Investigate crontab persistence.",
                    "triage_report": triage_report,
                    "source_run_id": "triage-run-contract",
                    "artifacts": {},
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
            ),
            config={
                "configurable": {
                    "model": InvestigationContractModel(),
                    "tools": tools,
                    "system_prompt": "You are an investigation agent.",
                }
            },
        )

        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["verdict"]["verdict"], "tp")
        self.assertNotIn("demoted_from", final["verdict"])
        self.assertEqual(final["verdict"]["triage_verdict"], "needs_investigation")
        self.assertEqual(final["verdict"]["blocking_gaps"], [])
        self.assertIn(
            "Initial access source IP not retrieved from telemetry",
            final["verdict"]["nonblocking_gaps"],
        )
        self.assertEqual(final["final_answer"].count("```json"), 1)
        self.assertEqual(parse_verdict(final["final_answer"]), final["verdict"])

        final_writes = [
            call for call in write_tool.calls
            if call.get("path", "").endswith("/reports/final.md")
        ]
        self.assertEqual(len(final_writes), 1)
        self.assertEqual(parse_verdict(final_writes[0]["content"]), final["verdict"])
        self.assertEqual(parse_verdict(post_tool.calls[0]["summary"]), final["verdict"])

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
            ),
            config={
                "configurable": {
                    "model": EmptyCompletionModel(),
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
