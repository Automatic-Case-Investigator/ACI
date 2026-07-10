"""Unit test: seeder Phase-2 duplicate-task guard.

Reproduces a real failure observed in production logs: the seeder's model phase
proposed the exact same task title twice within a single seeding pass (a
"<placeholder>"-titled destination task, created, then recreated 4 seconds
later), wasting a full task cycle. `run_seeder` now runs each Phase-2
`create_task` call through the same deterministic dedup matcher the pivot
node's lead validator already trusts (leads.duplicate_existing_task) before
executing it.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402

from agent.agents.base import Handoff  # noqa: E402
from agent.runtime.graph import GRAPH  # noqa: E402,F401 (import graph before seeder_runner: avoids a circular import — see graph/nodes_loop.py)
from agent.runtime.engine.seeder_runner import (  # noqa: E402
    _extract_plan_items, _item_priority, run_seeder,
)


class _Tool:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    async def ainvoke(self, args: dict):
        result = self._fn(**args)
        return json.dumps(result, default=str) if result is not None else "null"


class _DuplicateProposingModel(BaseChatModel):
    """Proposes the SAME create_task title twice in one turn, then stops."""

    def __init__(self):
        super().__init__()
        self._turn = 0

    @property
    def _llm_type(self):
        return "duplicate-proposing-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        self._turn += 1
        if self._turn == 1:
            dup_args = {
                "title": "Investigate attacker-controlled destination <addr>",
                "description": "pivot to all SIEM events to/from it",
                "priority": 90,
            }
            return AIMessage(content="", tool_calls=[
                {"name": "create_task", "id": "c1", "args": dup_args},
                {"name": "create_task", "id": "c2", "args": dict(dup_args)},
            ])
        return AIMessage(content="")


class _NoopModel(BaseChatModel):
    """Returns nothing — used to isolate the deterministic seeder phases."""

    @property
    def _llm_type(self):
        return "noop-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        return AIMessage(content="")


def _run(coro):
    return asyncio.run(coro)


class SeederDedupTest(unittest.TestCase):
    def test_duplicate_create_task_in_same_pass_is_skipped(self):
        created: list[dict] = []

        def _create_task(**kwargs):
            created.append(kwargs)
            return {"ok": True, "id": f"task_{len(created)}"}

        def _list_tasks():
            return created

        tools = [_Tool("create_task", _create_task), _Tool("list_tasks", _list_tasks)]
        handoff = Handoff(triage_report="## Triage Summary\nno plan section here.\n")

        _run(run_seeder(handoff, tools, _DuplicateProposingModel(), vicinity_hours=24))

        # Only ONE of the two identical create_task calls should have executed.
        matching = [c for c in created if "attacker-controlled destination" in c["title"]]
        self.assertEqual(len(matching), 1)


class SeederPriorityTest(unittest.TestCase):
    """The seeder must preserve the priority the triage report states per plan item.

    Regression: `_item_priority` previously ignored the stated `Priority: N` line and
    re-derived priority from keyword matching, so a P30 memory-check item was queued
    at P95 while a P85 scan-tail item dropped to P65 (session 64e5d676).
    """

    PLAN = (
        "## Investigation Plan\n"
        "1. **Confirm the 400-error burst for source 172.17.130.196**\n"
        "   - Pivots: `data.srcip=172.17.130.196`, `rule.id=31151`\n"
        "   - Priority: 60\n"
        "2. **Trace the scan-to-success tail**\n"
        "   - Pivots: `data.srcip=172.17.130.196`\n"
        "   - Priority: 85\n"
        "3. **Confirm whether this source appears in authentication success data**\n"
        "   - Priority: 75\n"
        "4. **Check case-adjacent memory for historical handling of rule 31151**\n"
        "   - Pivots: `rule_id=31151`\n"
        "   - Priority: 30\n"
    )

    def test_stated_priorities_are_preserved(self):
        items = _extract_plan_items(self.PLAN)
        self.assertEqual([_item_priority(it) for it in items], [60, 85, 75, 30])

    def test_falls_back_to_keywords_without_stated_priority(self):
        # No "Priority:" line → keyword inference ("webshell" → 95).
        item = "Decode the suspected webshell payload on host kali"
        self.assertEqual(_item_priority(item), 95)

    def test_default_when_neither_stated_nor_keyword(self):
        self.assertEqual(_item_priority("Summarize the overall investigation timeline"), 65)


class SeederTimelineTest(unittest.TestCase):
    """Phase 1.5 surfaces every burst in one recall-preserving coverage map."""

    def _tools(self, created, bursts):
        def _create_task(**kwargs):
            created.append(kwargs)
            return {"ok": True, "id": f"task_{len(created)}"}

        def _list_tasks(**_kwargs):
            return created

        def _get_event_volume(**_kwargs):
            return {"bursts": bursts, "total": sum(b.get("total", 0) for b in bursts)}

        return [
            _Tool("create_task", _create_task),
            _Tool("list_tasks", _list_tasks),
            _Tool("get_event_volume", _get_event_volume),
        ]

    def test_seeds_one_coverage_map_with_every_burst(self):
        created: list[dict] = []
        bursts = [
            {"start": "2022-01-18T11:59:00Z", "end": "2022-01-18T12:38:00Z", "total": 400},
            {"start": "2022-01-18T13:13:50Z", "end": "2022-01-18T13:14:53Z", "total": 30},
        ]
        report = ("## Triage Summary\nActivity observed from 2022-01-18T11:59:00Z through "
                  "2022-01-18T13:14:53Z on the host.\n")
        _run(run_seeder(Handoff(triage_report=report), self._tools(created, bursts),
                        _NoopModel(), vicinity_hours=24))

        timeline = [c for c in created if c["title"].startswith("Account for timeline coverage")]
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["priority"], 70)
        self.assertIn("2022-01-18T11:59:00Z to 2022-01-18T12:38:00Z", timeline[0]["description"])
        self.assertIn("2022-01-18T13:13:50Z to 2022-01-18T13:14:53Z", timeline[0]["description"])
        self.assertIn("covered by a cited finding", timeline[0]["description"])
        self.assertIn("converted into a concrete New Lead", timeline[0]["description"])

    def test_single_burst_is_not_decomposed(self):
        # One burst that fills the window is not a decomposition — seed nothing here.
        created: list[dict] = []
        bursts = [{"start": "2022-01-18T11:59:00Z", "end": "2022-01-18T13:14:53Z", "total": 400}]
        report = "Activity from 2022-01-18T11:59:00Z to 2022-01-18T13:14:53Z."
        _run(run_seeder(Handoff(triage_report=report), self._tools(created, bursts),
                        _NoopModel(), vicinity_hours=24))
        self.assertEqual([c for c in created if c["title"].startswith("Account for timeline coverage")], [])

    def test_no_incident_window_skips_decomposition(self):
        # Fewer than two distinct timestamps → nothing to decompose (and no volume call).
        created: list[dict] = []
        called = {"vol": 0}

        def _create_task(**kwargs):
            created.append(kwargs)
            return {"ok": True}

        def _get_event_volume(**_kwargs):
            called["vol"] += 1
            return {"bursts": []}

        tools = [_Tool("create_task", _create_task), _Tool("list_tasks", lambda **_k: created),
                 _Tool("get_event_volume", _get_event_volume)]
        _run(run_seeder(Handoff(triage_report="No timestamps here."), tools,
                        _NoopModel(), vicinity_hours=24))
        self.assertEqual(called["vol"], 0)
        self.assertEqual([c for c in created if c["title"].startswith("Account for timeline coverage")], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
