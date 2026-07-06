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
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402

from agent.agents.base import Handoff  # noqa: E402
from agent.runtime.graph import GRAPH  # noqa: E402,F401 (import graph before seeder_runner: avoids a circular import — see graph/nodes_loop.py)
from agent.runtime.engine.seeder_runner import run_seeder  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
