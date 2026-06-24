"""
Offline test: the investigation pivot node caps how many follow-up tasks it
auto-creates from a "## New Leads" section.

Without the cap, each completed task can spawn new leads that spawn more, so the
queue never drains and the run only ends by exhausting its step budget
(status=incomplete_budget) instead of reaching a verdict. The pivot node now:
  - creates at most `_MAX_PIVOT_TASKS` follow-up tasks across the whole run,
  - keeps the highest-priority leads when the cap is hit,
  - surfaces the rest as open leads on the Findings Board (not silently dropped).

No real Wazuh, TheHive, LLM, or AVFS needed.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_pivot_cap.py
"""
from __future__ import annotations

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

from aci_taskqueue.store import init_db, list_tasks as sq_list, create_task, list_tasks
from agent.runtime.graph import pivot, _MAX_PIVOT_TASKS


class TQTool:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    async def ainvoke(self, args: dict):
        result = self._fn(**args)
        return json.dumps(result, default=str) if result is not None else "null"


def _tools():
    return [TQTool("create_task", create_task), TQTool("list_tasks", list_tasks)]


def _leads_block(priorities):
    lines = ["## New Leads"]
    for i, p in enumerate(priorities):
        lines += [f"- title: Lead P{p} #{i}", f"  pivots: pivot for {p}", f"  priority: {p}"]
    return "\n".join(lines) + "\n"


def _state(run_id, final_answer, already=0):
    return {
        "run_id": run_id,
        "case_id": "~cap",
        "agent_name": "investigation",
        "final_answer": final_answer,
        "pivot_tasks_created": already,
    }


class PivotCapTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        init_db()
        import sqlite3
        con = sqlite3.connect(os.environ["TASKQUEUE_DB_PATH"])
        con.execute("DELETE FROM tasks")
        con.commit()
        con.close()

    async def test_caps_followups_and_keeps_highest_priority(self):
        run_id = "cap-run-1"
        # More leads than the cap, with descending priorities.
        priorities = list(range(95, 95 - 13 * 5, -5))  # 13 leads: 95,90,...,35
        self.assertGreater(len(priorities), _MAX_PIVOT_TASKS)
        config = {"configurable": {"tools": _tools()}}

        out = await pivot(_state(run_id, _leads_block(priorities)), config)

        tasks = sq_list("~cap", run_id, "investigation")
        self.assertEqual(len(tasks), _MAX_PIVOT_TASKS,
                         "pivot must not create more than the cap")
        self.assertEqual(out.get("pivot_tasks_created"), _MAX_PIVOT_TASKS)

        # The kept tasks are the highest-priority leads; the lowest are deferred.
        kept = {t["priority"] for t in tasks}
        top = sorted(priorities, reverse=True)[:_MAX_PIVOT_TASKS]
        self.assertEqual(kept, set(top))
        for low in sorted(priorities)[: len(priorities) - _MAX_PIVOT_TASKS]:
            self.assertNotIn(low, kept, f"low-priority lead P{low} should be deferred")

    async def test_no_new_tasks_once_budget_already_spent(self):
        run_id = "cap-run-2"
        config = {"configurable": {"tools": _tools()}}
        # Already at the cap from earlier pivots.
        out = await pivot(
            _state(run_id, _leads_block([90, 80, 70]), already=_MAX_PIVOT_TASKS),
            config,
        )
        self.assertEqual(len(sq_list("~cap", run_id, "investigation")), 0)
        self.assertEqual(out.get("pivot_tasks_created"), _MAX_PIVOT_TASKS)

    async def test_under_cap_creates_all(self):
        run_id = "cap-run-3"
        config = {"configurable": {"tools": _tools()}}
        out = await pivot(_state(run_id, _leads_block([90, 80, 70])), config)
        self.assertEqual(len(sq_list("~cap", run_id, "investigation")), 3)
        self.assertEqual(out.get("pivot_tasks_created"), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
