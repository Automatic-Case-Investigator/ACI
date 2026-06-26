"""
Offline test: the investigation pivot node auto-creates validated follow-up
tasks from a "## New Leads" section without applying a lead budget cap.

No real Wazuh, TheHive, LLM, or AVFS needed.
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
from agent.runtime.graph import pivot
from langchain_core.messages import AIMessage


class TQTool:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    async def ainvoke(self, args: dict):
        result = self._fn(**args)
        return json.dumps(result, default=str) if result is not None else "null"


def _lead_dicts(priorities):
    """The validated-lead JSON the (stubbed) lead model returns for these leads."""
    out = []
    for i, p in enumerate(priorities):
        ip = f"10.0.0.{i + 1}"
        out.append({
            "title": f"Investigate C2 callback activity for {ip}",
            "pivots": f"ip={ip}, time=2025-04-20T03:{i:02d}:00Z",
            "evidence": f"event=evt-{i}, {ip} appeared in the current task output",
            "priority": p,
            "approved": True,
            "category": "approved",
            "reason": "evidence-backed callback",
        })
    return out


class StubLeadModel:
    """Returns a fixed validated-lead JSON array regardless of prompt — the lead
    model is now responsible for extraction+validation."""
    def __init__(self, leads):
        self._payload = json.dumps(leads)

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        return AIMessage(content=self._payload)


def _config(priorities):
    return {"configurable": {
        "tools": [TQTool("create_task", create_task), TQTool("list_tasks", list_tasks)],
        "model": StubLeadModel(_lead_dicts(priorities)),
    }}


def _leads_block(priorities):
    # final_answer only needs a non-empty New Leads section so pivot proceeds; the
    # stub model produces the actual structured leads.
    lines = ["## Confirmed Facts"]
    for i, _ in enumerate(priorities):
        lines.append(f"- Event evt-{i} observed callback artifact 10.0.0.{i + 1}.")
    lines += ["", "## New Leads"]
    for i, p in enumerate(priorities):
        lines.append(f"- Investigate C2 callback activity for 10.0.0.{i + 1} (priority {p})")
    return "\n".join(lines) + "\n"


def _state(run_id, final_answer, already=0):
    return {
        "run_id": run_id,
        "case_id": "~cap",
        "agent_name": "investigation",
        "final_answer": final_answer,
        "pivot_tasks_created": already,
    }


class PivotLeadQueueTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        init_db()
        import sqlite3
        con = sqlite3.connect(os.environ["TASKQUEUE_DB_PATH"])
        con.execute("DELETE FROM tasks")
        con.commit()
        con.close()

    async def test_queues_all_validated_followups(self):
        run_id = "cap-run-1"
        priorities = list(range(95, 95 - 13 * 5, -5))  # 13 leads: 95,90,...,35
        config = _config(priorities)

        out = await pivot(_state(run_id, _leads_block(priorities)), config)

        tasks = sq_list("~cap", run_id, "investigation")
        self.assertEqual(len(tasks), len(priorities))
        self.assertEqual(out.get("pivot_tasks_created"), len(priorities))
        kept = {t["priority"] for t in tasks}
        self.assertEqual(kept, set(priorities))

    async def test_prior_created_count_does_not_block_new_leads(self):
        run_id = "cap-run-2"
        config = _config([90, 80, 70])
        out = await pivot(
            _state(run_id, _leads_block([90, 80, 70]), already=10),
            config,
        )
        self.assertEqual(len(sq_list("~cap", run_id, "investigation")), 3)
        self.assertEqual(out.get("pivot_tasks_created"), 13)

    async def test_creates_all_under_previous_small_examples(self):
        run_id = "cap-run-3"
        config = _config([90, 80, 70])
        out = await pivot(_state(run_id, _leads_block([90, 80, 70])), config)
        self.assertEqual(len(sq_list("~cap", run_id, "investigation")), 3)
        self.assertEqual(out.get("pivot_tasks_created"), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
