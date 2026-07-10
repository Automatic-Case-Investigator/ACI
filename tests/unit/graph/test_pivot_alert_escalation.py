from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from agent.runtime.graph.nodes_flow.pivot import pivot


class _Tool:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    async def ainvoke(self, args: dict):
        result = self._fn(**args)
        return json.dumps(result, default=str) if result is not None else "null"


class PivotAlertEscalationTests(unittest.TestCase):
    def test_standalone_alert_does_not_post_case_comment(self):
        calls = {"post": 0}

        def _post_case_comment(**_kwargs):
            calls["post"] += 1
            return {"ok": True}

        state = {
            "agent_name": "investigation",
            "case_id": "~392007704",
            "source_entity_type": "alert",
            "run_id": "run-alert",
            "final_answer": (
                "## Findings\n"
                "- Event `evt-1` confirmed reverse shell to 10.0.2.5.\n\n"
                "## Hypotheses\n- None.\n\n"
                "## New Leads\n- None.\n"
            ),
            "escalation_posted": False,
            "last_findings_verification": None,
            "last_confirmed_findings": [],
        }
        result = asyncio.run(pivot(state, {"configurable": {
            "tools": [_Tool("post_case_comment", _post_case_comment)],
        }}))

        self.assertEqual(calls["post"], 0)
        self.assertTrue(result["escalation_posted"])


if __name__ == "__main__":
    unittest.main()
