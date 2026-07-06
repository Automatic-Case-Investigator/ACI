"""
Offline test: specialist verdicts are propagated onto the orchestrator session row.

Run from project root with:
    python tests/unit/orchestrator/test_orchestrator_verdict_propagation.py -v
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django
django.setup()

from agent.models import AgentRun
from agent.runtime.orchestrator.tools import _propagate_verdict_to_session


class TestOrchestratorVerdictPropagation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.session_run = await AgentRun.objects.acreate(
            case_id="ZZTEST_PROPAGATION",
            agent_name="orchestrator",
            question="q",
            status=AgentRun.STATUS_COMPLETED,
            verdict=None,
        )

    async def asyncTearDown(self):
        await AgentRun.objects.filter(case_id="ZZTEST_PROPAGATION").adelete()

    async def test_propagates_structured_verdict_to_session_row(self):
        verdict = {"verdict": "fp", "confidence": "medium"}
        with patch("agent.runtime.orchestrator.tools.current_session", return_value=str(self.session_run.id)):
            await _propagate_verdict_to_session(verdict)

        await self.session_run.arefresh_from_db()
        self.assertEqual(self.session_run.verdict, verdict)

    async def test_ignores_non_dict_verdict(self):
        original = {"verdict": "tp", "confidence": "high"}
        self.session_run.verdict = original
        await self.session_run.asave(update_fields=["verdict", "updated_at"])

        with patch("agent.runtime.orchestrator.tools.current_session", return_value=str(self.session_run.id)):
            await _propagate_verdict_to_session(None)

        await self.session_run.arefresh_from_db()
        self.assertEqual(self.session_run.verdict, original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
