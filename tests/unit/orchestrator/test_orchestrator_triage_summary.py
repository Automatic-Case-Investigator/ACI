from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from agent.models import AgentRun  # noqa: E402
from agent.agents.registry import get_agent  # noqa: E402
from agent.runtime.orchestrator.tools import _agent_run_summary  # noqa: E402


class OrchestratorTriageSummaryTest(unittest.TestCase):
    def test_incomplete_budget_triage_does_not_surface_partial_report_as_handoff(self):
        agent_def = get_agent("triage")
        run = AgentRun(
            id="55555555-5555-5555-5555-555555555555",
            case_id="~1",
            agent_name="triage",
            question="triage",
            status=AgentRun.STATUS_INCOMPLETE_BUDGET,
            result="triage complete.",
            verdict={"verdict": "needs_investigation"},
        )
        summary = _agent_run_summary(agent_def, run)
        self.assertIn("status=incomplete_budget", summary)
        self.assertIn("triage_report=(unavailable: triage did not complete with a durable report)", summary)
        self.assertNotIn("triage_report=triage complete.", summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
