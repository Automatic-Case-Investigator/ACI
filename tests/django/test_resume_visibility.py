from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase

from agent.dashboard.runner.session_state import publish_specialist_result_to_session
from agent.models import AgentRun


class ResumeVisibilityTests(TestCase):
    def test_publish_specialist_result_updates_session_state_and_answer(self):
        session = AgentRun.objects.create(
            agent_name="orchestrator",
            case_id="~case-1",
            question="Investigate case",
            status=AgentRun.STATUS_RUNNING,
        )
        child = AgentRun.objects.create(
            agent_name="investigation",
            case_id="~case-1",
            question="Resume the prior investigation",
            status=AgentRun.STATUS_COMPLETED,
            result="## Verdict\ncompromise confirmed",
            metadata={"session_id": str(session.id)},
        )

        with patch("agent.dashboard.runner.session_state.logbus.emit") as emit:
            publish_specialist_result_to_session(str(session.id), str(child.id), reason="resume")

        session.refresh_from_db()
        orch_state = (session.metadata or {}).get("orch_session") or {}
        self.assertEqual(session.status, AgentRun.STATUS_COMPLETED)
        self.assertEqual(orch_state.get("investigation_run_id"), str(child.id))
        self.assertEqual(orch_state.get("last_investigation_status"), AgentRun.STATUS_COMPLETED)
        self.assertEqual(orch_state.get("last_investigation_report"), child.result)
        self.assertEqual(orch_state.get("visible_transcript")[-1]["role"], "assistant")
        self.assertIn("Resumed investigation run finished.", orch_state.get("visible_transcript")[-1]["content"])
        self.assertIn("Updated report below", session.result)
        emit.assert_called_once()
        self.assertEqual(emit.call_args.kwargs["metadata"]["reason"], "resume")
        self.assertEqual(emit.call_args.kwargs["metadata"]["specialist_run_id"], str(child.id))
