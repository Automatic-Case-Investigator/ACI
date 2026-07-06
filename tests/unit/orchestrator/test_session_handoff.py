"""Unit tests for AVFS session-handoff embrace (Phase 1 #12).

Covers the workspace folder helpers and the session-note builder that lets the next
run resume per the AVFS prompt's "read /sessions first" guidance.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from agent.runtime.graph.nodes_flow import _build_session_note, _extract_section  # noqa: E402
from agent.runtime.infra.avfs import (  # noqa: E402
    home_dir,
    knowledge_dir,
    sessions_dir,
    session_note_path,
    tasks_dir,
    workspace_dirs,
)
from agent.models import AgentRun  # noqa: E402
from agent.runtime.orchestrator.session import OrchestratorSession  # noqa: E402
from agent.runtime.orchestrator.specialist_sync import apply_specialist_run_to_session  # noqa: E402
from agent.dashboard.runner.lifecycle import start_investigation_from_triage  # noqa: E402


class WorkspaceDirsTest(unittest.TestCase):
    def test_workspace_dirs_are_under_home(self):
        home = home_dir()
        for d in workspace_dirs():
            self.assertTrue(d.startswith(home), d)

    def test_standard_folders_present(self):
        dirs = set(workspace_dirs())
        self.assertIn(sessions_dir(), dirs)
        self.assertIn(tasks_dir(), dirs)
        self.assertIn(knowledge_dir(), dirs)

    def test_session_note_path_shape(self):
        path = session_note_path("0057033e-8976-4bd6-b272-2466641174d3")
        self.assertTrue(path.startswith(sessions_dir() + "/"))
        self.assertTrue(path.endswith(".md"))
        # short id is the first dash-delimited segment, truncated to 8 chars
        self.assertIn("0057033e", path)

    def test_session_note_path_handles_missing_run_id(self):
        path = session_note_path("")
        self.assertTrue(path.endswith(".md"))


class ExtractSectionTest(unittest.TestCase):
    REPORT = (
        "## Verdict\ntp; high; active\n\n"
        "## Executive Summary\nLateral movement by hwarren confirmed.\n\n"
        "## Timeline\n- t1\n"
    )

    def test_extracts_named_section(self):
        self.assertEqual(
            _extract_section(self.REPORT, "Executive Summary"),
            "Lateral movement by hwarren confirmed.",
        )

    def test_case_insensitive(self):
        self.assertIn("hwarren", _extract_section(self.REPORT, "executive summary"))

    def test_absent_section_returns_empty(self):
        self.assertEqual(_extract_section(self.REPORT, "Open Gaps"), "")


class SessionNoteBuilderTest(unittest.TestCase):
    def _state(self, **kw):
        base = {
            "case_id": "~449101824",
            "run_id": "0057033e-8976-4bd6",
            "status": "incomplete_budget",
            "agent_name": "investigation",
        }
        base.update(kw)
        return base

    def test_note_carries_verdict_summary_and_gaps(self):
        verdict = {
            "verdict": "needs_investigation", "confidence": "high",
            "triage_verdict": "needs_investigation",
            "impact_state": "active", "scope_state": "lateral_spread",
            "blocking_gaps": ["cannot confirm C2"],
            "nonblocking_gaps": ["initial access vector"],
            "recommended_action": "escalate to tier 2",
        }
        final = (
            "## Executive Summary\nAttacker 172.17.130.196 authed as hwarren.\n\n"
            "## Open Gaps\n- C2 destination unknown\n"
        )
        note = _build_session_note(self._state(), verdict, final)
        self.assertIn("NEEDS_INVESTIGATION", note)
        self.assertIn("hwarren", note)
        self.assertIn("cannot confirm C2", note)
        self.assertIn("escalate to tier 2", note)
        self.assertIn("~449101824", note)

    def test_note_without_verdict_still_builds(self):
        note = _build_session_note(self._state(), None, "## Executive Summary\nDid X.\n")
        self.assertIn("Session handoff", note)
        self.assertIn("Did X.", note)


class TriageHandoffValidityTest(unittest.TestCase):
    def test_completed_triage_persists_durable_report(self):
        session = OrchestratorSession()
        run = AgentRun(
            id="11111111-1111-1111-1111-111111111111",
            case_id="~1",
            agent_name="triage",
            question="triage",
            status=AgentRun.STATUS_COMPLETED,
            result="## Triage Summary\nComplete report",
        )
        apply_specialist_run_to_session(session, run)
        self.assertEqual(session.last_triage_status, AgentRun.STATUS_COMPLETED)
        self.assertEqual(session.last_triage_report, "## Triage Summary\nComplete report")

    def test_incomplete_budget_triage_does_not_persist_handoff_report(self):
        session = OrchestratorSession(last_triage_report="older report")
        run = AgentRun(
            id="22222222-2222-2222-2222-222222222222",
            case_id="~1",
            agent_name="triage",
            question="triage",
            status=AgentRun.STATUS_INCOMPLETE_BUDGET,
            result="partial triage text",
        )
        apply_specialist_run_to_session(session, run)
        self.assertEqual(session.last_triage_status, AgentRun.STATUS_INCOMPLETE_BUDGET)
        self.assertIsNone(session.last_triage_report)

    def test_workflow_auto_investigation_rejects_incomplete_triage(self):
        source_run = AgentRun(
            id="33333333-3333-3333-3333-333333333333",
            case_id="~1",
            agent_name="triage",
            question="triage",
            status=AgentRun.STATUS_INCOMPLETE_BUDGET,
            result="partial triage text",
        )
        with self.assertRaises(ValueError):
            start_investigation_from_triage(source_run)

    def test_workflow_auto_investigation_carries_triage_status(self):
        source_run = AgentRun(
            id="44444444-4444-4444-4444-444444444444",
            case_id="~1",
            agent_name="triage",
            question="triage",
            status=AgentRun.STATUS_COMPLETED,
            result="## Triage Summary\nComplete report",
        )
        with patch("agent.dashboard.runner.lifecycle.start_session", return_value="sess-1") as start:
            session_id = start_investigation_from_triage(source_run)
        self.assertEqual(session_id, "sess-1")
        self.assertEqual(start.call_args.kwargs["orch_state"]["last_triage_status"], AgentRun.STATUS_COMPLETED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
