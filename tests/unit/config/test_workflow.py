"""
Offline test: workflow dedup + escalation policy.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_workflow.py -v
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django
django.setup()

from agent.models import AgentRun
from agent.runtime.policy.workflow import (
    find_duplicate_run,
    escalation_action,
    apply_escalation_policy,
    ACTION_AUTO_CLOSE,
    ACTION_AUTO_ESCALATE,
    ACTION_HOLD,
    ACTION_NONE,
)

MARK = "ZZTEST_WF_"


class TestDedup(unittest.TestCase):

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def test_finds_active_run_in_window(self):
        AgentRun.objects.create(
            case_id=MARK + "1", agent_name="triage", question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        dup = find_duplicate_run(MARK + "1", "triage", 600)
        self.assertIsNotNone(dup)

    def test_ignores_other_agent(self):
        AgentRun.objects.create(
            case_id=MARK + "2", agent_name="triage", question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        self.assertIsNone(find_duplicate_run(MARK + "2", "investigation", 600))

    def test_ignores_completed_run(self):
        AgentRun.objects.create(
            case_id=MARK + "3", agent_name="triage", question="q",
            status=AgentRun.STATUS_COMPLETED,
        )
        self.assertIsNone(find_duplicate_run(MARK + "3", "triage", 600))

    def test_ignores_run_outside_window(self):
        run = AgentRun.objects.create(
            case_id=MARK + "4", agent_name="triage", question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        old = datetime.now(timezone.utc) - timedelta(seconds=1200)
        AgentRun.objects.filter(id=run.id).update(created_at=old)
        self.assertIsNone(find_duplicate_run(MARK + "4", "triage", 600))

    def test_window_zero_disables(self):
        AgentRun.objects.create(
            case_id=MARK + "5", agent_name="triage", question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        self.assertIsNone(find_duplicate_run(MARK + "5", "triage", 0))


class TestEscalation(unittest.TestCase):

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def test_action_mapping(self):
        self.assertEqual(escalation_action({"verdict": "fp"}), ACTION_AUTO_CLOSE)
        self.assertEqual(escalation_action({"verdict": "tp"}), ACTION_AUTO_ESCALATE)
        self.assertEqual(escalation_action({"verdict": "inconclusive"}), ACTION_HOLD)
        self.assertEqual(escalation_action({"verdict": "needs_investigation"}), ACTION_HOLD)
        self.assertEqual(escalation_action(None), ACTION_NONE)

    def test_tp_with_nonblocking_gaps_still_escalates(self):
        verdict = {
            "verdict": "tp",
            "confidence": "high",
            "classification_basis": "malicious_evidence",
            "supporting_evidence": ["reverse shell in crontab"],
            "nonblocking_gaps": ["collect EDR process tree"],
        }
        self.assertEqual(escalation_action(verdict), ACTION_AUTO_ESCALATE)

    def test_fp_with_nonblocking_gaps_still_closes(self):
        verdict = {
            "verdict": "fp",
            "confidence": "high",
            "classification_basis": "benign_evidence",
            "supporting_evidence": ["approved change ticket"],
            "nonblocking_gaps": ["no packet capture available"],
        }
        self.assertEqual(escalation_action(verdict), ACTION_AUTO_CLOSE)

    def test_apply_records_decision_on_run(self):
        run = AgentRun.objects.create(
            case_id=MARK + "esc", agent_name="triage", question="q",
            status=AgentRun.STATUS_COMPLETED,
            verdict={"verdict": "fp", "confidence": "high"},
        )
        decision = apply_escalation_policy(run)
        self.assertEqual(decision["action"], ACTION_AUTO_CLOSE)
        run.refresh_from_db()
        self.assertEqual(run.metadata["escalation"]["action"], ACTION_AUTO_CLOSE)
        self.assertEqual(run.metadata["escalation"]["verdict"], "fp")

    def test_apply_no_verdict_is_none_action(self):
        run = AgentRun.objects.create(
            case_id=MARK + "esc2", agent_name="triage", question="q",
            status=AgentRun.STATUS_COMPLETED, verdict=None,
        )
        decision = apply_escalation_policy(run)
        self.assertEqual(decision["action"], ACTION_NONE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
