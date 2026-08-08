"""
Offline test: workflow dedup + response policy.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_workflow.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django

django.setup()

from agent.models import AgentRun
from django.test import TestCase as DjangoTestCase

from agent.models import ResponsePolicy
from agent.runtime.response_policy import policy
from agent.runtime.response_policy.workflow import (
    find_duplicate_run,
    response_action,
    apply_response_policy,
    read_decision,
    ACTION_NONE,
)

MARK = "ZZTEST_WF_"


def matrix_default_fallback():
    """Shipped failure-fallback action for a case subject."""
    return policy.default_action(policy.FAILURE_FALLBACK, policy.CASE)


class TestDedup(unittest.TestCase):

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def test_finds_active_run_in_window(self):
        AgentRun.objects.create(
            case_id=MARK + "1",
            agent_name="triage",
            question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        dup = find_duplicate_run(MARK + "1", "triage", 600)
        self.assertIsNotNone(dup)

    def test_ignores_other_agent(self):
        AgentRun.objects.create(
            case_id=MARK + "2",
            agent_name="triage",
            question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        self.assertIsNone(find_duplicate_run(MARK + "2", "investigation", 600))

    def test_ignores_completed_run(self):
        AgentRun.objects.create(
            case_id=MARK + "3",
            agent_name="triage",
            question="q",
            status=AgentRun.STATUS_COMPLETED,
        )
        self.assertIsNone(find_duplicate_run(MARK + "3", "triage", 600))

    def test_ignores_run_outside_window(self):
        run = AgentRun.objects.create(
            case_id=MARK + "4",
            agent_name="triage",
            question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        old = datetime.now(timezone.utc) - timedelta(seconds=1200)
        AgentRun.objects.filter(id=run.id).update(created_at=old)
        self.assertIsNone(find_duplicate_run(MARK + "4", "triage", 600))

    def test_window_zero_disables(self):
        AgentRun.objects.create(
            case_id=MARK + "5",
            agent_name="triage",
            question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        self.assertIsNone(find_duplicate_run(MARK + "5", "triage", 0))


class TestResponsePolicy(DjangoTestCase):
    """The (verdict, subject) matrix and the failure fallback."""

    def setUp(self):
        # Inside the per-test transaction, so the operator's real saved policy rows
        # are restored on rollback. Deleting outside one would wipe live settings.
        ResponsePolicy.objects.all().delete()

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def _run(self, **over):
        fields = dict(
            case_id=MARK + "esc",
            agent_name="triage",
            question="q",
            status=AgentRun.STATUS_COMPLETED,
            verdict={"verdict": "fp", "confidence": "high"},
            metadata={"source_entity_type": "case"},
        )
        fields.update(over)
        return AgentRun.objects.create(**fields)

    def test_shipped_defaults_document_cases_and_ignore_alerts(self):
        self.assertEqual(response_action({"verdict": "tp"}), policy.DOCUMENT)
        self.assertEqual(response_action(None), ACTION_NONE)

    def test_subject_split_reads_the_trigger_provider(self):
        case = self._run(metadata={"source_entity_type": "case"})
        soar = self._run(metadata={"source_entity_type": "alert"})
        siem = self._run(
            metadata={"source_entity_type": "alert", "trigger_provider": "wazuh"}
        )
        self.assertEqual(policy.subject_for_run(case), policy.CASE)
        # SOAR and SIEM alerts share one subject — the provider is not consulted.
        self.assertEqual(policy.subject_for_run(soar), policy.ALERT)
        self.assertEqual(policy.subject_for_run(siem), policy.ALERT)

    def test_configured_resolve_fires_on_a_clean_run(self):
        ResponsePolicy.objects.create(
            verdict="fp", subject="case", action=policy.RESOLVE
        )
        run = self._run(
            verdict={
                "verdict": "fp",
                "confidence": "high",
                "classification_basis": "benign_evidence",
                "supporting_evidence": ["approved change ticket"],
                "nonblocking_gaps": ["no packet capture available"],
            }
        )
        decision = apply_response_policy(run)
        self.assertEqual(decision["action"], policy.RESOLVE)
        self.assertNotIn("withheld_reason", decision)

    def test_promote_case_is_a_normal_executable_decision(self):
        ResponsePolicy.objects.create(
            verdict="tp", subject="alert", action=policy.PROMOTE_CASE
        )
        run = self._run(
            verdict={"verdict": "tp", "confidence": "high"},
            metadata={"source_entity_type": "alert"},
        )
        decision = apply_response_policy(run)
        self.assertEqual(decision["action"], policy.PROMOTE_CASE)
        self.assertNotIn("pending_connector", decision)

    def test_apply_records_subject_and_decision_on_run(self):
        run = self._run()
        decision = apply_response_policy(run)
        run.refresh_from_db()
        self.assertEqual(read_decision(run)["action"], decision["action"])
        self.assertEqual(read_decision(run)["subject"], policy.CASE)
        self.assertEqual(read_decision(run)["verdict"], "fp")

    def test_a_run_without_a_verdict_uses_the_failure_fallback(self):
        # Previously this recorded `none` and left the case with no trace at all.
        run = self._run(case_id=MARK + "esc2", verdict=None)
        decision = apply_response_policy(run)
        self.assertEqual(decision["fallback_reason"], "no_verdict")
        self.assertEqual(decision["action"], matrix_default_fallback())

    def test_a_failed_run_uses_the_failure_fallback(self):
        run = self._run(case_id=MARK + "esc3", status=AgentRun.STATUS_FAILED)
        decision = apply_response_policy(run)
        self.assertEqual(decision["fallback_reason"], "run_failed")

    def test_an_over_budget_run_still_uses_its_verdict(self):
        # Over budget is a truncated success, not a failure: it has a verdict, so the
        # verdict rows apply; the verdict pipeline has already floored the weak cases.
        run = self._run(case_id=MARK + "esc4", status="incomplete_budget")
        decision = apply_response_policy(run)
        self.assertNotIn("fallback_reason", decision)
        self.assertEqual(decision["verdict"], "fp")


if __name__ == "__main__":
    unittest.main(verbosity=2)
