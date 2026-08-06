"""What `document` and `resolve` actually send to TheHive.

`document` posts the run's investigation report as a case page, not a one-line note,
so the case carries the reasoning rather than just the disposition. `resolve` does
the same and then changes status — in that order, so a failed status update still
leaves the case explained.
"""
from __future__ import annotations


import os
import sys
import unittest
from unittest import mock

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django

django.setup()

from django.test import TestCase as DjangoTestCase

from agent.models import AgentRun, ResponsePolicy
from agent.runtime.response_policy import policy
from agent.runtime.response_policy.execution import _report_body, execute_response
from agent.runtime.response_policy.workflow import (
    DECISION_KEY,
    _LEGACY_DECISION_KEY,
    read_decision,
    store_decision,
)

MARK = "ZZTEST_EXEC_"
REPORT = "## Triage Summary\nphopkins ran `sudo cat /etc/shadow`.\n\n## Key Evidence\n- evt-1\n"


class _FakeClient:
    def __init__(self):
        self.reports = []
        self.updates = []
        self.comments = []
        self.promoted = []
        self.promote_result = {"_id": "case-99"}

    def post_report(self, case_id, summary, title="Investigation Report"):
        self.reports.append({"case_id": case_id, "summary": summary, "title": title})

    def post_case_comment(self, case_id, message):
        self.comments.append({"case_id": case_id, "message": message})

    def update_case(self, case_id, fields):
        self.updates.append({"case_id": case_id, "fields": fields})

    def promote_alert_to_case(self, alert_id, fields=None):
        self.promoted.append(alert_id)
        return self.promote_result


def _patch_client(client):
    return mock.patch("aci_thehive.client.TheHiveClient", return_value=client)


class ExecutionTests(DjangoTestCase):
    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def _run(self, action, verdict=None, *, key=DECISION_KEY):
        run = AgentRun.objects.create(
            case_id=MARK + "1", agent_name="triage", question="q",
            status=AgentRun.STATUS_COMPLETED,
            result=REPORT,
            verdict=verdict or {"verdict": "tp", "confidence": "high"},
            metadata={
                "source_entity_type": "case",
                key: {
                    "action": action,
                    "verdict": (verdict or {}).get("verdict", "tp"),
                    "confidence": "high",
                },
            },
        )
        client = _FakeClient()
        with _patch_client(client):
            execute_response(run)
        return run, client

    def test_document_posts_the_report_body(self):
        _, client = self._run(policy.DOCUMENT)
        self.assertEqual(len(client.reports), 1)
        self.assertIn("sudo cat /etc/shadow", client.reports[0]["summary"])
        self.assertIn("TP", client.reports[0]["title"])

    def test_document_changes_no_case_state(self):
        _, client = self._run(policy.DOCUMENT)
        self.assertEqual(client.updates, [])

    def test_resolve_documents_before_changing_status(self):
        _, client = self._run(policy.RESOLVE)
        self.assertEqual(len(client.reports), 1)
        self.assertIn("sudo cat /etc/shadow", client.reports[0]["summary"])
        self.assertEqual(client.updates[0]["fields"], {"status": "Resolved"})

    def test_resolve_marks_a_false_positive_distinctly(self):
        _, client = self._run(policy.RESOLVE, verdict={"verdict": "fp", "confidence": "high"})
        self.assertEqual(client.updates[0]["fields"], {"status": "FalsePositive"})

    def test_none_touches_nothing(self):
        _, client = self._run(policy.NONE)
        self.assertEqual((client.reports, client.updates, client.comments), ([], [], []))

    def test_execution_is_idempotent(self):
        run, _ = self._run(policy.DOCUMENT)
        second = _FakeClient()
        with _patch_client(second):
            execute_response(AgentRun.objects.get(id=run.id))
        self.assertEqual(second.reports, [], "already-executed run must not re-post")


class LegacyDecisionKeyTests(unittest.TestCase):
    """Runs recorded before the rename stored the decision under `escalation`."""

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def _run(self, metadata):
        return AgentRun.objects.create(
            case_id=MARK + "legacy", agent_name="triage", question="q",
            status=AgentRun.STATUS_COMPLETED, result=REPORT,
            verdict={"verdict": "fp", "confidence": "high"}, metadata=metadata)

    def test_read_falls_back_to_the_legacy_key(self):
        run = self._run({_LEGACY_DECISION_KEY: {"action": policy.RESOLVE}})
        self.assertEqual(read_decision(run)["action"], policy.RESOLVE)

    def test_current_key_wins_when_both_are_present(self):
        run = self._run({
            _LEGACY_DECISION_KEY: {"action": policy.RESOLVE},
            DECISION_KEY: {"action": policy.DOCUMENT},
        })
        self.assertEqual(read_decision(run)["action"], policy.DOCUMENT)

    def test_missing_and_malformed_decisions_read_as_empty(self):
        self.assertEqual(read_decision(self._run({})), {})
        self.assertEqual(read_decision(self._run({DECISION_KEY: "not-a-dict"})), {})
        self.assertEqual(read_decision(self._run({DECISION_KEY: {}})), {})

    def test_a_legacy_run_still_executes(self):
        run = self._run({
            "source_entity_type": "case",
            _LEGACY_DECISION_KEY: {"action": policy.DOCUMENT, "verdict": "fp",
                                   "confidence": "high"},
        })
        client = _FakeClient()
        with _patch_client(client):
            execute_response(run)
        self.assertEqual(len(client.reports), 1)

    def test_writing_migrates_off_the_legacy_key(self):
        meta = store_decision(
            {_LEGACY_DECISION_KEY: {"action": policy.RESOLVE}},
            {"action": policy.DOCUMENT},
        )
        self.assertNotIn(_LEGACY_DECISION_KEY, meta)
        self.assertEqual(meta[DECISION_KEY]["action"], policy.DOCUMENT)

    def test_executing_a_legacy_run_leaves_only_the_current_key(self):
        run = self._run({
            "source_entity_type": "case",
            _LEGACY_DECISION_KEY: {"action": policy.DOCUMENT, "verdict": "fp",
                                   "confidence": "high"},
        })
        with _patch_client(_FakeClient()):
            execute_response(run)
        meta = AgentRun.objects.get(id=run.id).metadata
        self.assertNotIn(_LEGACY_DECISION_KEY, meta)
        self.assertTrue(meta[DECISION_KEY]["executed_at"])


class ReportBodyTests(unittest.TestCase):
    def _run(self, result):
        return AgentRun(
            case_id=MARK + "b", agent_name="triage", question="q", result=result)

    def test_body_leads_with_the_verdict_then_the_report(self):
        body = _report_body(self._run(REPORT), "TP", "high")
        self.assertLess(body.index("TP"), body.index("Triage Summary"))
        self.assertIn("confidence: high", body)

    def test_empty_result_still_produces_a_usable_page(self):
        body = _report_body(self._run(""), "FP", "medium")
        self.assertIn("FP", body)
        self.assertIn("no report body", body)


if __name__ == "__main__":
    unittest.main()


class FailureFallbackExecutionTests(unittest.TestCase):
    """A failed run must say so on the case rather than leaving it silent."""

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def _failed_run(self, action, reason="run_failed", result=""):
        run = AgentRun.objects.create(
            case_id=MARK + "fail", agent_name="triage", question="q",
            status=AgentRun.STATUS_FAILED, result=result, verdict=None,
            metadata={
                "source_entity_type": "case",
                DECISION_KEY: {"action": action, "fallback_reason": reason},
            },
        )
        client = _FakeClient()
        with _patch_client(client):
            execute_response(run)
        return client

    def test_the_posted_page_states_the_case_was_not_triaged(self):
        client = self._failed_run(policy.DOCUMENT)
        body = client.reports[0]["summary"]
        self.assertIn("did not produce a verdict", body)
        self.assertIn("NOT been triaged", body)

    def test_the_page_title_marks_the_failure(self):
        client = self._failed_run(policy.DOCUMENT)
        self.assertIn("did not complete", client.reports[0]["title"])

    def test_partial_output_is_still_carried_across(self):
        client = self._failed_run(policy.DOCUMENT, result="## Triage Summary\npartial work")
        self.assertIn("partial work", client.reports[0]["summary"])

    def test_no_case_state_is_changed_by_a_failure(self):
        client = self._failed_run(policy.DOCUMENT)
        self.assertEqual(client.updates, [])

    def test_a_no_verdict_failure_reads_differently_from_a_crash(self):
        crashed = self._report("run_failed")
        no_verdict = self._report("no_verdict")
        self.assertIn("stopped with an error", crashed)
        self.assertIn("no usable verdict", no_verdict)

    def _report(self, reason):
        run = AgentRun(case_id=MARK + "b", agent_name="triage", question="q", result="")
        return _report_body(run, "UNKNOWN", "?", {"fallback_reason": reason})


class PromoteCaseTests(unittest.TestCase):
    """`promote_case` creates the case via TheHive, then documents onto it."""

    def tearDown(self):
        AgentRun.objects.filter(case_id__startswith=MARK).delete()

    def _promote(self, created=None, alert_id=None):
        run = AgentRun.objects.create(
            case_id=alert_id or (MARK + "alert"), agent_name="triage", question="q",
            status=AgentRun.STATUS_COMPLETED, result=REPORT,
            verdict={"verdict": "tp", "confidence": "high"},
            metadata={
                "source_entity_type": "alert",
                DECISION_KEY: {"action": policy.PROMOTE_CASE, "verdict": "tp",
                               "confidence": "high"},
            },
        )
        client = _FakeClient()
        if created is not None:
            client.promote_result = created
        with _patch_client(client):
            execute_response(run)
        return run, client

    def test_the_alert_is_promoted_then_documented_on_the_new_case(self):
        run, client = self._promote()
        self.assertEqual(client.promoted, [run.case_id])
        self.assertEqual(len(client.reports), 1)
        # The report lands on the CASE that was created, not on the alert.
        self.assertEqual(client.reports[0]["case_id"], "case-99")
        self.assertIn("sudo cat /etc/shadow", client.reports[0]["summary"])

    def test_the_new_case_id_is_recorded_on_the_run(self):
        run, _ = self._promote()
        self.assertEqual(read_decision(AgentRun.objects.get(id=run.id))["promoted_case_id"],
                         "case-99")

    def test_alternate_id_keys_from_thehive_are_accepted(self):
        _, client = self._promote(created={"caseId": "case-77"})
        self.assertEqual(client.reports[0]["case_id"], "case-77")

    def test_a_promotion_returning_no_id_is_an_execution_error(self):
        run, client = self._promote(created={})
        self.assertEqual(client.reports, [], "must not document without a case")
        self.assertIn("execution_error", read_decision(AgentRun.objects.get(id=run.id)))

    def test_the_alert_guard_no_longer_blocks_promotion(self):
        # Other case-targeting actions still skip on an alert subject; promotion is
        # the one action whose whole purpose is to act on one.
        _, client = self._promote()
        self.assertTrue(client.promoted)
