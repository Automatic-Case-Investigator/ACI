"""
Offline test: analyst feedback loop (FeedbackEntry + PatternCandidate spawning).

Verifies the no-auto-promotion rule: a contradicting tp/fp correction spawns a
PENDING candidate, never a live PatternEntry. Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_feedback_loop.py -v
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django
django.setup()

from agent.models import AgentRun, FeedbackEntry, PatternCandidate, PatternEntry
from agent.runtime.learning.feedback import record_feedback

MARK = "ZZTEST_FB_"


class TestFeedbackLoop(unittest.TestCase):

    def setUp(self):
        self.run = AgentRun.objects.create(
            case_id=MARK + "case",
            agent_name="triage",
            question="what happened?",
            status=AgentRun.STATUS_COMPLETED,
            verdict={"verdict": "tp", "confidence": "medium", "supporting_evidence": ["e1"]},
        )

    def tearDown(self):
        PatternCandidate.objects.filter(name__startswith="Review: case " + MARK).delete()
        FeedbackEntry.objects.filter(case_id__startswith=MARK).delete()
        PatternEntry.objects.filter(name__startswith="Review: case " + MARK).delete()
        self.run.delete()

    def test_agreement_records_feedback_no_candidate(self):
        fb, candidate = record_feedback(self.run, analyst_verdict="tp", created_by="alice")
        self.assertIsNotNone(fb.id)
        self.assertIsNone(candidate)
        self.assertEqual(fb.original_verdict["verdict"], "tp")
        self.assertEqual(fb.analyst_verdict["verdict"], "tp")

    def test_contradiction_to_fp_spawns_pending_candidate(self):
        fb, candidate = record_feedback(
            self.run, analyst_verdict="fp", note="known maintenance", created_by="bob"
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.status, PatternCandidate.STATUS_PENDING)
        self.assertEqual(candidate.verdict, "fp")
        self.assertEqual(candidate.source_feedback_id, fb.id)
        # No live pattern is created — review required.
        self.assertIsNone(candidate.promoted_pattern)
        self.assertEqual(candidate.conditions, {})

    def test_contradiction_to_inconclusive_no_candidate(self):
        # inconclusive/needs_investigation are not reusable pattern labels.
        fb, candidate = record_feedback(self.run, analyst_verdict="inconclusive")
        self.assertIsNone(candidate)

    def test_accepts_full_verdict_dict(self):
        fb, candidate = record_feedback(
            self.run,
            analyst_verdict={"verdict": "fp", "confidence": "high"},
            created_by="carol",
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.confidence, "high")

    def test_no_candidate_auto_promotes_to_pattern(self):
        record_feedback(self.run, analyst_verdict="fp", created_by="dave")
        # The candidate exists but is NOT a live pattern.
        self.assertFalse(
            PatternEntry.objects.filter(name__startswith="Review: case " + MARK).exists()
        )

    def test_reassessment_does_not_duplicate_candidates(self):
        # Re-assessing the verdict (fp → tp → fp) must keep at most one pending
        # candidate for the feedback, not append one per change.
        fb, c1 = record_feedback(self.run, analyst_verdict="fp", created_by="erin")
        fb, c2 = record_feedback(self.run, analyst_verdict="tp", created_by="erin")
        fb, c3 = record_feedback(self.run, analyst_verdict="fp", created_by="erin")
        pending = PatternCandidate.objects.filter(
            source_feedback_id=fb.id, status=PatternCandidate.STATUS_PENDING
        )
        self.assertEqual(pending.count(), 1)
        self.assertEqual(pending.first().verdict, "fp")

    def test_reassessment_to_agreement_clears_candidate(self):
        # Disputing then confirming the agent verdict drops the pending candidate.
        fb, candidate = record_feedback(self.run, analyst_verdict="fp", created_by="fred")
        self.assertIsNotNone(candidate)
        fb, candidate = record_feedback(self.run, analyst_verdict="tp", created_by="fred")
        # Agent verdict is "tp"; confirming it is not a dispute → no candidate.
        self.assertIsNone(candidate)
        self.assertFalse(
            PatternCandidate.objects.filter(
                source_feedback_id=fb.id, status=PatternCandidate.STATUS_PENDING
            ).exists()
        )

    def test_feedback_on_run_without_verdict(self):
        self.run.verdict = None
        self.run.save(update_fields=["verdict"])
        fb, candidate = record_feedback(self.run, analyst_verdict="fp")
        # original None, analyst fp → contradiction → candidate spawned
        self.assertIsNone(fb.original_verdict)
        self.assertIsNotNone(candidate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
