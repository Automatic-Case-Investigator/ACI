"""The response matrix is the authority on what each cell may offer.

These pin the shape of the approved matrix so a later edit to `ALLOWED_ACTIONS` has
to be deliberate — particularly the two cut decisions (no dismiss/suppress for FP
alerts, no escalate for the uncertain verdicts), which read as omissions otherwise.
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

from agent.runtime.analysis.verdict import VERDICT_ORDER
from agent.runtime.response_policy import policy


class MatrixShapeTests(unittest.TestCase):
    def test_every_row_subject_pair_has_a_cell(self):
        self.assertEqual(len(policy.cells()), len(policy.POLICY_ROWS) * len(policy.SUBJECT_ORDER))
        # The grid is the four verdicts plus the failure row.
        self.assertEqual(policy.POLICY_ROWS, VERDICT_ORDER + (policy.FAILURE_FALLBACK,))
        for cell in policy.cells():
            self.assertIn(cell, policy.ALLOWED_ACTIONS, cell)

    def test_none_is_always_offerable(self):
        for verdict, subject in policy.cells():
            self.assertIn(policy.NONE, policy.allowed_actions(verdict, subject))

    def test_every_default_is_within_its_own_menu(self):
        for verdict, subject in policy.cells():
            self.assertTrue(
                policy.is_allowed(verdict, subject, policy.default_action(verdict, subject)),
                f"{verdict}/{subject}",
            )


class ApprovedDecisionsTests(unittest.TestCase):
    def test_fp_on_alerts_is_a_deliberate_no_op(self):
        # Dismiss and suppress were cut; this row must stay single-option.
        self.assertEqual(policy.allowed_actions("fp", policy.ALERT), (policy.NONE,))

    def test_soar_and_siem_alerts_share_one_subject(self):
        # Which system raised an alert does not change what can be done with it.
        self.assertEqual(policy.SUBJECT_ORDER, (policy.CASE, policy.ALERT))
        self.assertEqual(set(policy.LEGACY_SUBJECTS.values()), {policy.ALERT})

    def test_alerts_are_promoted_not_annotated(self):
        # `promote_case` carries the report, so no document-on-alert action exists.
        self.assertFalse(hasattr(policy, "DOCUMENT_ALERT"))
        for verdict in VERDICT_ORDER:
            self.assertNotIn(
                "document_alert", policy.allowed_actions(verdict, policy.ALERT), verdict)

    def test_escalate_is_not_an_action_anywhere(self):
        # Removed: it could only bump TheHive severity and leave a note, so it
        # promised urgency it could not deliver. Documenting the report replaces it.
        for verdict, subject in policy.cells():
            self.assertNotIn(
                "escalate", policy.allowed_actions(verdict, subject), f"{verdict}/{subject}")

    def test_a_confirmed_case_can_be_resolved_or_documented(self):
        self.assertEqual(
            policy.allowed_actions("tp", policy.CASE),
            (policy.RESOLVE, policy.DOCUMENT, policy.NONE))

    def test_alerts_cannot_be_resolved(self):
        # A confirmed detection on an alert is promoted, not finished.
        for verdict in VERDICT_ORDER:
            self.assertNotIn(
                policy.RESOLVE, policy.allowed_actions(verdict, policy.ALERT), verdict)

    def test_uncertain_verdicts_can_always_launch_an_investigation(self):
        for verdict in ("inconclusive", "needs_investigation"):
            for subject in policy.SUBJECT_ORDER:
                self.assertIn(
                    policy.INVESTIGATE, policy.allowed_actions(verdict, subject),
                    f"{verdict}/{subject}")

    def test_no_default_auto_resolves_a_case(self):
        # Promotion is a shipped default; closing a case never is. Creating a case is
        # additive and reversible, resolving one asserts the work is finished.
        for verdict, subject in policy.cells():
            self.assertNotEqual(
                policy.default_action(verdict, subject), policy.RESOLVE,
                f"{verdict}/{subject}")

    def test_unresolved_verdicts_default_to_investigating(self):
        for subject in policy.SUBJECT_ORDER:
            self.assertEqual(
                policy.default_action("needs_investigation", subject), policy.INVESTIGATE)

    def test_the_failure_row_never_defaults_to_a_write(self):
        self.assertEqual(policy.default_action(policy.FAILURE_FALLBACK, policy.CASE),
                         policy.DOCUMENT)
        self.assertEqual(policy.default_action(policy.FAILURE_FALLBACK, policy.ALERT),
                         policy.NONE)


if __name__ == "__main__":
    unittest.main()
