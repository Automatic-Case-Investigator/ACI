"""`inconclusive` is an investigation-only verdict.

Triage is a bounded first pass. "We looked hard and still cannot tell" is a claim it
is not entitled to make, so the same evidential state must surface as
`needs_investigation` — a verdict the response matrix can route to an action.
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

from agent.runtime.analysis.verdict import (
    apply_agent_scope_floor,
    apply_verdict_integrity,
    verdict_enum_line,
)


class AgentScopeFloorTests(unittest.TestCase):
    def test_triage_inconclusive_becomes_needs_investigation(self):
        out, changed = apply_agent_scope_floor(
            {"verdict": "inconclusive", "confidence": "medium"}, "triage")
        self.assertTrue(changed)
        self.assertEqual(out["verdict"], "needs_investigation")
        self.assertEqual(out["demoted_from"], "inconclusive")
        self.assertTrue(out["blocking_gaps"])

    def test_investigation_may_still_conclude_inconclusive(self):
        v = {"verdict": "inconclusive", "confidence": "medium"}
        out, changed = apply_agent_scope_floor(v, "investigation")
        self.assertFalse(changed)
        self.assertEqual(out["verdict"], "inconclusive")

    def test_triage_terminal_verdicts_pass_through(self):
        for verdict in ("tp", "fp", "needs_investigation"):
            out, changed = apply_agent_scope_floor({"verdict": verdict}, "triage")
            self.assertFalse(changed, verdict)
            self.assertEqual(out["verdict"], verdict)

    def test_existing_blocking_gaps_are_preserved(self):
        out, _ = apply_agent_scope_floor(
            {"verdict": "inconclusive", "blocking_gaps": ["original gap"]}, "triage")
        self.assertEqual(out["blocking_gaps"], ["original gap"])


class PipelineIntegrationTests(unittest.TestCase):
    def test_uncited_triage_tp_lands_on_needs_investigation_not_inconclusive(self):
        """The citation policy demotes to `inconclusive`; scope must catch that too."""
        verdict, notes = apply_verdict_integrity(
            {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence", "supporting_evidence": []},
            strict=True,
            agent_name="triage",
        )
        self.assertEqual(verdict["verdict"], "needs_investigation")

    def test_same_input_stays_inconclusive_for_investigation(self):
        verdict, _ = apply_verdict_integrity(
            {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence", "supporting_evidence": []},
            strict=False,
            agent_name="investigation",
        )
        self.assertEqual(verdict["verdict"], "inconclusive")

    def test_pipeline_is_idempotent_under_rescoping(self):
        first, _ = apply_verdict_integrity(
            {"verdict": "inconclusive"}, strict=True, agent_name="triage")
        second, notes = apply_verdict_integrity(
            first, strict=True, agent_name="triage")
        self.assertEqual(second["verdict"], "needs_investigation")
        self.assertEqual(first["verdict"], second["verdict"])


class PromptVocabularyTests(unittest.TestCase):
    def test_triage_schema_line_omits_inconclusive(self):
        line = verdict_enum_line("triage")
        self.assertNotIn("inconclusive", line)
        for verdict in ("tp", "fp", "needs_investigation"):
            self.assertIn(verdict, line)

    def test_other_agents_get_the_full_vocabulary(self):
        self.assertIn("inconclusive", verdict_enum_line("investigation"))
        self.assertIn("inconclusive", verdict_enum_line(""))


if __name__ == "__main__":
    unittest.main()
