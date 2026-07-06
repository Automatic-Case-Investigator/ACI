"""Unit tests for the per-task self-review (graph/reflection.py).

The self-review replaces the six assess-node guards with one model call that returns
a conclude/keep_working decision plus per-finding verdicts. These tests cover JSON
parsing, the findings split, fail-open behavior, the decision plumbing for each
scenario the old guards handled, and the agent-facing feedback / board-gating state.

The model's judgment itself cannot be unit-tested deterministically, so a stub model
returns the canned JSON each scenario would produce and we assert the harness builds
the right TaskReview from it.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from agent.runtime.graph.reflection import (  # noqa: E402
    TaskReview,
    _parse_review,
    _split_findings,
    review_task_model,
)


class _StubModel:
    """Minimal async chat model returning a canned response (or raising)."""

    def __init__(self, content="", exc=None):
        self._content = content
        self._exc = exc
        self.calls = 0

    async def ainvoke(self, messages):
        self.calls += 1
        if self._exc:
            raise self._exc

        class _R:
            content = self._content
        return _R()


def _run(coro):
    return asyncio.run(coro)


class ParseReviewTest(unittest.TestCase):
    def test_parses_object(self):
        raw = '{"findings": [], "decision": "conclude", "feedback": ""}'
        self.assertEqual(_parse_review(raw)["decision"], "conclude")

    def test_unparseable_returns_none(self):
        self.assertIsNone(_parse_review("not json at all"))
        self.assertIsNone(_parse_review(""))

    def test_object_embedded_in_prose(self):
        raw = 'Sure:\n{"decision":"keep_working","findings":[],"feedback":"do x"}\nthanks'
        self.assertEqual(_parse_review(raw)["decision"], "keep_working")

    def test_array_is_not_an_object(self):
        # The findings verifier returns an array; the reviewer must return an object.
        self.assertIsNone(_parse_review("[]"))


class SplitFindingsTest(unittest.TestCase):
    def test_split_verified_and_rejected(self):
        data = {"findings": [
            {"text": "evt-1 webshell", "status": "confirmed", "grounded": True, "novel": True},
            {"text": "scan 1.2.3.4", "status": "restated", "grounded": True, "novel": False, "reason": "board fact"},
            {"text": "esc claim", "status": "ungrounded", "grounded": False, "novel": True, "reason": "not retrieved"},
        ]}
        fv = _split_findings(data)
        self.assertEqual(fv.verified_count, 1)
        self.assertEqual(len(fv.rejected), 2)

    def test_missing_findings_key_is_empty(self):
        fv = _split_findings({"decision": "conclude"})
        self.assertEqual(fv.verified_count, 0)
        self.assertEqual(len(fv.rejected), 0)


class ReviewPromptContractTest(unittest.TestCase):
    """The task's completion contract (interpret's success criteria) is the reviewer's
    yardstick for DONE — rendered as its own block when present, absent otherwise."""

    def _prompt(self, stop_condition=""):
        from agent.runtime.graph.reflection import _build_review_prompt
        return _build_review_prompt(
            findings_section="- evt-1 confirmed reverse shell.",
            new_leads_section="- None.",
            evidence_digest="Event ids retrieved this task: evt-1",
            board_facts=[],
            current_task={"title": "Decode the embedded payload"},
            signals={"evidence_queries": 1},
            stop_condition=stop_condition,
        )

    def test_stop_condition_renders_as_completion_contract(self):
        p = self._prompt("(a) payload decoded — unmet; (b) destination named — unmet")
        self.assertIn("Task completion contract", p)
        self.assertIn("payload decoded", p)

    def test_no_contract_block_when_absent(self):
        self.assertNotIn("Task completion contract", self._prompt(""))


class ReviewTaskModelTest(unittest.TestCase):
    def _kwargs(self, **over):
        base = dict(
            findings_section="- evt-1 confirmed reverse shell.",
            new_leads_section="- None.",
            evidence_digest="Event ids retrieved this task: evt-1",
            board_facts=[],
            current_task={"title": "Pivot on 10.0.2.5"},
            agent_name="investigation",
            signals={"evidence_queries": 3, "hit_count": 12, "hit_ceiling": False, "unpivoted_iocs": []},
        )
        base.update(over)
        return base

    def test_model_none_fails_open(self):
        self.assertIsNone(_run(review_task_model(None, **self._kwargs())))

    def test_exception_fails_open(self):
        self.assertIsNone(_run(review_task_model(_StubModel(exc=RuntimeError("boom")), **self._kwargs())))

    def test_unparseable_fails_open(self):
        self.assertIsNone(_run(review_task_model(_StubModel("garbage"), **self._kwargs())))

    def test_conclude_on_grounded_complete_task(self):
        content = json.dumps({
            "findings": [{"text": "evt-1 reverse shell to 10.0.2.5", "status": "confirmed",
                          "grounded": True, "novel": True}],
            "decision": "conclude", "feedback": "grounded and complete",
        })
        review = _run(review_task_model(_StubModel(content), **self._kwargs()))
        self.assertIsNotNone(review)
        self.assertFalse(review.keep_working)
        self.assertEqual(review.verified_count, 1)

    def test_keep_working_orient_only(self):
        # Task asked for SIEM evidence but only oriented — model says keep working.
        content = json.dumps({
            "findings": [], "decision": "keep_working",
            "feedback": "No evidence query ran; search data.srcip=10.0.2.5 in the alert window.",
        })
        review = _run(review_task_model(
            _StubModel(content), **self._kwargs(findings_section="- None.",
                                                signals={"evidence_queries": 0, "hit_count": None,
                                                         "hit_ceiling": False, "unpivoted_iocs": []})))
        self.assertTrue(review.keep_working)
        self.assertIn("search data.srcip", review.to_feedback())

    def test_keep_working_restated_findings(self):
        content = json.dumps({
            "findings": [{"text": "alert says brute force", "status": "restated",
                          "grounded": True, "novel": False, "reason": "paraphrase of the alert"}],
            "decision": "keep_working", "feedback": "Substantiate with a retrieved event id.",
        })
        review = _run(review_task_model(_StubModel(content), **self._kwargs()))
        self.assertTrue(review.keep_working)
        self.assertEqual(review.verified_count, 0)
        self.assertIn("REJECTED [restated]", review.to_feedback())

    def test_keep_working_on_ceiling_result(self):
        content = json.dumps({
            "findings": [], "decision": "keep_working",
            "feedback": "10000-hit result is a sample; narrow the window and add rule.id.",
        })
        review = _run(review_task_model(
            _StubModel(content), **self._kwargs(signals={"evidence_queries": 2, "hit_count": 10000,
                                                         "hit_ceiling": True, "unpivoted_iocs": []})))
        self.assertTrue(review.keep_working)

    def test_keep_working_unpivoted_c2(self):
        content = json.dumps({
            "findings": [{"text": "evt-1 C2 callback to 10.0.2.5", "status": "confirmed",
                          "grounded": True, "novel": True}],
            "decision": "keep_working",
            "feedback": "Add a New Leads pivot on 10.0.2.5 toward initial access.",
        })
        review = _run(review_task_model(
            _StubModel(content), **self._kwargs(signals={"evidence_queries": 4, "hit_count": 8,
                                                         "hit_ceiling": False, "unpivoted_iocs": ["10.0.2.5"]})))
        self.assertTrue(review.keep_working)
        self.assertIn("10.0.2.5", review.to_feedback())

    def test_unknown_decision_defaults_to_conclude(self):
        content = json.dumps({"findings": [], "decision": "maybe??", "feedback": ""})
        review = _run(review_task_model(_StubModel(content), **self._kwargs()))
        self.assertFalse(review.keep_working)

    def test_unqueried_clusters_signal_reaches_the_prompt(self):
        from agent.runtime.graph.reflection import _build_review_prompt
        prompt = _build_review_prompt(
            findings_section="- x", new_leads_section="- None.",
            evidence_digest="d", board_facts=[], current_task=None,
            signals={"evidence_queries": 2, "unqueried_clusters": ["2022-01-18T13:34:00Z"]},
        )
        self.assertIn("2022-01-18T13:34:00Z", prompt)
        self.assertIn("never queried", prompt.lower())

    def test_unqueried_time_ranges_signal_reaches_the_prompt(self):
        from agent.runtime.graph.reflection import _build_review_prompt
        prompt = _build_review_prompt(
            findings_section="- x", new_leads_section="- None.",
            evidence_digest="d", board_facts=[], current_task=None,
            signals={"evidence_queries": 3,
                     "unqueried_time_ranges": ["2022-01-18T12:29:00Z–2022-01-18T13:14:00Z"]},
        )
        self.assertIn("2022-01-18T12:29:00Z–2022-01-18T13:14:00Z", prompt)
        self.assertIn("never searched", prompt.lower())

    def test_unreported_compromise_signal_reaches_the_prompt(self):
        from agent.runtime.graph.reflection import _build_review_prompt
        prompt = _build_review_prompt(
            findings_section="- None.", new_leads_section="- None.",
            evidence_digest="d", board_facts=[], current_task=None,
            signals={"evidence_queries": 3,
                     "unreported_compromise_artifacts": ["command: [decoded] /dev/tcp/192.168.130.77 [e1]"]},
        )
        self.assertIn("/dev/tcp/192.168.130.77", prompt)
        self.assertIn("MISSING from ## Findings", prompt)

    def test_review_system_prompt_is_methodology_first(self):
        from agent.runtime.graph.reflection import _REVIEW_SYSTEM
        self.assertIn("Use this general review method", _REVIEW_SYSTEM)
        self.assertIn("Decide `keep_working` only when the next action is specific", _REVIEW_SYSTEM)
        self.assertNotIn("Decide `keep_working` when ANY of these hold", _REVIEW_SYSTEM)


class TaskReviewStateTest(unittest.TestCase):
    def _review(self, decision="keep_working"):
        data = {"findings": [
            {"text": "evt-1 webshell", "status": "confirmed", "grounded": True, "novel": True},
            {"text": "scan 1.2.3.4", "status": "restated", "grounded": True, "novel": False, "reason": "board fact"},
        ]}
        return TaskReview(findings=_split_findings(data), decision=decision, feedback_text="next: query X")

    def test_findings_state_round_trips_for_board_gating(self):
        # The pivot node reconstructs FindingsVerification from this dict — shape must match.
        from agent.runtime.graph.findings_model import FindingsVerification
        state = self._review().findings_state()
        restored = FindingsVerification.from_state(state)
        self.assertEqual(restored.verified_count, 1)
        self.assertEqual(len(restored.rejected), 1)

    def test_feedback_includes_next_action_and_rejections(self):
        fb = self._review().to_feedback()
        self.assertIn("next: query X", fb)
        self.assertIn("REJECTED [restated]", fb)

    def test_feedback_without_rejections_reports_verified_count(self):
        data = {"findings": [{"text": "evt-1 webshell", "status": "confirmed",
                              "grounded": True, "novel": True}]}
        review = TaskReview(findings=_split_findings(data), decision="conclude", feedback_text="done")
        self.assertIn("1 verified finding", review.to_feedback())


if __name__ == "__main__":
    unittest.main(verbosity=2)
