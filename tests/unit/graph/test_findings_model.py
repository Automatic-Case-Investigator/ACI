"""Unit tests for model-based findings verification (findings_model.py).

Covers verdict parsing, fail-open behavior, classification → verified/rejected split,
and the agent-facing feedback rendering.
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

from agent.runtime.graph.findings_model import (  # noqa: E402
    FindingsVerification,
    FindingVerdict,
    _parse_model_verdicts,
    _to_verdict,
    verify_findings_model,
)


class _StubModel:
    """Minimal async chat model returning a canned response (or raising)."""

    def __init__(self, content="", exc=None):
        self._content = content
        self._exc = exc

    async def ainvoke(self, messages):
        if self._exc:
            raise self._exc

        class _R:
            content = self._content
        return _R()


def _run(coro):
    return asyncio.run(coro)


class ParseVerdictsTest(unittest.TestCase):
    def test_parses_array(self):
        raw = '[{"text":"a","status":"confirmed","grounded":true,"novel":true}]'
        self.assertEqual(len(_parse_model_verdicts(raw)), 1)

    def test_unparseable_returns_none(self):
        self.assertIsNone(_parse_model_verdicts("not json at all"))
        self.assertIsNone(_parse_model_verdicts(""))

    def test_empty_array_is_valid(self):
        self.assertEqual(_parse_model_verdicts("[]"), [])

    def test_array_embedded_in_prose(self):
        raw = 'Here you go:\n[{"text":"x","status":"restated"}]\nDone.'
        self.assertEqual(len(_parse_model_verdicts(raw)), 1)


class ToVerdictTest(unittest.TestCase):
    def test_confirmed_grounded_novel_is_verified(self):
        v = _to_verdict({"text": "evt-1 shell", "status": "confirmed", "grounded": True, "novel": True})
        self.assertTrue(v.is_verified)

    def test_confirmed_but_not_grounded_is_not_verified(self):
        v = _to_verdict({"text": "x", "status": "confirmed", "grounded": False, "novel": True})
        self.assertFalse(v.is_verified)

    def test_unknown_status_demoted_to_speculative(self):
        v = _to_verdict({"text": "x", "status": "totally-made-up", "grounded": True, "novel": True})
        self.assertEqual(v.status, "speculative")
        self.assertFalse(v.is_verified)


class VerifyFindingsModelTest(unittest.TestCase):
    def _kwargs(self, **over):
        base = dict(findings_section="- evt-1 confirmed reverse shell.",
                    evidence_digest="Event ids retrieved this task: evt-1",
                    board_facts=[], current_task={"title": "t"}, agent_name="investigation")
        base.update(over)
        return base

    def test_model_none_fails_open(self):
        self.assertIsNone(_run(verify_findings_model(None, **self._kwargs())))

    def test_empty_findings_returns_empty_verification_no_call(self):
        v = _run(verify_findings_model(_StubModel("[]"), **self._kwargs(findings_section="")))
        self.assertIsNotNone(v)
        self.assertEqual(v.verified_count, 0)

    def test_exception_fails_open(self):
        self.assertIsNone(_run(verify_findings_model(_StubModel(exc=RuntimeError("boom")), **self._kwargs())))

    def test_unparseable_fails_open(self):
        self.assertIsNone(_run(verify_findings_model(_StubModel("garbage"), **self._kwargs())))

    def test_classification_split(self):
        content = json.dumps([
            {"text": "evt-1 webshell call", "status": "confirmed", "grounded": True, "novel": True},
            {"text": "scan from 1.2.3.4", "status": "restated", "grounded": True, "novel": False, "reason": "already a board fact"},
            {"text": "phopkins escalated", "status": "ungrounded", "grounded": False, "novel": True, "reason": "event not retrieved"},
        ])
        v = _run(verify_findings_model(_StubModel(content), **self._kwargs()))
        self.assertEqual(v.verified_count, 1)
        self.assertEqual(len(v.rejected), 2)


class FeedbackAndStateTest(unittest.TestCase):
    def _verification(self):
        return FindingsVerification(
            verified=[FindingVerdict("evt-1 webshell", "confirmed", True, True, "")],
            rejected=[
                FindingVerdict("scan from 1.2.3.4", "restated", True, False, "already a board fact"),
                FindingVerdict("phopkins escalated", "ungrounded", False, True, "event not in retrieved evidence"),
            ],
        )

    def test_feedback_lists_rejections_and_count(self):
        fb = self._verification().to_feedback()
        self.assertIn("REJECTED [restated]", fb)
        self.assertIn("REJECTED [ungrounded]", fb)
        self.assertIn("1 verified finding", fb)

    def test_feedback_caps_items(self):
        rejected = [FindingVerdict(f"b{i}", "speculative", False, True, "no cite") for i in range(10)]
        fb = FindingsVerification(verified=[], rejected=rejected).to_feedback(max_items=3)
        self.assertIn("more rejected bullet", fb)
        self.assertEqual(fb.count("REJECTED"), 3)

    def test_state_round_trip(self):
        v = self._verification()
        restored = FindingsVerification.from_state(v.to_state())
        self.assertEqual(restored.verified_count, 1)
        self.assertEqual(len(restored.rejected), 2)
        self.assertEqual(restored.verified[0].text, "evt-1 webshell")

    def test_from_state_none(self):
        self.assertIsNone(FindingsVerification.from_state(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
