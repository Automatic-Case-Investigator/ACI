"""
Offline test: the orchestrator's triage -> investigation auto-chain gate.

`_analyst_requested_investigation` decides whether the orchestrator may skip the
analyst checkpoint and launch a full investigation immediately after triage. It
must fire only on an *imperative request* to investigate, never on an *inquiry
about whether* to investigate (e.g. "tell me whether it warrants a full
investigation"), otherwise the human-in-the-loop checkpoint is silently bypassed.

No real Wazuh, TheHive, LLM, or AVFS needed.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_orchestrator_checkpoint.py
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

import agent.runtime.orchestrator as orchestrator
from agent.runtime.orchestrator import OrchestratorSession, _analyst_requested_investigation, run_orchestrator


class AnalystRequestedInvestigationTest(unittest.TestCase):
    def test_package_is_canonical_orchestrator_surface(self):
        self.assertEqual(Path(orchestrator.__file__).name, "__init__.py")
        self.assertIsNotNone(run_orchestrator)
        self.assertIsNotNone(OrchestratorSession)

    # Inquiries: the analyst is asking *whether* to investigate. The orchestrator
    # must answer, not auto-launch a costly investigation -> expect False.
    INQUIRIES = [
        "Triage case ~254202040 and tell me whether it warrants a full investigation.",
        "Should we investigate this case?",
        "Does this warrant a full investigation?",
        "Is this worth investigating?",
        "Triage this alert and decide if it warrants investigation.",
        "Do we need to investigate further?",
    ]

    # Explicit imperatives: the analyst is instructing investigation -> expect True.
    REQUESTS = [
        "Triage and then investigate the case.",
        "Run a full investigation on case ~254202040.",
        "Proceed to investigation.",
        "Triage then investigation, please.",
        "start investigation now",
        "Triage and investigation for ~254202040.",
    ]

    # Explicit opt-outs -> expect False.
    NEGATIVES = [
        "Triage only, do not investigate.",
        "Triage this case without investigation.",
        "Don't investigate, just triage.",
    ]

    def test_inquiries_do_not_auto_chain(self):
        for q in self.INQUIRIES:
            with self.subTest(question=q):
                self.assertFalse(_analyst_requested_investigation(q))

    def test_explicit_requests_auto_chain(self):
        for q in self.REQUESTS:
            with self.subTest(question=q):
                self.assertTrue(_analyst_requested_investigation(q))

    def test_explicit_negatives_block(self):
        for q in self.NEGATIVES:
            with self.subTest(question=q):
                self.assertFalse(_analyst_requested_investigation(q))

    def test_empty_is_false(self):
        self.assertFalse(_analyst_requested_investigation(""))
        self.assertFalse(_analyst_requested_investigation(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
