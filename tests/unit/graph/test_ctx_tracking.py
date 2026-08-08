"""Context-wheel token tracking.

Every model call that grows an agent's context must publish its prompt-token
count to the logbus, not merely thread it through graph state — a call site that
only extracts leaves the dashboard's context wheel frozen on the previous call's
number. `_track_input_tokens` is the single helper that does both.
"""

from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django

django.setup()

from agent.runtime.graph.toolio import _COMPACT_THRESHOLD, _track_input_tokens
from agent.runtime.infra import logbus


class _Resp:
    """Minimal stand-in for a LangChain AIMessage carrying usage metadata."""

    def __init__(self, usage=None):
        self.usage_metadata = usage


class TrackInputTokensTests(unittest.TestCase):
    def setUp(self):
        self.session_token = logbus.bind_session("sess-ctx")
        self.run_token = logbus.bind_run("run-ctx")
        self.addCleanup(logbus.clear_session_context_usage, "sess-ctx")

    def tearDown(self):
        logbus.reset_run(self.run_token)
        logbus.reset_session(self.session_token)

    def test_publishes_usage_to_the_logbus(self):
        returned = _track_input_tokens(_Resp({"input_tokens": 4321}), "inv")
        self.assertEqual(returned, 4321)

        recorded = logbus.get_context_usage("run-ctx")
        self.assertIsNotNone(recorded)
        self.assertEqual(recorded["tokens"], 4321)
        self.assertEqual(recorded["source"], "inv")

    def test_missing_usage_returns_fallback_and_publishes_nothing(self):
        _track_input_tokens(_Resp({"input_tokens": 1000}), "inv")
        # A provider that omits usage must not clobber the last good reading.
        returned = _track_input_tokens(_Resp(None), "inv", fallback=1000)
        self.assertEqual(returned, 1000)
        self.assertEqual(logbus.get_context_usage("run-ctx")["tokens"], 1000)

    def test_latest_reading_wins_over_the_orchestrator_entry(self):
        # The orchestrator's reading is keyed by session id; a specialist that
        # reported more recently is the one the wheel should show.
        orch_token = logbus.bind_run("sess-ctx")
        _track_input_tokens(_Resp({"input_tokens": 500}), "orch")
        logbus.reset_run(orch_token)

        _track_input_tokens(_Resp({"input_tokens": 90000}), "inv")

        latest = logbus.get_latest_context_usage("sess-ctx")
        self.assertEqual(latest["tokens"], 90000)
        self.assertEqual(latest["source"], "inv")


class ContextStoreBoundsTests(unittest.TestCase):
    def test_store_is_capped(self):
        session_token = logbus.bind_session("sess-cap")
        self.addCleanup(logbus.clear_session_context_usage, "sess-cap")
        try:
            for i in range(logbus._MAX_CTX_ENTRIES + 25):
                run_token = logbus.bind_run(f"run-cap-{i}")
                logbus.update_context_usage(i + 1, "inv")
                logbus.reset_run(run_token)
        finally:
            logbus.reset_session(session_token)

        self.assertLessEqual(len(logbus._ctx_by_run), logbus._MAX_CTX_ENTRIES)
        # Eviction is oldest-first, so the newest run must have survived.
        newest = f"run-cap-{logbus._MAX_CTX_ENTRIES + 24}"
        self.assertIsNotNone(logbus.get_context_usage(newest))

    def test_clear_session_removes_every_reading(self):
        session_token = logbus.bind_session("sess-clear")
        run_token = logbus.bind_run("run-clear")
        logbus.update_context_usage(123, "tri")
        logbus.reset_run(run_token)
        logbus.reset_session(session_token)

        logbus.clear_session_context_usage("sess-clear")
        self.assertIsNone(logbus.get_context_usage("run-clear"))
        self.assertIsNone(logbus.get_latest_context_usage("sess-clear"))


class CompactThresholdTests(unittest.TestCase):
    def test_threshold_is_a_usable_fraction(self):
        # get_ctx ships this to the browser as the wheel's warning band; a value
        # outside (0, 1) would silently mis-color the ring.
        self.assertGreater(_COMPACT_THRESHOLD, 0)
        self.assertLess(_COMPACT_THRESHOLD, 1)


if __name__ == "__main__":
    unittest.main()
