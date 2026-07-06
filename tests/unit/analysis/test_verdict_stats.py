"""
Offline test: verdict trend/breakdown aggregation for the dashboard.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_verdict_stats.py -v
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
from agent.stats import verdict_trend, verdict_breakdown

MARK = "ZZTEST_STATS_"


def _mk(verdict, agent="triage", days_ago=0, confidence="high"):
    run = AgentRun.objects.create(
        case_id=MARK + "c",
        agent_name=agent,
        question="q",
        status=AgentRun.STATUS_COMPLETED,
        verdict={"verdict": verdict, "confidence": confidence} if verdict else None,
    )
    # created_at is auto_now_add; rewrite it via queryset update to backdate.
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    AgentRun.objects.filter(id=run.id).update(created_at=when)
    return run


class TestVerdictStats(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _mk("tp", agent="triage", days_ago=0)
        _mk("fp", agent="triage", days_ago=0)
        _mk("fp", agent="investigation", days_ago=1)
        _mk("inconclusive", agent="investigation", days_ago=1, confidence="low")
        _mk("tp", agent="investigation", days_ago=20)  # outside 7d window

    @classmethod
    def tearDownClass(cls):
        AgentRun.objects.filter(case_id=MARK + "c").delete()

    def _our_trend(self, days):
        # Filter to only our marked runs' contribution is hard (trend is global);
        # assert on totals being at least our injected counts within the window.
        return verdict_trend(days)

    def test_trend_has_per_day_rows(self):
        trend = verdict_trend(7)
        self.assertTrue(all("date" in r and "total" in r for r in trend))
        # Each row sums its verdict columns into total.
        for r in trend:
            self.assertEqual(
                r["total"], r["tp"] + r["fp"] + r["inconclusive"] + r["needs_investigation"]
            )

    def test_window_excludes_old_runs(self):
        wide = verdict_breakdown(30, group_by="agent_name")
        narrow = verdict_breakdown(7, group_by="agent_name")
        inv_wide = next((r for r in wide if r["agent_name"] == "investigation"), None)
        inv_narrow = next((r for r in narrow if r["agent_name"] == "investigation"), None)
        # The 20-day-old tp counts in the 30d window but not the 7d window.
        self.assertIsNotNone(inv_wide)
        self.assertGreaterEqual(inv_wide["tp"], 1)
        # narrow investigation tp should be lower than wide (old tp dropped)
        narrow_tp = inv_narrow["tp"] if inv_narrow else 0
        self.assertLess(narrow_tp, inv_wide["tp"])

    def test_breakdown_by_confidence(self):
        rows = verdict_breakdown(7, group_by="confidence")
        keys = {r["confidence"] for r in rows}
        self.assertIn("high", keys)
        self.assertIn("low", keys)

    def test_breakdown_invalid_group_by_falls_back(self):
        rows = verdict_breakdown(7, group_by="not_a_field")
        # falls back to agent_name grouping
        self.assertTrue(all("agent_name" in r for r in rows))

    def test_breakdown_totals_consistent(self):
        rows = verdict_breakdown(7, group_by="agent_name")
        for r in rows:
            self.assertEqual(
                r["total"], r["tp"] + r["fp"] + r["inconclusive"] + r["needs_investigation"]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
