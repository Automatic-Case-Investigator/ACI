"""
Offline test: aci-memory read store over the Django memory tables.

Creates rows via the Django ORM (committed to the real db.sqlite3), reads them
back through the aci_memory.store read-only connection, then deletes them. Uses
unique markers so it never collides with real data.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_memory_store.py -v
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import timedelta

# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django
django.setup()

from django.conf import settings
from django.utils import timezone

# Point the read store at the same DB Django writes to, then import it.
os.environ["ACI_MEMORY_DB_PATH"] = str(settings.DATABASES["default"]["NAME"])
from aci_memory import store

from agent.models import PatternEntry, BaselineSnapshot, FeedbackEntry

MARK = "ZZTEST_MEM_"


class TestMemoryStore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        now = timezone.now()
        cls.p_fp = PatternEntry.objects.create(
            name=MARK + "cron_backup_fp",
            verdict="fp",
            conditions={"rule_ids": ["2832"], "users": ["backup"]},
            required_evidence=["matching user"],
            invalidators=["external source IP"],
            confidence="high",
            enabled=True,
            expires_at=now + timedelta(days=30),
        )
        cls.p_tp = PatternEntry.objects.create(
            name=MARK + "revshell_tp",
            verdict="tp",
            conditions={"rule_ids": ["550"]},
            enabled=True,
        )
        cls.p_expired = PatternEntry.objects.create(
            name=MARK + "expired",
            verdict="fp",
            conditions={"rule_ids": ["2832"]},
            enabled=True,
            expires_at=now - timedelta(days=1),
        )
        cls.p_disabled = PatternEntry.objects.create(
            name=MARK + "disabled",
            verdict="fp",
            conditions={"rule_ids": ["2832"]},
            enabled=False,
        )
        cls.bl = BaselineSnapshot.objects.create(
            subject_type="user",
            subject_id=MARK + "alice",
            feature="active_hours",
            value={"hours": [8, 9, 10, 17, 18]},
            window_days=30,
            health="fresh",
        )
        cls.fb = FeedbackEntry.objects.create(
            run_id="run-xyz",
            case_id=MARK + "case1",
            agent_name="triage",
            original_verdict={"verdict": "tp"},
            analyst_verdict={"verdict": "fp"},
            note="benign maintenance",
            created_by="analyst1",
        )

    @classmethod
    def tearDownClass(cls):
        PatternEntry.objects.filter(name__startswith=MARK).delete()
        BaselineSnapshot.objects.filter(subject_id__startswith=MARK).delete()
        FeedbackEntry.objects.filter(case_id__startswith=MARK).delete()

    def _names(self, patterns):
        return {p["name"] for p in patterns if p["name"].startswith(MARK)}

    def test_search_patterns_excludes_expired_and_disabled(self):
        names = self._names(store.search_patterns())
        self.assertIn(MARK + "cron_backup_fp", names)
        self.assertIn(MARK + "revshell_tp", names)
        self.assertNotIn(MARK + "expired", names)
        self.assertNotIn(MARK + "disabled", names)

    def test_search_patterns_verdict_filter(self):
        names = self._names(store.search_patterns(verdict="fp"))
        self.assertIn(MARK + "cron_backup_fp", names)
        self.assertNotIn(MARK + "revshell_tp", names)

    def test_search_patterns_rule_id_overlap(self):
        names = self._names(store.search_patterns(rule_ids=["550"]))
        self.assertIn(MARK + "revshell_tp", names)
        self.assertNotIn(MARK + "cron_backup_fp", names)

    def test_search_patterns_parses_json_fields(self):
        pat = next(p for p in store.search_patterns(verdict="fp")
                   if p["name"] == MARK + "cron_backup_fp")
        self.assertEqual(pat["conditions"]["users"], ["backup"])
        self.assertEqual(pat["required_evidence"], ["matching user"])
        self.assertEqual(pat["invalidators"], ["external source IP"])
        self.assertTrue(pat["enabled"])

    def test_get_baselines(self):
        rows = store.get_baselines("user", MARK + "alice")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["feature"], "active_hours")
        self.assertEqual(rows[0]["value"]["hours"], [8, 9, 10, 17, 18])
        self.assertEqual(rows[0]["health"], "fresh")

    def test_get_baselines_unknown_subject_empty(self):
        self.assertEqual(store.get_baselines("user", MARK + "nobody"), [])

    def test_search_feedback(self):
        rows = store.search_feedback(MARK + "case1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["original_verdict"], {"verdict": "tp"})
        self.assertEqual(rows[0]["analyst_verdict"], {"verdict": "fp"})
        self.assertEqual(rows[0]["created_by"], "analyst1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
