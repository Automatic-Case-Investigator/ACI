"""
Offline test: deterministic FP/TP pattern matcher.

Pure-logic tests (evaluate) need no DB. The loader test (match_patterns) creates
and deletes PatternEntry rows via the ORM. Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_pattern_matcher.py -v
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import timedelta

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django
django.setup()

from django.utils import timezone

from agent.runtime.analysis.pattern_matcher import evaluate, match_patterns, PatternMatch
from agent.models import PatternEntry

# A cron-maintenance FP pattern, as it would be stored.
CRON_FP = {
    "name": "Known cron maintenance by backup user",
    "verdict": "fp",
    "confidence": "high",
    "conditions": {
        "rule_ids": ["2832"],
        "users": ["backup"],
        "path_prefixes": ["/var/spool/cron"],
        "time_window": "maintenance_hours",
    },
    "required_evidence": ["matching user", "approved host"],
    "invalidators": ["external source IP", "new user", "privilege escalation nearby"],
}

FULL_META = {
    "rule_ids": ["2832"],
    "users": ["backup"],
    "paths": ["/var/spool/cron/crontabs/backup"],
    "time_windows": ["maintenance_hours"],
    "signals": [],
}


class TestEvaluate(unittest.TestCase):

    def test_full_match(self):
        m = evaluate(CRON_FP, FULL_META)
        self.assertTrue(m.matched)
        self.assertEqual(m.verdict, "fp")
        self.assertEqual(
            set(m.matched_conditions),
            {"rule_ids", "users", "path_prefixes", "time_window"},
        )
        self.assertEqual(m.invalidators_triggered, [])

    def test_one_unmet_condition_blocks_match(self):
        meta = dict(FULL_META, users=["root"])  # wrong user
        m = evaluate(CRON_FP, meta)
        self.assertFalse(m.matched)
        self.assertIn("users", m.unmet_conditions)

    def test_missing_field_counts_as_unmet(self):
        meta = {"rule_ids": ["2832"], "users": ["backup"], "paths": ["/var/spool/cron/x"]}
        # no time_windows key at all
        m = evaluate(CRON_FP, meta)
        self.assertFalse(m.matched)
        self.assertIn("time_window", m.unmet_conditions)

    def test_invalidator_blocks_match(self):
        meta = dict(FULL_META, signals=["external source ip"])
        m = evaluate(CRON_FP, meta)
        self.assertFalse(m.matched)
        self.assertEqual(m.invalidators_triggered, ["external source IP"])
        # conditions still recorded as matched even though invalidated
        self.assertIn("rule_ids", m.matched_conditions)

    def test_path_prefix_matching(self):
        meta = dict(FULL_META, paths=["/etc/passwd"])  # not under cron prefix
        m = evaluate(CRON_FP, meta)
        self.assertFalse(m.matched)
        self.assertIn("path_prefixes", m.unmet_conditions)

    def test_empty_conditions_never_match(self):
        pat = {"name": "empty", "verdict": "fp", "conditions": {}}
        m = evaluate(pat, FULL_META)
        self.assertFalse(m.matched)
        self.assertEqual(m.matched_conditions, [])

    def test_rule_id_int_vs_str_normalized(self):
        pat = {"name": "n", "verdict": "tp", "conditions": {"rule_ids": [550]}}
        meta = {"rule_ids": ["550"]}
        self.assertTrue(evaluate(pat, meta).matched)

    def test_to_contract_strings(self):
        matched = evaluate(CRON_FP, FULL_META)
        self.assertIn("conditions met", matched.to_contract())
        invalid = evaluate(CRON_FP, dict(FULL_META, signals=["new user"]))
        self.assertIn("NOT applied", invalid.to_contract())


class TestMatchPatternsLoader(unittest.TestCase):
    MARK = "ZZTEST_PM_"

    @classmethod
    def setUpClass(cls):
        now = timezone.now()
        cls.active = PatternEntry.objects.create(
            name=cls.MARK + "active", verdict="fp", confidence="high",
            conditions={"rule_ids": ["2832"]}, enabled=True,
            expires_at=now + timedelta(days=10),
        )
        cls.expired = PatternEntry.objects.create(
            name=cls.MARK + "expired", verdict="fp",
            conditions={"rule_ids": ["2832"]}, enabled=True,
            expires_at=now - timedelta(days=1),
        )
        cls.disabled = PatternEntry.objects.create(
            name=cls.MARK + "disabled", verdict="fp",
            conditions={"rule_ids": ["2832"]}, enabled=False,
        )

    @classmethod
    def tearDownClass(cls):
        PatternEntry.objects.filter(name__startswith=cls.MARK).delete()

    def test_loader_excludes_expired_and_disabled(self):
        results = match_patterns({"rule_ids": ["2832"]})
        names = {r.name for r in results if r.name.startswith(self.MARK)}
        self.assertEqual(names, {self.MARK + "active"})

    def test_loader_returns_pattern_match_objects(self):
        results = match_patterns({"rule_ids": ["2832"]})
        self.assertTrue(all(isinstance(r, PatternMatch) for r in results))

    def test_no_applicable_patterns_returns_empty(self):
        results = match_patterns({"rule_ids": ["999999"]})
        names = {r.name for r in results if r.name.startswith(self.MARK)}
        self.assertEqual(names, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
