"""
Offline test: TheHive alert metadata extraction (pure parsing, no DB/LLM).

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_alert_metadata.py -v
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)

from agent.runtime.analysis.alert_metadata import extract_alert_metadata


class TestExtractAlertMetadata(unittest.TestCase):

    def test_rule_id_from_kv_tag(self):
        meta = extract_alert_metadata({"tags": ["rule:2832"]}, None)
        self.assertEqual(meta["rule_ids"], ["2832"])

    def test_rule_id_variants(self):
        meta = extract_alert_metadata(
            {"tags": ["rule_id=5710", "ruleid:1002", "sigid: 99001"]}, None
        )
        self.assertEqual(set(meta["rule_ids"]), {"5710", "1002", "99001"})

    def test_bare_numeric_tag_is_rule_id(self):
        meta = extract_alert_metadata({"tags": ["2832", "12"]}, None)
        # "12" is too short (< 3 digits) and is ignored; "2832" is a rule id.
        self.assertEqual(meta["rule_ids"], ["2832"])

    def test_user_and_path_tags(self):
        meta = extract_alert_metadata(
            {"tags": ["user:backup", "path:/var/spool/cron"]}, None
        )
        self.assertEqual(meta["users"], ["backup"])
        self.assertEqual(meta["paths"], ["/var/spool/cron"])

    def test_merges_case_and_alert_groups(self):
        case = {"tags": ["rule:2832"], "title": "Cron modification"}
        alerts = {
            "groups": [{"title": "Crontab changed", "tags": ["user:backup"]}],
            "alerts": [{"title": "FIM crontab", "tags": ["5710"]}],
        }
        meta = extract_alert_metadata(case, alerts)
        self.assertEqual(set(meta["rule_ids"]), {"2832", "5710"})
        self.assertEqual(meta["users"], ["backup"])
        self.assertIn("Cron modification", meta["titles"])
        self.assertIn("Crontab changed", meta["titles"])

    def test_none_inputs_yield_empty(self):
        meta = extract_alert_metadata(None, None)
        self.assertEqual(meta["rule_ids"], [])
        self.assertEqual(meta["users"], [])
        self.assertEqual(meta["titles"], [])
        # Contract fields always present
        for key in ("rule_ids", "users", "paths", "tags", "titles", "time_windows", "signals"):
            self.assertIn(key, meta)

    def test_non_tag_strings_ignored(self):
        meta = extract_alert_metadata({"tags": ["mitre:T1053", "suspicious"]}, None)
        # neither is a recognized rule/user/path kv, "mitre" key not in any set
        self.assertEqual(meta["rule_ids"], [])
        self.assertEqual(meta["users"], [])
        self.assertIn("mitre:T1053", meta["tags"])

    def test_dedup_across_sources(self):
        case = {"tags": ["rule:2832"]}
        alerts = {"groups": [{"tags": ["2832"]}]}
        meta = extract_alert_metadata(case, alerts)
        self.assertEqual(meta["rule_ids"], ["2832"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
