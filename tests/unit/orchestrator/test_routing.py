from __future__ import annotations

import os
import sys
import tempfile
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from agent.runtime.orchestrator.driver import _triage_routing_target


class OrchestratorRoutingTests(unittest.TestCase):
    def test_explicit_alert_routing_beats_generic_tilde_entity(self):
        entity_id, entity_type = _triage_routing_target(
            "Triage and investigate alert ~392007704",
            None,
        )
        self.assertEqual(entity_id, "~392007704")
        self.assertEqual(entity_type, "alert")

    def test_case_word_routes_as_case(self):
        entity_id, entity_type = _triage_routing_target(
            "Triage case ~392007704",
            None,
        )
        self.assertEqual(entity_id, "~392007704")
        self.assertEqual(entity_type, "case")


if __name__ == "__main__":
    unittest.main()
