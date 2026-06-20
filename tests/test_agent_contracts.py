from __future__ import annotations

import os
import sys
import tempfile
import unittest

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci_backend.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from aci_taskqueue.store import claim_next, complete_task, create_task, init_db
from agent.agents.base import AgentDefinition
from agent.agents.registry import register
from agent.workspace.citations import CitationValidationError, validate_citations
from agent.workspace.indexer import parent_index_dirs, upsert_memory_content


class TestAgentContracts(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_registry_rejects_duplicate_agent_names(self):
        agent = AgentDefinition(
            name="contract-test-agent",
            description="test",
            prompt_layers=[],
            tool_policy=[],
        )
        register(agent)
        with self.assertRaises(ValueError):
            register(agent)

    def test_taskqueue_claims_highest_priority_first(self):
        create_task("case-a", "run-a", "investigation", "low", priority=10)
        high = create_task("case-a", "run-a", "investigation", "high", priority=90)
        claimed = claim_next("case-a", "run-a", "investigation")
        self.assertEqual(claimed["id"], high["id"])
        self.assertEqual(claimed["status"], "claimed")

    def test_taskqueue_rejects_empty_completion_summary(self):
        task = create_task("case-empty", "run-empty", "investigation", "Silent task")
        with self.assertRaisesRegex(ValueError, "non-empty completion summary"):
            complete_task(task["id"], "   ")

    def test_memory_index_upserts_file_and_parent_directory(self):
        event_path = "/home/agent_1/cases/case-a/evidence/events/wazuh/event-1.json"
        leaf = upsert_memory_content(
            "",
            directory="/home/agent_1/cases/case-a/evidence/events/wazuh",
            changed_path=event_path,
            created_by="investigation",
        )
        self.assertIn("| event-1.json | JSON | Raw SIEM event evidence.", leaf)

        parent = upsert_memory_content(
            "",
            directory="/home/agent_1/cases/case-a/evidence/events",
            changed_path=event_path,
            created_by="investigation",
        )
        self.assertIn("| wazuh | Directory | Contains workspace artifacts.", parent)

    def test_parent_index_dirs_stop_at_case_root(self):
        dirs = parent_index_dirs(
            "/home/agent_1/cases/case-a/evidence/events/wazuh/event-1.json",
            stop_at="/home/agent_1/cases/case-a",
        )
        self.assertEqual(dirs[-1], "/home/agent_1/cases/case-a")
        self.assertIn("/home/agent_1/cases/case-a/evidence/events/wazuh", dirs)

    def test_citation_validation_rejects_missing_path(self):
        with self.assertRaises(CitationValidationError):
            validate_citations(
                [{"claim_id": "c1", "avfs_path": "/missing/event.json"}],
                exists=lambda path: False,
            )

    def test_citation_validation_accepts_existing_path(self):
        validated = validate_citations(
            [{"claim_id": "c1", "avfs_path": "/evidence/event.json", "native_id": "abc"}],
            exists=lambda path: path == "/evidence/event.json",
        )
        self.assertEqual(validated[0]["native_id"], "abc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
