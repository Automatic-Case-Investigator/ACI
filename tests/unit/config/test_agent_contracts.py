from __future__ import annotations

import os
import sys
import tempfile
import unittest

# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from aci_taskqueue.store import claim_next, complete_task, create_task, init_db
from agent.agents.base import AgentDefinition
from agent.agents.registry import register
from agent.runtime.providers.contracts import (
    format_provider_capability_contracts,
    instructions_required_for_server,
    provider_contract_snapshot,
)
from agent.runtime.providers.registry import list_providers
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

    def test_siem_and_soar_providers_declare_required_standard_capabilities(self):
        providers = {
            provider.key: provider
            for provider in list_providers()
            if provider.kind in {"siem", "soar"}
        }
        self.assertIn("aci-wazuh", providers)
        self.assertIn("aci-thehive", providers)
        for provider in providers.values():
            self.assertEqual(
                provider.missing_required_capabilities(),
                (),
                f"{provider.key} missing capabilities",
            )

    def test_provider_contract_snapshot_has_stable_shape(self):
        provider = next(provider for provider in list_providers() if provider.key == "aci-wazuh")
        snapshot = provider_contract_snapshot(provider)
        self.assertEqual(snapshot["provider_key"], "aci-wazuh")
        self.assertEqual(snapshot["provider_kind"], "siem")
        self.assertIs(snapshot["instructions_required"], True)
        self.assertTrue(
            any(item["id"] == "search_events" for item in snapshot["standardized_capabilities"])
        )

    def test_contract_rendering_includes_utility_and_filesystem_bindings(self):
        text = format_provider_capability_contracts(
            ["aci-wazuh", "aci-thehive", "aci-taskqueue", "aci-board", "avfs"]
        )
        self.assertIn("Utility providers", text)
        self.assertIn("Filesystem providers", text)
        self.assertIn("queue_write_tasks", text)
        self.assertIn("board_write_findings", text)
        self.assertIn("workspace_read_write", text)

    def test_provider_instruction_requirement_uses_metadata(self):
        self.assertTrue(instructions_required_for_server("aci-wazuh"))
        self.assertFalse(instructions_required_for_server("avfs"))
        self.assertTrue(instructions_required_for_server("unknown-server"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
