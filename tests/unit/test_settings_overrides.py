"""
Offline test: analyst-editable settings overrides + MCP categorization rules.

Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_settings_overrides.py -v
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django
django.setup()

from django.test import RequestFactory, TestCase as DjangoTestCase
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.db import SessionStore

from agent.agents.registry import get_agent
from agent.dashboard import settings_views as sv
from agent.models import (
    AgentConfig, WorkflowConfig, EscalationRule, MCPServerConfig, ProviderConfig,
)
from agent.runtime.config import is_enabled, provider_category, resolve_settings, INTERNAL_PROVIDERS, DEFAULT_PROVIDERS
from agent.runtime.config.overrides import (
    resolve_agent_definition, resolve_workflow, resolve_escalation_map,
)
from agent.runtime.config.prompts import compose_system_prompt


def _post(data):
    r = RequestFactory().post("/x", data)
    r.session = SessionStore()
    setattr(r, "_messages", FallbackStorage(r))
    return r


class TestCategorization(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(provider_category("aci-memory"), "internal")
        self.assertEqual(provider_category("aci-wazuh"), "default")
        self.assertEqual(provider_category("my-thing"), "custom")

    def test_internal_always_enabled(self):
        for key in INTERNAL_PROVIDERS:
            self.assertTrue(is_enabled(key))

    def test_internal_sets_are_disjoint(self):
        self.assertFalse(INTERNAL_PROVIDERS & DEFAULT_PROVIDERS)


class TestAgentOverride(DjangoTestCase):
    def setUp(self):
        # Remove any pre-existing override so tests start from baseline state.
        # Runs inside the per-test savepoint — rolled back automatically after
        # each test, so real production data is never permanently modified.
        AgentConfig.objects.filter(agent_name="triage").delete()
        AgentConfig.objects.filter(agent_name="investigation").delete()

    def test_budget_and_tools_override(self):
        sv.settings_agent_save(_post({
            "agent_name": "triage", "max_steps": "5", "max_tool_calls": "6",
            "tool_policy": ["aci-thehive", "aci-memory"], "stream_intent": "1",
            "vicinity_window_hours": "12",
        }))
        a = resolve_agent_definition(get_agent("triage"))
        self.assertEqual(a.budget.max_steps, 5)
        self.assertEqual(a.budget.max_tool_calls, 6)
        self.assertEqual(a.tool_policy, ["aci-thehive", "aci-memory"])
        self.assertEqual(a.default_vicinity_window_hours, 12)

    def test_blank_budget_keeps_default(self):
        base = get_agent("triage")
        sv.settings_agent_save(_post({"agent_name": "triage", "max_steps": "", "max_tool_calls": ""}))
        a = resolve_agent_definition(get_agent("triage"))
        self.assertEqual(a.budget.max_steps, base.budget.max_steps)
        self.assertEqual(a.default_vicinity_window_hours, 24)

    def test_blank_vicinity_window_clears_override(self):
        AgentConfig.objects.update_or_create(
            agent_name="triage",
            defaults={"vicinity_window_hours": 18},
        )
        sv.settings_agent_save(_post({"agent_name": "triage", "vicinity_window_hours": ""}))
        row = AgentConfig.objects.get(agent_name="triage")
        self.assertIsNone(row.vicinity_window_hours)
        self.assertEqual(resolve_agent_definition(get_agent("triage")).default_vicinity_window_hours, 24)

    def test_agents_have_independent_vicinity_windows(self):
        AgentConfig.objects.update_or_create(
            agent_name="triage",
            defaults={"vicinity_window_hours": 8},
        )
        AgentConfig.objects.update_or_create(
            agent_name="investigation",
            defaults={"vicinity_window_hours": 36},
        )
        self.assertEqual(resolve_agent_definition(get_agent("triage")).default_vicinity_window_hours, 8)
        self.assertEqual(resolve_agent_definition(get_agent("investigation")).default_vicinity_window_hours, 36)

    def test_prompt_includes_resolved_vicinity_window(self):
        prompt = compose_system_prompt(
            get_agent("triage").prompt_layers,
            {
                "case_id": "~1",
                "run_id": "run-1",
                "agent_name": "triage",
                "budget": {"max_steps": 5, "max_tool_calls": 6},
                "default_vicinity_window_hours": 18,
                "available_tools": [],
            },
        )
        self.assertIn("Default vicinity window", prompt)
        self.assertIn("±18h", prompt)


class TestWorkflowOverride(DjangoTestCase):
    def setUp(self):
        # Clean state: remove any pre-existing rows that would interfere with
        # the tests below. Runs inside the per-test savepoint — automatically
        # rolled back so real production rows survive.
        WorkflowConfig.objects.filter(event_type="new_case").delete()
        EscalationRule.objects.all().delete()

    def test_workflow_override(self):
        sv.settings_workflow_save(_post({"event_type": "new_case", "enabled": "1", "dedupe_window": "90"}))
        self.assertEqual(
            resolve_workflow("new_case", default_enabled=True, default_window=600), (True, 90)
        )

    def test_workflow_disable(self):
        sv.settings_workflow_save(_post({"event_type": "new_case", "dedupe_window": "60"}))
        enabled, _ = resolve_workflow("new_case", default_enabled=True, default_window=600)
        self.assertFalse(enabled)

    def test_escalation_override(self):
        sv.settings_escalation_save(_post({
            "action_tp": "hold", "action_fp": "auto_close",
            "action_inconclusive": "hold", "action_needs_investigation": "hold",
        }))
        self.assertEqual(resolve_escalation_map()["tp"], "hold")

    def test_escalation_default_when_no_rows(self):
        self.assertEqual(resolve_escalation_map()["tp"], "auto_escalate")


class TestMCPProtections(DjangoTestCase):
    def setUp(self):
        MCPServerConfig.objects.filter(id="zztest-siem").delete()
        ProviderConfig.objects.filter(key="aci-memory").delete()

    def test_internal_toggle_rejected(self):
        sv.settings_provider_toggle(_post({"key": "aci-memory", "enabled": "0"}))
        self.assertTrue(is_enabled("aci-memory"))
        self.assertFalse(ProviderConfig.objects.filter(key="aci-memory").exists())

    def test_custom_add_and_delete(self):
        sv.settings_mcp_save(_post({
            "id": "zztest-siem", "name": "Test", "transport": "stdio",
            "command_or_url": "python -m x", "enabled": "1", "allowed_agents": "triage",
        }))
        self.assertTrue(MCPServerConfig.objects.filter(id="zztest-siem").exists())
        sv.settings_mcp_delete(_post({"id": "zztest-siem"}))
        self.assertFalse(MCPServerConfig.objects.filter(id="zztest-siem").exists())

    def test_reserved_key_rejected(self):
        sv.settings_mcp_save(_post({
            "id": "aci-wazuh", "name": "x", "transport": "stdio", "command_or_url": "y",
        }))
        self.assertFalse(MCPServerConfig.objects.filter(id="aci-wazuh").exists())

    def test_builtin_delete_blocked(self):
        # Even if a stray row existed, delete must refuse a built-in key.
        sv.settings_mcp_delete(_post({"id": "aci-thehive"}))
        # No exception; built-ins simply aren't MCPServerConfig rows.
        self.assertFalse(MCPServerConfig.objects.filter(id="aci-thehive").exists())


class TestTheHiveDBSettings(DjangoTestCase):
    """resolve_settings must read ProviderConfig.settings for aci-thehive.

    TheHive/Wazuh connection settings come from the DB only — no env fallback.
    """

    def setUp(self):
        ProviderConfig.objects.filter(key="aci-thehive").delete()

    def test_db_row_settings_used(self):
        ProviderConfig.objects.update_or_create(
            key="aci-thehive",
            defaults={
                "kind": ProviderConfig.KIND_SOAR,
                "settings": {
                    "host": "http://test-hive",
                    "port": "9001",
                    "api_key": "testkey123",
                    "verify_tls": "false",
                },
            },
        )
        from agent.runtime.providers.registry import get_provider
        provider = get_provider("aci-thehive")
        resolved = resolve_settings("aci-thehive", provider.setting_defaults() if provider else {})
        self.assertEqual(resolved["host"], "http://test-hive")
        self.assertEqual(resolved["port"], "9001")
        self.assertEqual(resolved["api_key"], "testkey123")
        self.assertEqual(resolved["verify_tls"], "false")

    def test_no_db_row_yields_empty_defaults(self):
        from agent.runtime.providers.registry import get_provider
        provider = get_provider("aci-thehive")
        resolved = resolve_settings("aci-thehive", provider.setting_defaults() if provider else {})
        self.assertEqual(resolved["host"], "")
        self.assertEqual(resolved["api_key"], "")

    def test_partial_db_row_leaves_missing_fields_as_empty_defaults(self):
        ProviderConfig.objects.update_or_create(
            key="aci-thehive",
            defaults={
                "kind": ProviderConfig.KIND_SOAR,
                "settings": {"api_key": "dbkey"},
            },
        )
        from agent.runtime.providers.registry import get_provider
        provider = get_provider("aci-thehive")
        resolved = resolve_settings("aci-thehive", provider.setting_defaults() if provider else {})
        self.assertEqual(resolved["host"], "")       # empty default, not from env
        self.assertEqual(resolved["api_key"], "dbkey")  # DB wins


if __name__ == "__main__":
    unittest.main(verbosity=2)
