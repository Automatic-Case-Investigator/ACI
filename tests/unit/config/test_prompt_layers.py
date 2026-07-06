"""Offline test: prompt layers actually load and compose.

Regression guard for a path bug where `_PROMPTS_DIR` pointed at a non-existent
directory (after prompts.py moved deeper in the package tree), so every agent ran
with empty layer prompts and only the run-context footer. These tests fail loudly
if the prompt directory or any core layer goes missing again.

Run from project root with:
    python -m pytest tests/unit/config/test_prompt_layers.py
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.agents.registry import get_agent
from agent.runtime.config.prompts import _PROMPTS_DIR, _load_layer, compose_system_prompt
from agent.runtime.providers.base import format_provider_capability_contracts


class PromptLayerLoadingTests(unittest.TestCase):
    def test_prompts_dir_exists(self):
        self.assertTrue(_PROMPTS_DIR.exists(), f"prompts dir missing: {_PROMPTS_DIR}")

    def test_core_layers_load_nonempty(self):
        for layer in ("platform", "triage", "investigation", "siem_methodology", "playbook"):
            self.assertGreater(
                len(_load_layer(layer)), 0, f"layer '{layer}' loaded empty"
            )

    def test_playbook_composes_into_triage_and_investigation(self):
        for name in ("triage", "investigation"):
            prompt = compose_system_prompt(
                get_agent(name).prompt_layers,
                {
                    "case_id": "~1",
                    "run_id": "r",
                    "agent_name": name,
                    "default_vicinity_window_hours": 24,
                    "available_tools": [],
                },
            )
            self.assertIn("Incident Response Playbook", prompt)
            self.assertIn("## Command & Control", prompt)

    def test_shared_siem_methodology_composes_into_triage_and_investigation(self):
        for name in ("triage", "investigation"):
            prompt = compose_system_prompt(
                get_agent(name).prompt_layers,
                {
                    "case_id": "~1",
                    "run_id": "r",
                    "agent_name": name,
                    "default_vicinity_window_hours": 24,
                    "available_tools": [],
                },
            )
            self.assertIn("SIEM Investigation Methodology", prompt)
            self.assertIn("Treat time as an evidence axis", prompt)
            self.assertIn("Profiles and aggregates are maps", prompt)

    def test_seeder_does_not_include_playbook(self):
        prompt = compose_system_prompt(
            get_agent("seeder").prompt_layers,
            {"case_id": "~1", "run_id": "r", "agent_name": "seeder", "available_tools": []},
        )
        self.assertNotIn("Incident Response Playbook", prompt)
        self.assertNotIn("SIEM Investigation Methodology", prompt)

    def test_provider_capability_contracts_render_in_prompt(self):
        prompt = compose_system_prompt(
            get_agent("investigation").prompt_layers,
            {
                "case_id": "~1",
                "run_id": "r",
                "agent_name": "investigation",
                "available_tools": ["search", "get_case"],
                "provider_capability_contracts": format_provider_capability_contracts(
                    ["aci-thehive", "aci-wazuh", "aci-board"]
                ),
            },
        )
        self.assertIn("## Standardized MCP Capability Contract", prompt)
        self.assertIn("`search_events`", prompt)
        self.assertIn("`read_case`", prompt)
        self.assertIn("`aci-wazuh` (siem)", prompt)

    def test_runtime_context_and_mcp_guidance_render_as_separate_sections(self):
        prompt = compose_system_prompt(
            get_agent("investigation").prompt_layers,
            {
                "case_id": "~1",
                "run_id": "r",
                "agent_name": "investigation",
                "available_tools": ["search_events"],
                "mcp_prompt_guidance": "Provider-specific SIEM instruction.",
                "restart_context": "Prior run state.",
                "orchestrator_conversation": "Analyst-visible handoff.",
            },
        )
        self.assertIn("## Run Context", prompt)
        self.assertIn("## Prior Analyst Conversation (Orchestrator)", prompt)
        self.assertIn("## Prior Run Restart Context", prompt)
        self.assertIn("## Tool Usage Instructions (from MCP Servers)", prompt)
        self.assertLess(prompt.index("## Run Context"), prompt.index("## Tool Usage Instructions (from MCP Servers)"))

    def test_investigation_prompt_includes_anchor_first_reverse_shell_guidance(self):
        prompt = compose_system_prompt(
            get_agent("investigation").prompt_layers,
            {
                "case_id": "~1",
                "run_id": "r",
                "agent_name": "investigation",
                "default_vicinity_window_hours": 24,
                "available_tools": [],
            },
        )
        self.assertIn("pivot from that anchor", prompt)
        self.assertIn("process.parent.name", prompt)
        self.assertIn("data.audit.session", prompt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
