"""
Offline test: graph-managed tools never leak into the model's tool list.

`claim_next` (claiming) and `complete_task` (completion) are owned by the graph.
If the model can call them it corrupts the queue (premature claim/complete). Run:
    python .claude/skills/run-aci-backend/tests/test_tool_visibility.py -v
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

from agent.runtime.graph import _model_tools_for_agent


class _Tool:
    def __init__(self, name):
        self.name = name


ALL_TOOLS = [_Tool(n) for n in (
    "create_task", "list_tasks", "claim_next", "complete_task",
    "search", "get_board", "add_fact", "write", "get_case",
)]

HIDDEN = {"claim_next", "complete_task"}


def _names(tools):
    return {t.name for t in tools}


class TestToolVisibility(unittest.TestCase):

    def test_investigation_normal_task_hides_graph_tools(self):
        current = {"title": "Investigate SSH brute-force"}
        names = _names(_model_tools_for_agent("investigation", ALL_TOOLS, current))
        self.assertFalse(names & HIDDEN, f"leaked: {names & HIDDEN}")
        self.assertIn("search", names)  # real work tools still present

    def test_investigation_seed_task_has_full_tools(self):
        # Seed task is no longer restricted — model gets all tools except graph-managed ones.
        current = {"title": "Populate investigation queue from triage handoff"}
        names = _names(_model_tools_for_agent("investigation", ALL_TOOLS, current))
        self.assertFalse(names & HIDDEN)
        self.assertIn("create_task", names)
        self.assertIn("search", names)

    def test_triage_hides_create_task_and_graph_tools(self):
        names = _names(_model_tools_for_agent("triage", ALL_TOOLS, None))
        self.assertNotIn("create_task", names)
        self.assertFalse(names & HIDDEN)

    def test_no_current_task_still_hides_graph_tools(self):
        names = _names(_model_tools_for_agent("investigation", ALL_TOOLS, None))
        self.assertFalse(names & HIDDEN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
