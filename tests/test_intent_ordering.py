from __future__ import annotations

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci_backend.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django

django.setup()

from langchain_core.messages import AIMessage

from agent.runtime.graph import use_tools


class FakeTool:
    name = "search"

    async def ainvoke(self, args):
        return '{"total": 1, "events": [{"id": "event-1"}]}'


class TestIntentOrdering(unittest.TestCase):
    def test_tool_call_proceeds_without_fallback_intent(self):
        events = []

        def capture(source, kind, summary, detail=None, **kwargs):
            events.append(kind)

        state = {
            "run_id": "missing-run",
            "case_id": "case-1",
            "agent_name": "investigation",
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{
                        "id": "call-1",
                        "name": "search",
                        "args": {"query": "host.name:test"},
                    }],
                )
            ],
            "tool_calls_made": 0,
            "current_intent": "",
            "intent_sequence": 0,
        }
        config = {"configurable": {"tools": [FakeTool()]}}

        with patch("agent.runtime.graph.emit", side_effect=capture):
            asyncio.run(use_tools(state, config))

        self.assertNotIn("intent", events)
        self.assertLess(events.index("call"), events.index("result"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
