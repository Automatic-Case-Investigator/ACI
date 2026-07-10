from __future__ import annotations

import asyncio
import json
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

from langchain_core.messages import AIMessage

from agent.runtime.graph.nodes_loop import use_tools


class _Tool:
    name = "profile_field"

    def __init__(self):
        self.calls = 0

    async def ainvoke(self, args: dict):
        self.calls += 1
        return json.dumps({"field": args["field"], "buckets": [{"key": "web", "doc_count": 3}]})


def _state(cache=None):
    return {
        "agent_name": "triage",
        "case_id": "~1",
        "source_entity_type": "case",
        "run_id": "not-a-real-run",
        "messages": [AIMessage(content="", tool_calls=[{
            "name": "profile_field",
            "id": "call-1",
            "args": {"field": "rule.groups", "time_range": {
                "from": "2022-01-18T00:00:00Z",
                "to": "2022-01-18T01:00:00Z",
            }},
        }])],
        "tool_calls_made": 0,
        "last_observation": None,
        "current_task": {"title": "cache test"},
        "tool_result_cache": cache or {},
    }


class ToolResultCacheTests(unittest.TestCase):
    def test_exact_cache_hit_avoids_second_tool_invocation(self):
        tool = _Tool()
        config = {"configurable": {"tools": [tool]}}

        first = asyncio.run(use_tools(_state(), config))
        second = asyncio.run(use_tools(_state(first["tool_result_cache"]), config))

        self.assertEqual(tool.calls, 1)
        self.assertEqual(first["tool_calls_made"], 1)
        self.assertEqual(second["tool_calls_made"], 0)


if __name__ == "__main__":
    unittest.main()
