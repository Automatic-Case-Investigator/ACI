"""Regression tests for the `think` continuation rebuild.

Root cause of the checklist-replay loop (sessions 5429c6f2, 7a44aba5): on every
post-interpretation turn `think` rebuilt its prompt from the ledger, but it also
re-appended the ORIGINAL seed task description verbatim. That description is a
numbered orientation checklist ("1. Load the case. 2. Load alerts. ..."), so small
models replayed orientation each cycle and never reached the SIEM step — six concrete
numbered imperatives out-pull one advisory interpretation note.

The fix: on continuation (ledger has `next_step_instruction`), inject ONLY the task
objective, never the numbered checklist. A fresh claim still shows the full description.
"""
import asyncio
import unittest

from langchain_core.messages import AIMessage, HumanMessage

from agent.runtime.graph import nodes_loop


def _run(coro):
    return asyncio.run(coro)


_CHECKLIST_DESCRIPTION = (
    "Analyst question: Triage and investigate case ~449101824. Follow the mandated "
    "startup sequence, assess the case/alerts, identify likely attack category.\n\n"
    "Complete a bounded triage handoff and write a report.\n"
    "1. Load the case record.\n"
    "2. Load the linked alert summary.\n"
    "3. Check known FP/TP patterns for this case's detection rule IDs.\n"
    "4. Check baselines for common behaviors.\n"
    "5. Check analyst corrections for these rule IDs.\n"
    "6. Load other alerts / events; derive an absolute time window and query the SIEM."
)


class _StubBound:
    def __init__(self, tools):
        self.tools = tools


class _StubModel:
    def bind_tools(self, tools):
        return _StubBound(tools)


def _state(*, ledger, messages=None):
    return {
        "agent_name": "triage",
        "messages": messages or [],
        "current_task": {
            "title": "Triage case ~449101824",
            "description": _CHECKLIST_DESCRIPTION,
        },
        "task_ledger": ledger,
        "tool_calls_made": 5,
        "task_call_floor": 0,
        "ctx_tokens": 0,
        "steps": 3,
        "default_vicinity_window_hours": 24,
        "case_id": "~449101824",
        "run_id": "run-1",
    }


class ThinkContinuationTest(unittest.TestCase):
    def setUp(self):
        self._captured = []

        async def _capture(bound, messages, agent_name):
            self._captured.append(messages)
            return AIMessage(content="ok")

        self._orig = nodes_loop._invoke_bound_model
        nodes_loop._invoke_bound_model = _capture

    def tearDown(self):
        nodes_loop._invoke_bound_model = self._orig

    def _human_text(self):
        msgs = self._captured[-1]
        human = [m for m in msgs if isinstance(m, HumanMessage)]
        return human[-1].content

    def _config(self):
        return {"configurable": {"model": _StubModel(), "tools": [], "system_prompt": "SYS"}}

    def test_continuation_strips_numbered_checklist(self):
        # Post-interpretation: ledger carries an instruction. The rebuilt prompt must
        # carry the objective and the note but MUST NOT re-inject the numbered checklist.
        ledger = {
            "objective": "Triage and investigate case ~449101824",
            "next_step_instruction": "Orientation is complete — issue your first SIEM query now.",
            "evidence_state": "orientation",
            "evidence_summary": "case + 1 alert loaded; rule 31151 on 172.17.130.196",
        }
        _run(nodes_loop.think(_state(ledger=ledger), self._config()))
        text = self._human_text()
        self.assertIn("Orientation is COMPLETE", text)
        # The de-amnesia block names the spent tools and renders the last result.
        self.assertIn("Do NOT", text)
        self.assertIn("case + 1 alert loaded", text)
        self.assertIn("issue your first SIEM query", text)
        self.assertIn("Triage and investigate case ~449101824", text)
        # The next step is framed as required, not advisory.
        self.assertIn("REQUIRED next step", text)
        self.assertNotIn("advisory, not binding", text)
        # The numbered orientation steps must be gone.
        self.assertNotIn("1. Load the case record.", text)
        self.assertNotIn("2. Load the linked alert summary.", text)
        self.assertNotIn("3. Check known FP/TP patterns", text)

    def test_fresh_claim_keeps_full_checklist(self):
        # A fresh claim (no next_step_instruction yet) still shows the full description,
        # so the turn-1 startup sequence is intact.
        ledger = {
            "objective": "Triage and investigate case ~449101824",
            "next_step_instruction": "",
        }
        _run(nodes_loop.think(_state(ledger=ledger), self._config()))
        text = self._human_text()
        self.assertIn("1. Load the case record.", text)
        self.assertIn("6. Load other alerts", text)

    def test_continuation_without_objective_falls_back_to_title(self):
        ledger = {
            "objective": "",
            "next_step_instruction": "Issue your first SIEM query now.",
        }
        _run(nodes_loop.think(_state(ledger=ledger), self._config()))
        text = self._human_text()
        self.assertIn("Triage case ~449101824", text)
        self.assertNotIn("1. Load the case record.", text)


if __name__ == "__main__":
    unittest.main()
