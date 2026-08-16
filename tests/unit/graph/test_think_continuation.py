"""Regression tests for `think`'s anchor-once / steer-transiently prompt shape.

Root cause of the checklist-replay loop (sessions 5429c6f2, 7a44aba5): on every
post-interpretation turn `think` rebuilt its prompt from the ledger AND re-appended
the ORIGINAL seed task description verbatim. That description is a numbered
orientation checklist ("1. Load the case. 2. Load alerts. ..."), so small models
replayed orientation each cycle and never reached the SIEM step — six concrete
numbered imperatives out-pull one advisory interpretation note.

The original fix wiped the message history each cycle, which also destroyed the
model's view of its own retrieved evidence. The current design separates the two
things that were sharing one list:

  - the ANCHOR (task objective + reasoning contract) is written once as message[1]
    and never re-appended, so the checklist cannot come back;
  - the STEERING (ledger-derived guidance) rides on the model call but is never
    persisted, so instructions do not accumulate;
  - EVIDENCE accumulates across cycles and is cleared only at `claim`.

These pin all three.
"""

import asyncio
import unittest

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

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
        "agent_name": "investigation",
        "messages": messages if messages is not None else [],
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


def _retained_history(anchor_text: str) -> list:
    """A task mid-flight: anchor, one tool call, and its raw result."""
    return [
        SystemMessage(content="SYS"),
        HumanMessage(content="# USER\n" + anchor_text),
        AIMessage(content="", tool_calls=[{"name": "search", "args": {}, "id": "c1"}]),
        ToolMessage(
            content='{"total": 3, "events": [{"_id": "evt-1"}]}',
            tool_call_id="c1",
            name="search",
        ),
    ]


class ThinkPromptShapeTest(unittest.TestCase):
    def setUp(self):
        self._captured = []

        async def _capture(bound, messages, agent_name):
            self._captured.append(messages)
            return AIMessage(content="ok")

        self._orig = nodes_loop.nodes._invoke_bound_model
        nodes_loop.nodes._invoke_bound_model = _capture

    def tearDown(self):
        nodes_loop.nodes._invoke_bound_model = self._orig

    def _sent(self):
        return self._captured[-1]

    def _last_human(self):
        return [m for m in self._sent() if isinstance(m, HumanMessage)][-1].content

    def _all_text(self):
        return "\n".join(str(getattr(m, "content", "")) for m in self._sent())

    def _config(self):
        return {
            "configurable": {"model": _StubModel(), "tools": [], "system_prompt": "SYS"}
        }

    # ── the anchor ──────────────────────────────────────────────────────────────

    def test_fresh_claim_carries_the_full_task_description(self):
        # Turn 1 still shows the whole startup sequence — it is only the REPLAY of it
        # that was harmful.
        _run(
            nodes_loop.think(
                _state(ledger={"next_step_instruction": ""}), self._config()
            )
        )
        text = self._all_text()
        self.assertIn("1. Load the case record.", text)
        self.assertIn("6. Load other alerts", text)

    def test_the_anchor_is_not_re_appended_on_continuation(self):
        # THE anti-replay guarantee: with history retained, `think` does not rebuild the
        # anchor, so the numbered checklist appears exactly once no matter how many
        # cycles the task runs.
        anchor = nodes_loop._task_anchor(_state(ledger={}))
        history = _retained_history(anchor)
        ledger = {"next_step_instruction": "Issue your first SIEM query now."}
        _run(nodes_loop.think(_state(ledger=ledger, messages=history), self._config()))
        self.assertEqual(self._all_text().count("1. Load the case record."), 1)

    # ── the steering ────────────────────────────────────────────────────────────

    def test_the_instruction_rides_on_the_call_as_the_last_message(self):
        ledger = {
            "next_step_instruction": "Orientation is complete — issue your first SIEM query now.",
            "evidence_state": "orientation",
        }
        _run(
            nodes_loop.think(
                _state(ledger=ledger, messages=_retained_history("A")), self._config()
            )
        )
        steering = self._last_human()
        self.assertIn("REQUIRED next step", steering)
        self.assertIn("issue your first SIEM query", steering)

    def test_steering_is_not_persisted(self):
        ledger = {"next_step_instruction": "Query the SIEM now."}
        history = _retained_history("A")
        out = _run(
            nodes_loop.think(_state(ledger=ledger, messages=history), self._config())
        )
        # History grows by the model's reply only — the steering never lands in state,
        # so instructions cannot accumulate over a long task.
        self.assertEqual(len(out["messages"]), len(history) + 1)
        persisted = "\n".join(str(getattr(m, "content", "")) for m in out["messages"])
        self.assertNotIn("REQUIRED next step", persisted)

    # ── the evidence ────────────────────────────────────────────────────────────

    def test_retained_evidence_reaches_the_model(self):
        # The property the whole flattening exists for: the model choosing the next
        # tool call can see what earlier cycles retrieved.
        ledger = {"next_step_instruction": "Keep going."}
        _run(
            nodes_loop.think(
                _state(ledger=ledger, messages=_retained_history("A")), self._config()
            )
        )
        self.assertIn("evt-1", self._all_text())


if __name__ == "__main__":
    unittest.main()
