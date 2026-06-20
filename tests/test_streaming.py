from __future__ import annotations

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_root)

from langchain_core.messages import AIMessage, AIMessageChunk

from agent.runtime.intent import generate_public_intent
from agent.runtime.streaming import invoke_streaming


class FakeStreamingModel:
    async def astream(self, messages):
        yield AIMessageChunk(content="hello")
        yield AIMessageChunk(content=" world")

    async def ainvoke(self, messages):
        return AIMessage(content="fallback")


class CapturingStreamingModel(FakeStreamingModel):
    def __init__(self):
        self.messages = []

    def bind(self, **kwargs):
        return self

    async def astream(self, messages):
        self.messages = messages
        yield AIMessageChunk(content="The parser test fails at the input boundary.\n\n")
        yield AIMessageChunk(content="- The failure is reproducible.\n")
        yield AIMessageChunk(content="- I will inspect `parse_input` next.")


class EmptyIntentModel:
    async def astream(self, messages):
        if False:
            yield None

    async def ainvoke(self, messages):
        return AIMessage(content="")


class TestStreaming(unittest.TestCase):
    def test_streaming_chunks_are_accumulated(self):
        result = asyncio.run(
            invoke_streaming(FakeStreamingModel(), [], "orchestrator", "orch")
        )
        self.assertEqual(result.content, "hello world")

    def test_public_intent_accumulates_streamed_text(self):
        result = asyncio.run(
            generate_public_intent(
                FakeStreamingModel(),
                [],
                source="inv",
                sequence=3,
                task_title="Check authentication activity",
                available_tools=["search"],
            )
        )
        self.assertEqual(result.text, "hello world")
        self.assertEqual(result.sequence, 3)

    def test_public_summary_requests_found_assessment_and_next(self):
        model = CapturingStreamingModel()
        result = asyncio.run(
            generate_public_intent(
                model,
                [],
                source="inv",
                sequence=4,
                task_title="Fix the parser test",
                available_tools=["read_file"],
            )
        )
        prompt = model.messages[-1].content
        self.assertIn("think out loud", prompt)
        self.assertIn("Output only a few sentences", prompt)
        self.assertIn("The parser test fails", result.text)
        self.assertIn("`parse_input`", result.text)
        self.assertIn("Current objective", prompt)
        self.assertNotIn("**Found:**", prompt)

    def test_empty_intent_emits_no_synthetic_event(self):
        with patch("agent.runtime.intent.emit") as emit:
            result = asyncio.run(
                generate_public_intent(
                    EmptyIntentModel(),
                    [],
                    source="inv",
                    sequence=5,
                    task_title="Continue",
                    available_tools=["search"],
                )
            )
        self.assertEqual(result.text, "")
        self.assertFalse(result.streamed)
        emit.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
