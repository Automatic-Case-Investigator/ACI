"""LLM judge wrapper for judge-based metrics (rubric scoring, technique attribution).

A metric that sets `needs_judge = True` reads `ctx.judge`, an instance of this class,
to ask a model a bounded, structured question and get back a parsed verdict. Kept
separate from the metrics so the model-call plumbing (provider config, ret/parse,
determinism controls) lives in one place.
"""
from __future__ import annotations


class LLMJudge:
    def __init__(self, model_config: dict | None = None) -> None:
        self._config = model_config or {}

    def score(self, prompt: str, schema: dict | None = None) -> dict:
        raise NotImplementedError("LLM judge not yet implemented")
