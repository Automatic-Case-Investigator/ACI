from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Budget:
    max_steps: int = 20
    max_tool_calls: int = 60


@dataclass
class AgentDefinition:
    name: str
    description: str
    prompt_layers: list[str]
    tool_policy: list[str]
    budget: Budget = field(default_factory=Budget)
    can_spawn: bool = False
    handoff_targets: list[str] = field(default_factory=list)
    finalizer: str = "default"
    # Orchestrator routing hints (A2): how this agent participates in handoffs.
    # `produces_handoff` agents (triage) leave a report the orchestrator captures;
    # `consumes_handoff` agents (investigation) accept a triage report to seed from.
    produces_handoff: bool = False
    consumes_handoff: bool = False
    # Whether the orchestrator should route to this agent at all (vs. internal-only).
    orchestrator_routable: bool = True
    stream_intent: bool = True
    intent_style: str = "concise"


@dataclass
class Handoff:
    """Structured handoff from one agent run to the next (e.g. triage → investigation).

    Travels in `AgentRun.metadata["handoff"]` rather than being smuggled inside the
    question text, so the receiving agent's `seed` step can build its task queue from
    explicit fields instead of string-matching.
    """
    analyst_request: str = ""
    triage_report: str = ""
    source_run_id: str = ""
    artifacts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "analyst_request": self.analyst_request,
            "triage_report": self.triage_report,
            "source_run_id": self.source_run_id,
            "artifacts": self.artifacts,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "Handoff | None":
        if not data:
            return None
        return cls(
            analyst_request=data.get("analyst_request", ""),
            triage_report=data.get("triage_report", ""),
            source_run_id=data.get("source_run_id", ""),
            artifacts=data.get("artifacts") or {},
        )

    def to_seed_text(self) -> str:
        """The investigation seed-task description built from this handoff.

        Single canonical place for the handoff instructions: the orchestrator stores
        the Handoff, and `graph.seed` renders it here so the wording lives in one
        spot instead of being duplicated across the orchestrator and the graph.
        """
        parts = ["## Investigation handoff", ""]
        if self.analyst_request:
            parts.append(f"**Analyst request:** {self.analyst_request}")
            parts.append("")
        parts.append("### Step 1 — populate your task queue (do this before any investigation)")
        parts.append("")
        parts.append(
            "Your ONLY goal while executing this seed task is to call `create_task` for "
            "**every** numbered item in the triage investigation plan below. "
            "Count the items in the plan — then call `create_task` exactly that many times. "
            "For each task include: the question to answer, the exact pivots, the absolute "
            "time window, and the expected evidence source. Carry forward the triage priority. "
            "Do NOT run any SIEM queries, read files, or start investigating until all tasks "
            "are queued and this seed task is marked complete."
        )
        if self.artifacts:
            import json

            parts.append("")
            parts.append("### Carried artifacts")
            parts.append("```json")
            parts.append(json.dumps(self.artifacts, indent=2, default=str))
            parts.append("```")
        parts.append("")
        parts.append("## Triage report")
        parts.append("")
        parts.append(self.triage_report or "(no triage report text provided)")
        return "\n".join(parts)
