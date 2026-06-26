from __future__ import annotations

"""Core dataclasses that define agent behavior and cross-agent handoffs."""

from dataclasses import dataclass, field


@dataclass
class Budget:
    """Execution limits enforced by the runtime graph for one agent run."""
    max_steps: int = 20
    max_tool_calls: int = 60


@dataclass
class AgentDefinition:
    """Static configuration for an agent exposed through the registry."""
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
    default_vicinity_window_hours: int = 24


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
    prior_investigation_report: str = ""  # set for resume runs; used instead of triage_report

    def to_dict(self) -> dict:
        """Serialize the handoff into AgentRun metadata."""
        return {
            "analyst_request": self.analyst_request,
            "triage_report": self.triage_report,
            "source_run_id": self.source_run_id,
            "artifacts": self.artifacts,
            "prior_investigation_report": self.prior_investigation_report,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "Handoff | None":
        """Rehydrate a handoff payload previously stored in run metadata."""
        if not data:
            return None
        return cls(
            analyst_request=data.get("analyst_request", ""),
            triage_report=data.get("triage_report", ""),
            source_run_id=data.get("source_run_id", ""),
            artifacts=data.get("artifacts") or {},
            prior_investigation_report=data.get("prior_investigation_report", ""),
        )

    def to_seed_text(self) -> str:
        """Seed-task description for resume runs (prior investigation report present).

        Normal triage handoffs are seeded by the dedicated seeder agent instead.
        """
        return self._resume_seed_text()

    def _resume_seed_text(self) -> str:
        """Seed text for a resume run: populate the queue from the prior run's open gaps."""
        parts = ["## Investigation resume handoff", ""]
        if self.analyst_request:
            parts.append(f"**Analyst request:** {self.analyst_request}")
            parts.append("")
        parts.append("### Context")
        parts.append(
            "A prior investigation run exhausted its budget before completing. "
            "The prior run's findings and open gaps are provided below. "
            "Your job is to populate the task queue with tasks that cover the **remaining open work** "
            "— do NOT re-investigate questions that were already conclusively answered."
        )
        parts.append("")
        parts.append("### Step 1 — populate your task queue (do this before any investigation)")
        parts.append("")
        parts.append(
            "Read the prior investigation report below carefully. Then:\n"
            "1. Identify every item in **## Open Gaps**, **## Blocking Gaps**, **## Incomplete Tasks**, "
            "and any `[Open]` hypotheses. Create one `create_task` call per item.\n"
            "2. Do NOT create tasks for questions already answered in **## Completed Tasks** "
            "or the **## Investigation Summary** — those are done.\n"
            "3. For any incomplete task listed in **## Incomplete Tasks**, create a task to "
            "finish it, including the relevant pivots and time windows from the prior run.\n"
            "4. Always call `list_tasks` before each `create_task` to avoid duplicates.\n\n"
            "Do NOT run SIEM queries or read files until all tasks are queued and this seed "
            "task is marked complete."
        )
        parts.append("")
        parts.append("## Prior investigation report")
        parts.append("")
        parts.append(self.prior_investigation_report or "(no prior report provided)")
        return "\n".join(parts)

