from __future__ import annotations

"""Typed state shared between LangGraph nodes during an agent run."""

from typing import Optional
from typing_extensions import TypedDict




class AgentState(TypedDict):
    """Canonical mutable state consumed and returned by graph nodes."""
    run_id: str
    case_id: str
    agent_name: str
    question: str
    handoff: Optional[dict]
    current_task: Optional[dict]
    last_completed_task: Optional[dict]
    messages: list
    steps: int
    tool_calls_made: int
    max_steps: int
    max_tool_calls: int
    default_vicinity_window_hours: int
    status: str
    final_answer: str
    ctx_tokens: int  # input tokens from the most recent model call
    verdict: Optional[dict]  # structured diagnosis contract parsed at finish
    pivot_tasks_created: int  # follow-up tasks the pivot node has auto-created
    task_call_floor: int  # tool_calls_made snapshot at claim time — bounds per-task call budget
    escalation_posted: bool  # True once an in-band escalation comment has been posted
    reflection_retries: int  # per-task count of self-review (keep-working / fix-report) nudges
    reflection_evidence_at_last_nudge: int  # evidence-query count when the last keep-working nudge fired (convergence guard)
    last_findings_verification: Optional[dict]  # self-review verdicts on the current task's ## Findings (reused by pivot for board gating)
    last_confirmed_findings: list  # durable confirmed findings from the just-completed task ledger
    completed_task_titles: list  # [{title, summary}] for each finished task — used by lead validator to block re-investigation
    task_ledger: Optional[dict]  # durable per-task metacognition/evidence state updated after each observation
    last_observation: Optional[dict]  # normalized summary of the most recent tool-observation batch
    observation_retries: int  # consecutive observation cycles with no meaningful new evidence
    refine_streak: int  # consecutive interpret cycles that chose refine_query without advancing
