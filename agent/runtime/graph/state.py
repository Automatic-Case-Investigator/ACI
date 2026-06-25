from __future__ import annotations

from typing import Optional
from typing_extensions import TypedDict




class AgentState(TypedDict):
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
    status: str
    final_answer: str
    ctx_tokens: int  # input tokens from the most recent model call
    verdict: Optional[dict]  # structured diagnosis contract parsed at finish
    pivot_tasks_created: int  # follow-up tasks the pivot node has auto-created (capped)
    escalation_posted: bool  # True once an in-band escalation comment has been posted
    summary_format_retries: int  # per-task count of report-format correction nudges
