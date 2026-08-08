from __future__ import annotations

"""LangGraph assembly for the agent execution loop."""

from langgraph.graph import END, StateGraph

from .nodes_flow import (
    assess,
    finish,
    pivot,
    publish_finish,
    reassess_verdict,
    verdict_contract,
)
from .coverage import _count_evidence_queries
from .interpretation import interpret
from .nodes_loop import _MAX_TASK_TOOL_CALLS, claim, seed, think, use_tools
from .state import AgentState
from .triage_flat import triage_think


def _route_seed(state: AgentState) -> str:
    """Triage runs the flat loop; every other agent runs the task-queue loop."""
    return "triage_think" if state["agent_name"] == "triage" else "claim"


def _route_claim(state: AgentState) -> str:
    """Advance to reasoning only when a task was successfully claimed."""
    return "think" if state.get("current_task") else "finish"


def _route_use_tools(state: AgentState) -> str:
    """Interpret tool output before the model is allowed to act again."""
    if state.get("status") == "cancelled":
        return "finish"
    # Triage's flat loop has no interpret node — its history IS its memory, so the
    # raw tool results go straight back to the model that will act on them next.
    if state["agent_name"] == "triage":
        return "triage_think"
    return "interpret"


def _route_triage_think(state: AgentState) -> str:
    """Act on tool calls, or finish once the flat loop produced a report."""
    if state.get("status") == "cancelled":
        return "finish"
    if (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    ):
        return "finish"
    last = state["messages"][-1] if state["messages"] else None
    return "use_tools" if (last and getattr(last, "tool_calls", None)) else "finish"


def _route_interpret(state: AgentState) -> str:
    """The single completion decision: continue task reasoning, or finalize the task.

    `interpret` is the only node that decides a task is done. `assess` used to hold a
    second vote (`review_task_model().keep_working`) that could overturn this one —
    two model calls answering one question — and it no longer does.
    """
    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )
    if state.get("status") == "cancelled" or over_budget:
        return "finish"
    if state.get("status") != "ready_to_assess":
        return "think"
    # Evidence floor: a task that retrieved nothing has not investigated anything, and
    # its vote to conclude is not credible. Observed concluding "rule-out" tasks on
    # cumulative board context with zero queries of their own. A deterministic predicate
    # here rather than a retry loop in another node — it vetoes a completion decision,
    # it never initiates one.
    if (
        state.get("agent_name") == "investigation"
        and _count_evidence_queries(state.get("messages") or []) == 0
    ):
        return "think"
    return "assess"


def _route_think(state: AgentState) -> str:
    """Choose between more tool use, assessment, or shutdown based on the latest model reply."""
    last = state["messages"][-1] if state["messages"] else None
    if (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    ):
        return "finish"
    # Per-task call cap: a capped investigation task must close (→ assess), never loop
    # back into use_tools — `think` already stripped its tools, but this also blocks a
    # pathological hallucinated tool call from bypassing the cap via use_tools' full map.
    # Keyed on the deterministic per-task counter, never on ToolMessage presence: the
    # counter measures this task alone and cannot be fooled by how history is assembled.
    task_calls = state["tool_calls_made"] - state.get("task_call_floor", 0)
    if state["agent_name"] == "investigation" and task_calls >= _MAX_TASK_TOOL_CALLS:
        return "assess"
    return "use_tools" if (last and getattr(last, "tool_calls", None)) else "assess"


def _route_assess(state: AgentState) -> str:
    """Continue queue processing, or stop if the run is out of budget.

    No `needs_more_work` branch: `assess` produces the task's report and findings but
    no longer votes on whether the task is done, so it can never send one back.
    """
    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )
    return "finish" if over_budget else "pivot"


def build_graph():
    """Construct the compiled agent graph shared by all runtime executions."""
    g = StateGraph(AgentState)
    g.add_node("seed", seed)
    g.add_node("claim", claim)
    g.add_node("think", think)
    g.add_node("triage_think", triage_think)
    g.add_node("use_tools", use_tools)
    g.add_node("interpret", interpret)
    g.add_node("assess", assess)
    g.add_node("pivot", pivot)
    g.add_node("finish", finish)
    g.add_node("verdict_contract", verdict_contract)
    g.add_node("reassess_verdict", reassess_verdict)
    g.add_node("publish_finish", publish_finish)

    g.set_entry_point("seed")
    g.add_conditional_edges(
        "seed",
        _route_seed,
        {"claim": "claim", "triage_think": "triage_think"},
    )
    g.add_conditional_edges(
        "claim", _route_claim, {"think": "think", "finish": "finish"}
    )
    g.add_conditional_edges(
        "use_tools",
        _route_use_tools,
        {"interpret": "interpret", "triage_think": "triage_think", "finish": "finish"},
    )
    g.add_conditional_edges(
        "triage_think",
        _route_triage_think,
        {"use_tools": "use_tools", "finish": "finish"},
    )
    g.add_conditional_edges(
        "interpret",
        _route_interpret,
        {"think": "think", "assess": "assess", "finish": "finish"},
    )
    g.add_conditional_edges(
        "think",
        _route_think,
        {"use_tools": "use_tools", "assess": "assess", "finish": "finish"},
    )
    g.add_conditional_edges(
        "assess",
        _route_assess,
        {"pivot": "pivot", "finish": "finish"},
    )
    g.add_edge("pivot", "claim")
    g.add_edge("finish", "verdict_contract")
    g.add_edge("verdict_contract", "reassess_verdict")
    g.add_edge("reassess_verdict", "publish_finish")
    g.add_edge("publish_finish", END)
    return g.compile()


GRAPH = build_graph()
