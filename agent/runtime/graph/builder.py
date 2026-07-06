from __future__ import annotations

"""LangGraph assembly for the agent execution loop."""

from langgraph.graph import END, StateGraph

from .nodes_flow import assess, finish, pivot, publish_finish, reassess_verdict, verdict_contract
from .interpretation import interpret
from .nodes_loop import _MAX_TASK_TOOL_CALLS, claim, seed, think, use_tools
from .state import AgentState



def _route_claim(state: AgentState) -> str:
    """Advance to reasoning only when a task was successfully claimed."""
    return "think" if state.get("current_task") else "finish"


def _route_use_tools(state: AgentState) -> str:
    """Interpret tool output before the model is allowed to act again."""
    if state.get("status") == "cancelled":
        return "finish"
    return "interpret"


def _route_interpret(state: AgentState) -> str:
    """Either continue task reasoning or finalize the current task."""
    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )
    if state.get("status") == "cancelled" or over_budget:
        return "finish"
    return "assess" if state.get("status") == "ready_to_assess" else "think"


def _route_think(state: AgentState) -> str:
    """Choose between more tool use, assessment, or shutdown based on the latest model reply."""
    last = state["messages"][-1] if state["messages"] else None
    if state["steps"] >= state["max_steps"] or state["tool_calls_made"] >= state["max_tool_calls"]:
        return "finish"
    # Per-task call cap: a capped investigation task must close (→ assess), never loop
    # back into use_tools — `think` already stripped its tools, but this also blocks a
    # pathological hallucinated tool call from bypassing the cap via use_tools' full map.
    # Keyed on the deterministic counter alone: the interpret→think continuation clears
    # `messages` to [], so a ToolMessage-presence guard here silently defeats the cap.
    task_calls = state["tool_calls_made"] - state.get("task_call_floor", 0)
    if (
        state["agent_name"] == "investigation"
        and task_calls >= _MAX_TASK_TOOL_CALLS
    ):
        return "assess"
    return "use_tools" if (last and getattr(last, "tool_calls", None)) else "assess"


def _route_assess(state: AgentState) -> str:
    """Let guard rails retry when budget remains; otherwise continue queue processing or finish."""
    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )
    if state.get("status") == "needs_more_work":
        return "finish" if over_budget else "think"
    if over_budget:
        return "finish"
    return "pivot"


def build_graph():
    """Construct the compiled agent graph shared by all runtime executions."""
    g = StateGraph(AgentState)
    g.add_node("seed", seed)
    g.add_node("claim", claim)
    g.add_node("think", think)
    g.add_node("use_tools", use_tools)
    g.add_node("interpret", interpret)
    g.add_node("assess", assess)
    g.add_node("pivot", pivot)
    g.add_node("finish", finish)
    g.add_node("verdict_contract", verdict_contract)
    g.add_node("reassess_verdict", reassess_verdict)
    g.add_node("publish_finish", publish_finish)

    g.set_entry_point("seed")
    g.add_edge("seed", "claim")
    g.add_conditional_edges("claim", _route_claim, {"think": "think", "finish": "finish"})
    g.add_conditional_edges("use_tools", _route_use_tools, {"interpret": "interpret", "finish": "finish"})
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
        "assess", _route_assess,
        {"think": "think", "pivot": "pivot", "finish": "finish"},
    )
    g.add_edge("pivot", "claim")
    g.add_edge("finish", "verdict_contract")
    g.add_edge("verdict_contract", "reassess_verdict")
    g.add_edge("reassess_verdict", "publish_finish")
    g.add_edge("publish_finish", END)
    return g.compile()


GRAPH = build_graph()
