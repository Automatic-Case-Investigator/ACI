from __future__ import annotations

from langgraph.graph import END, StateGraph

from .nodes_flow import assess, finish, pivot, publish_finish, reassess_verdict, verdict_contract
from .nodes_loop import claim, seed, think, use_tools
from .state import AgentState



def _route_claim(state: AgentState) -> str:
    return "think" if state.get("current_task") else "finish"


def _route_use_tools(state: AgentState) -> str:
    if state.get("status") == "cancelled":
        return "finish"
    return "think"


def _route_think(state: AgentState) -> str:
    last = state["messages"][-1] if state["messages"] else None
    if state["steps"] >= state["max_steps"] or state["tool_calls_made"] >= state["max_tool_calls"]:
        return "finish"
    return "use_tools" if (last and getattr(last, "tool_calls", None)) else "assess"


def _route_assess(state: AgentState) -> str:
    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )
    if state.get("status") in {"seed_guard", "triage_siem_guard", "investigation_siem_guard", "summary_format_guard"}:
        return "finish" if over_budget else "think"
    if over_budget:
        return "finish"
    return "pivot"


def build_graph():
    g = StateGraph(AgentState)
    g.add_node("seed", seed)
    g.add_node("claim", claim)
    g.add_node("think", think)
    g.add_node("use_tools", use_tools)
    g.add_node("assess", assess)
    g.add_node("pivot", pivot)
    g.add_node("finish", finish)
    g.add_node("verdict_contract", verdict_contract)
    g.add_node("reassess_verdict", reassess_verdict)
    g.add_node("publish_finish", publish_finish)

    g.set_entry_point("seed")
    g.add_edge("seed", "claim")
    g.add_conditional_edges("claim", _route_claim, {"think": "think", "finish": "finish"})
    g.add_conditional_edges("use_tools", _route_use_tools, {"think": "think", "finish": "finish"})
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
