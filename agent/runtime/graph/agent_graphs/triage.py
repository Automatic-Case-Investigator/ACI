from __future__ import annotations

from langgraph.graph import END, StateGraph

from ..nodes_flow import finish, publish_finish, reassess_verdict, verdict_contract
from ..nodes_loop import seed, triage_think, use_tools
from ..state import AgentState


def _route_use_tools(state: AgentState) -> str:
    if state.get("status") == "cancelled":
        return "finish"
    return "triage_think"


def _route_triage_think(state: AgentState) -> str:
    if state.get("status") == "cancelled":
        return "finish"
    if (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    ):
        return "finish"
    last = state["messages"][-1] if state["messages"] else None
    return "use_tools" if (last and getattr(last, "tool_calls", None)) else "finish"


def build_triage_graph():
    g = StateGraph(AgentState)
    g.add_node("seed", seed)
    g.add_node("triage_think", triage_think)
    g.add_node("use_tools", use_tools)
    g.add_node("finish", finish)
    g.add_node("verdict_contract", verdict_contract)
    g.add_node("reassess_verdict", reassess_verdict)
    g.add_node("publish_finish", publish_finish)

    g.set_entry_point("seed")
    g.add_edge("seed", "triage_think")
    g.add_conditional_edges(
        "triage_think",
        _route_triage_think,
        {"use_tools": "use_tools", "finish": "finish"},
    )
    g.add_conditional_edges(
        "use_tools",
        _route_use_tools,
        {"triage_think": "triage_think", "finish": "finish"},
    )
    g.add_edge("finish", "verdict_contract")
    g.add_edge("verdict_contract", "reassess_verdict")
    g.add_edge("reassess_verdict", "publish_finish")
    g.add_edge("publish_finish", END)
    return g.compile()
