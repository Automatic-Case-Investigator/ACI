from __future__ import annotations

"""Per-agent graph resolver.

This module intentionally replaces the former singleton `GRAPH` contract.
Runtime callers must request a graph by agent name.
"""

from functools import lru_cache

from .agent_graphs import (
    build_investigation_graph,
    build_seeder_graph,
    build_triage_graph,
)


@lru_cache(maxsize=None)
def get_graph(agent_name: str):
    """Return the compiled graph for a registered agent name."""
    if agent_name == "investigation":
        return build_investigation_graph()
    if agent_name == "triage":
        return build_triage_graph()
    if agent_name == "seeder":
        return build_seeder_graph()
    raise ValueError(f"Unknown agent graph: {agent_name}")
