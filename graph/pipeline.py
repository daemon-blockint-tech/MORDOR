from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from graph.nodes import (
    handle_error,
    phase_deep_analysis,
    phase_filter,
    phase_fingerprint,
    phase_hypothesize,
    phase_map_structure,
    phase_report,
    phase_validate,
)
from graph.state import CaseState


def build_pipeline() -> StateGraph:
    builder = StateGraph(CaseState)

    builder.add_node("fingerprint", phase_fingerprint)
    builder.add_node("filter", phase_filter)
    builder.add_node("hypothesize", phase_hypothesize)
    builder.add_node("map_structure", phase_map_structure)
    builder.add_node("deep_analysis", phase_deep_analysis)
    builder.add_node("validate", phase_validate)
    builder.add_node("report", phase_report)
    builder.add_node("error", handle_error)

    builder.set_entry_point("fingerprint")

    # All routing is handled by goto inside each phase node's Command return.
    # Adding edges here would double-schedule the target node in LangGraph 0.6.x
    # when Command is also used for routing.
    builder.add_edge("report", END)
    builder.add_edge("error", END)

    checkpointer = MemorySaver()
    graph = builder.compile(checkpointer=checkpointer)

    return graph
