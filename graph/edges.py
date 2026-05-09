from __future__ import annotations

from typing import Literal

from agents.tiers import AnalysisTier
from graph.state import CaseState, PhaseName


def route_by_tier(state: CaseState) -> Literal["filter", "report"]:
    tier_str = state.get("analysis_tier", "standard")
    tier = AnalysisTier(tier_str) if isinstance(tier_str, str) and tier_str in {"quick", "standard", "deep"} else AnalysisTier.STANDARD
    if tier == AnalysisTier.QUICK:
        return "report"
    return "filter"


def should_retry(error_count: int) -> Literal["continue", "abort"]:
    return "continue" if error_count < 3 else "abort"


def route_after_error(state: CaseState) -> PhaseName:
    error_count = state.get("error_count", 0)

    if error_count >= 3:
        return "error"

    prev = state.get("current_phase", "fingerprint")
    phase_order: list[PhaseName] = [
        "fingerprint",
        "filter",
        "hypothesize",
        "map_structure",
        "deep_analysis",
        "validate",
    ]

    try:
        idx = phase_order.index(prev)
        return phase_order[max(0, idx)]
    except ValueError:
        return "fingerprint"


def should_skip_deep_analysis(state: CaseState) -> Literal["validate", "deep_analysis"]:
    confidence = state.get("confidence_overall", 0.0)
    has_critical = state.get("hypotheses", []) and any(
        h.get("confidence", 0) >= 85 for h in state["hypotheses"]
    )

    if confidence < 50 and not has_critical:
        return "validate"
    return "deep_analysis"


def route_completion(state: CaseState) -> PhaseName:
    if state.get("error_count", 0) >= 3:
        return "error"
    return "done"
