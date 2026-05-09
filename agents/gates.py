from __future__ import annotations

from agents.tiers import AnalysisTier, requires_llm


def skip_llm(tier: AnalysisTier | str) -> bool:
    return not requires_llm(tier)


def needs_extra_validation(tier: AnalysisTier | str) -> bool:
    resolved = AnalysisTier(tier) if isinstance(tier, str) else tier
    return resolved == AnalysisTier.DEEP
