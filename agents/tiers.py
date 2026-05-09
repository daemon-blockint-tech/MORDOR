from __future__ import annotations

from enum import Enum


class AnalysisTier(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


_TIER_ORDER = [AnalysisTier.QUICK, AnalysisTier.STANDARD, AnalysisTier.DEEP]
_TIER_MAP = {t.value: t for t in _TIER_ORDER}


def _resolve(tier: AnalysisTier | str) -> AnalysisTier:
    if isinstance(tier, AnalysisTier):
        return tier
    return _TIER_MAP.get(tier, AnalysisTier.STANDARD)


def at_least(current: AnalysisTier | str, minimum: AnalysisTier | str) -> bool:
    return _TIER_ORDER.index(_resolve(current)) >= _TIER_ORDER.index(_resolve(minimum))


def requires_llm(tier: AnalysisTier | str) -> bool:
    return at_least(tier, AnalysisTier.STANDARD)
