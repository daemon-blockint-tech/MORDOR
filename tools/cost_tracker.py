from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from tools.model_router import ComplexityTier, ModelConfig, TIER_CONFIGS

logger = logging.getLogger("mordor.cost_tracker")

MAX_COST_LIMIT = 50.0  # Safe max spend per case


@dataclass
class CostEntry:
    agent_name: str
    model: str
    tier: ComplexityTier
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    estimated_cost: float = 0.0
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    phase: str = ""
    success: bool = True


class CostTracker:
    def __init__(self) -> None:
        self.entries: list[CostEntry] = []
        self._start_time: float = 0.0
        self._current_entry: CostEntry | None = None

    def start_phase(self, agent_name: str, phase: str = "") -> None:
        cfg = _get_config_for_agent(agent_name)
        self._current_entry = CostEntry(
            agent_name=agent_name,
            model=cfg.model_id,
            tier=_get_tier_for_agent(agent_name),
            phase=phase,
        )
        self._start_time = time.monotonic()

    def record_usage(
        self,
        usage_metadata: dict[str, Any] | None,
        success: bool = True,
    ) -> None:
        if not self._current_entry:
            return
        elapsed = (time.monotonic() - self._start_time) * 1000
        self._current_entry.duration_ms = round(elapsed, 1)
        self._current_entry.success = success

        if usage_metadata:
            input_tokens = usage_metadata.get("input_tokens", 0) or 0
            output_tokens = usage_metadata.get("output_tokens", 0) or 0
            self._current_entry.input_tokens = input_tokens
            self._current_entry.output_tokens = output_tokens

            output_details = usage_metadata.get("output_token_details", {}) or {}
            self._current_entry.reasoning_tokens = output_details.get("reasoning", 0) or 0

            input_details = usage_metadata.get("input_token_details", {}) or {}
            self._current_entry.cache_creation_tokens = input_details.get("cache_creation", 0) or 0
            self._current_entry.cache_read_tokens = input_details.get("cache_read", 0) or 0

            self._current_entry.estimated_cost = self._calculate_cost(
                self._current_entry.model,
                input_tokens,
                output_tokens,
                self._current_entry.reasoning_tokens,
            )

            # Safeguard: Prevent exploding costs
            if self.get_total_cost() + self._current_entry.estimated_cost > MAX_COST_LIMIT:
                logger.critical("COST LIMIT EXCEEDED: Analysis halted to prevent exploding costs.")
                raise RuntimeError(f"Cost limit of ${MAX_COST_LIMIT} exceeded during analysis.")

        self.entries.append(self._current_entry)
        logger.debug(
            "Cost[%s/%s]: %d+%d tokens = $%.6f in %.0fms",
            self._current_entry.agent_name,
            self._current_entry.phase,
            self._current_entry.input_tokens,
            self._current_entry.output_tokens,
            self._current_entry.estimated_cost,
            self._current_entry.duration_ms,
        )
        self._current_entry = None

    def _calculate_cost(
        self, model: str, input_tokens: int, output_tokens: int, reasoning_tokens: int = 0
    ) -> float:
        cfg = _find_config(model)
        if not cfg:
            return 0.0
        input_cost = (input_tokens / 1000) * cfg.cost_per_1k_input
        output_cost = (output_tokens / 1000) * cfg.cost_per_1k_output
        return round(input_cost + output_cost, 8)

    def get_total_cost(self) -> float:
        return round(sum(e.estimated_cost for e in self.entries), 8)

    def get_phase_cost(self, phase: str) -> float:
        return round(
            sum(e.estimated_cost for e in self.entries if e.phase == phase),
            8,
        )

    def get_agent_cost(self, agent_name: str) -> float:
        return round(
            sum(
                e.estimated_cost
                for e in self.entries
                if e.agent_name == agent_name
            ),
            8,
        )

    def get_token_summary(self) -> dict[str, int]:
        total_input = sum(e.input_tokens for e in self.entries)
        total_output = sum(e.output_tokens for e in self.entries)
        total_reasoning = sum(e.reasoning_tokens for e in self.entries)
        return {
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_reasoning_tokens": total_reasoning,
            "total_tokens": total_input + total_output,
        }

    def get_summary(self) -> dict[str, Any]:
        return {
            "total_cost": self.get_total_cost(),
            "total_entries": len(self.entries),
            "phases": list(set(e.phase for e in self.entries if e.phase)),
            "agents": list(set(e.agent_name for e in self.entries)),
            "tokens": self.get_token_summary(),
            "entries": [
                {
                    "agent": e.agent_name,
                    "model": e.model,
                    "phase": e.phase,
                    "input_tokens": e.input_tokens,
                    "output_tokens": e.output_tokens,
                    "cost": e.estimated_cost,
                    "duration_ms": e.duration_ms,
                    "success": e.success,
                }
                for e in self.entries
            ],
        }


_global_tracker = CostTracker()


def get_tracker() -> CostTracker:
    return _global_tracker


def reset_tracker() -> None:
    global _global_tracker
    _global_tracker = CostTracker()


def _get_config_for_agent(agent_name: str) -> ModelConfig:
    from tools.model_router import get_agent_model

    return get_agent_model(agent_name)


def _get_tier_for_agent(agent_name: str) -> ComplexityTier:
    from tools.model_router import get_agent_tier

    return get_agent_tier(agent_name)


def _find_config(model: str) -> ModelConfig | None:
    for cfg in TIER_CONFIGS.values():
        if cfg.model_id == model:
            return cfg
    return None
