from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from dotenv import load_dotenv
try:
    from langchain_openrouter import ChatOpenRouter
    _HAS_OPENROUTER = True
except ImportError:
    ChatOpenRouter = None  # type: ignore
    _HAS_OPENROUTER = False

load_dotenv()


class ComplexityTier(str, Enum):
    SIMPLE = "simple"
    MEDIUM = "medium"
    COMPLEX = "complex"
    CRITICAL = "critical"


@dataclass
class ModelConfig:
    model_id: str
    temperature: float = 0.3
    max_tokens: int = 2048
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    supports_vision: bool = False
    supports_structured_output: bool = True


TIER_CONFIGS: dict[ComplexityTier, ModelConfig] = {
    ComplexityTier.SIMPLE: ModelConfig(
        model_id=os.getenv("MODEL_SIMPLE", "openai/gpt-4o-mini"),
        temperature=0.1,
        max_tokens=512,
        cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006,
        supports_vision=False,
    ),
    ComplexityTier.MEDIUM: ModelConfig(
        model_id=os.getenv("MODEL_MEDIUM", "moonshotai/kimi-k2.6"),
        temperature=0.3,
        max_tokens=2048,
        cost_per_1k_input=0.002,
        cost_per_1k_output=0.008,
        supports_vision=False,
    ),
    ComplexityTier.COMPLEX: ModelConfig(
        model_id=os.getenv("MODEL_COMPLEX", "anthropic/claude-sonnet-4.5"),
        temperature=0.3,
        max_tokens=4096,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
        supports_vision=True,
    ),
    ComplexityTier.CRITICAL: ModelConfig(
        model_id=os.getenv("SARUMAN_MODEL", "anthropic/claude-opus-4"),
        temperature=0.2,
        max_tokens=8192,
        cost_per_1k_input=0.015,
        cost_per_1k_output=0.075,
        supports_vision=True,
    ),
}


DEFAULT_TIER_MAP: dict[str, ComplexityTier] = {
    "aragorn": ComplexityTier.MEDIUM,
    "boromir": ComplexityTier.SIMPLE,
    "gollum": ComplexityTier.MEDIUM,
    "legolas": ComplexityTier.MEDIUM,
    "merry": ComplexityTier.SIMPLE,
    "elrond": ComplexityTier.SIMPLE,
    "faramir": ComplexityTier.SIMPLE,
    "arwen": ComplexityTier.MEDIUM,
    "pippin": ComplexityTier.MEDIUM,
    "eowyn": ComplexityTier.COMPLEX,
    "frodo": ComplexityTier.MEDIUM,
    "gimli": ComplexityTier.MEDIUM,
    "treebeard": ComplexityTier.SIMPLE,
    "saruman": ComplexityTier.CRITICAL,
    "gandalf": ComplexityTier.COMPLEX,
    "gandalf_white": ComplexityTier.COMPLEX,
    "bilbo": ComplexityTier.SIMPLE,
    "multimodal": ComplexityTier.COMPLEX,
}


def get_agent_tier(agent_name: str) -> ComplexityTier:
    return DEFAULT_TIER_MAP.get(agent_name, ComplexityTier.MEDIUM)


def get_agent_model(agent_name: str) -> ModelConfig:
    tier = get_agent_tier(agent_name)
    return TIER_CONFIGS[tier]


def classify_tier_from_input(
    signal_count: int = 0,
    has_known_packer: bool = False,
    imports_count: int = 0,
    is_critical_hypothesis: bool = False,
    needs_vision: bool = False,
) -> ComplexityTier:
    if is_critical_hypothesis:
        return ComplexityTier.CRITICAL
    if needs_vision:
        return ComplexityTier.COMPLEX
    if has_known_packer or imports_count > 200 or signal_count > 50:
        return ComplexityTier.COMPLEX
    if signal_count > 10 or imports_count > 50:
        return ComplexityTier.MEDIUM
    return ComplexityTier.SIMPLE


def create_chat_model(
    agent_name: str | None = None,
    tier: ComplexityTier | None = None,
    model_override: str | None = None,
    temperature_override: float | None = None,
    max_tokens_override: int | None = None,
    **kwargs: Any,
) -> ChatOpenRouter:
    from tools.openrouter_client import OPENROUTER_API_KEY, APP_NAME, APP_URL

    if model_override:
        cfg = ModelConfig(
            model_id=model_override,
            temperature=temperature_override or 0.3,
            max_tokens=max_tokens_override or 2048,
        )
    elif tier:
        cfg = TIER_CONFIGS[tier]
    elif agent_name:
        cfg = get_agent_model(agent_name)
    else:
        cfg = TIER_CONFIGS[ComplexityTier.MEDIUM]

    return ChatOpenRouter(
        model=cfg.model_id,
        temperature=temperature_override or cfg.temperature,
        max_tokens=max_tokens_override or cfg.max_tokens,
        openrouter_api_key=OPENROUTER_API_KEY,
        app_title=APP_NAME,
        app_url=APP_URL,
        **kwargs,
    )
