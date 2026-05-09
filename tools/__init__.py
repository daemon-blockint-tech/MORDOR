from tools.openrouter_client import chat, chat_json, chat_structured, get_model
from tools.model_router import create_chat_model, ComplexityTier, get_agent_tier, TIER_CONFIGS
from tools.cost_tracker import CostTracker, CostEntry, get_tracker, reset_tracker

# Optional coding-agent adapters (gate-checked by env vars)
try:
    from tools.opencode_adapter import (
        coding_query as _opencode_query,  # noqa: F401
        is_available as _opencode_available,  # noqa: F401
        run_opencode_analysis as _run_opencode_analysis,  # noqa: F401
    )
except ImportError:
    pass

try:
    from tools.claude_agent_adapter import (
        coding_query as _claude_agent_query,  # noqa: F401
        is_available as _claude_agent_available,  # noqa: F401
        run_agent_analysis as _run_agent_analysis,  # noqa: F401
    )
except ImportError:
    pass

__all__ = [
    "chat",
    "chat_json",
    "chat_structured",
    "get_model",
    "create_chat_model",
    "ComplexityTier",
    "get_agent_tier",
    "TIER_CONFIGS",
    "CostTracker",
    "CostEntry",
    "get_tracker",
    "reset_tracker",
]
