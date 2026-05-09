"""Claude Agent SDK adapter — optional coding-agent integration.

Integrates with Anthropic's Claude Agent SDK (https://github.com/anthropics/claude-code)
for autonomous coding agent capabilities within the MORDOR pipeline.

Gate check: CLAUDE_AGENT_ENABLED=true in .env (default: disabled).
Install: pip install anthropic-agent-sdk  (Python >=3.10)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from dotenv import load_dotenv

from tools.openrouter_client import chat, chat_structured

load_dotenv()

logger = logging.getLogger("mordor.tools.claude_agent")

# ---------------------------------------------------------------------------
# Optional import — SDK may not be installed
# ---------------------------------------------------------------------------
_HAS_CLAUDE_AGENT = False
_claude_query = None
_claude_Agent = None
_claude_AvailableModel = None

try:
    from anthropic_agent_sdk import query as _claude_query
    from anthropic_agent_sdk import Agent as _claude_Agent  # noqa: F401
    from anthropic_agent_sdk import AvailableModel as _claude_AvailableModel  # noqa: F401

    _HAS_CLAUDE_AGENT = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CLAUDE_AGENT_ENABLED = os.getenv("CLAUDE_AGENT_ENABLED", "").lower() in ("1", "true", "yes")
CLAUDE_AGENT_MODEL = os.getenv("CLAUDE_AGENT_MODEL", "")

# ---------------------------------------------------------------------------
# Gate check
# ---------------------------------------------------------------------------
def is_available() -> bool:
    """Check if Claude Agent integration is enabled and the SDK is installed."""
    if not CLAUDE_AGENT_ENABLED:
        return False
    if not _HAS_CLAUDE_AGENT:
        logger.debug("anthropic-agent-sdk not installed")
        return False
    return True


def ensure_available() -> None:
    """Raise RuntimeError if Claude Agent is not available."""
    if not CLAUDE_AGENT_ENABLED:
        raise RuntimeError(
            "Claude Agent is not enabled. Set CLAUDE_AGENT_ENABLED=true in .env"
        )
    if not _HAS_CLAUDE_AGENT:
        raise RuntimeError(
            "anthropic-agent-sdk is not installed. Run: pip install anthropic-agent-sdk"
        )

# ---------------------------------------------------------------------------
# SDK wrappers
# ---------------------------------------------------------------------------
def query(
    prompt: str,
    model: str | None = None,
    max_tokens: int | None = None,
) -> str | None:
    """Send a single query to Claude Agent.

    Args:
        prompt: The prompt text to send.
        model: Optional model override (e.g., "claude-sonnet-4-20250514").
        max_tokens: Optional max output tokens (default: SDK default).

    Returns:
        Response text, or None on failure.
    """
    if not is_available():
        logger.warning("Claude Agent not available")
        return None

    try:
        kwargs: dict[str, Any] = {"prompt": prompt}
        if model:
            kwargs["model"] = model
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens

        result = _claude_query(**kwargs)
        return str(result) if result is not None else None

    except Exception as exc:
        logger.error("Claude Agent query failed: %s", exc, exc_info=True)
        return None


def coding_query(
    task: str,
    context: str = "",
    model_override: str | None = None,
    agent_name: str = "claude_agent",
    phase: str = "",
    structured_schema: type | None = None,
) -> str | dict[str, Any] | list[Any] | None:
    """Execute a coding-oriented query, preferring Claude Agent when available.

    Falls back to the standard LLM pipeline when the SDK is not available
    or not enabled.

    Args:
        task: The coding task description.
        context: Additional context (file paths, code snippets, etc.).
        model_override: Model name override.
        agent_name: Agent name for cost tracking (LLM fallback).
        phase: Phase name for cost tracking (LLM fallback).
        structured_schema: Optional Pydantic schema for structured output.

    Returns:
        Response text (str) or structured dict/list, or None on failure.
    """
    if not is_available():
        logger.info("Claude Agent not available — falling back to LLM for 'coding_query'")
        return _llm_fallback(task, context, model_override, agent_name, phase, structured_schema)

    resolved_model = model_override or CLAUDE_AGENT_MODEL or None
    full_prompt = f"Task: {task}\n\nContext:\n{context}"

    if structured_schema is not None:
        schema_str = json.dumps(structured_schema.model_json_schema(), indent=2)
        full_prompt += (
            f"\n\nIMPORTANT: Respond with ONLY a valid JSON object matching this schema:\n{schema_str}"
        )

    result = query(full_prompt, model=resolved_model)
    if result is None:
        logger.warning("Claude Agent query returned None — falling back to LLM")
        return _llm_fallback(task, context, model_override, agent_name, phase, structured_schema)

    if structured_schema is not None:
        try:
            return json.loads(result)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Claude Agent response was not valid JSON — returning raw text")
            return result

    return result


def _llm_fallback(
    task: str,
    context: str = "",
    model_override: str | None = None,
    agent_name: str = "claude_agent",
    phase: str = "",
    structured_schema: type | None = None,
) -> str | dict[str, Any] | list[Any] | None:
    """Fallback: use the standard LLM pipeline instead of Claude Agent."""
    messages = [
        {"role": "system", "content": (
            "You are a coding assistant integrated into the MORDOR malware analysis pipeline. "
            "Complete the requested coding task precisely. Return only the code or analysis requested."
        )},
        {"role": "user", "content": f"Task: {task}\n\nContext:\n{context}"},
    ]

    if structured_schema is not None:
        result = chat_structured(
            messages,
            schema=structured_schema,
            model=model_override,
            agent_name=agent_name,
            phase=phase,
        )
        if result is not None:
            return result.model_dump()
        return None

    return chat(
        messages,
        model=model_override,
        agent_name=agent_name,
        phase=phase,
    )


def run_agent_analysis(
    binary_path: str,
    analysis_type: str = "decompile",
    agent_name: str = "claude_agent",
    phase: str = "",
) -> str | None:
    """Run a Claude Agent-assisted binary analysis task.

    Example analysis_type values: "decompile", "disassemble", "extract_strings",
    "identify_packer", "find_suspicious_calls", "trace_control_flow".

    Falls back to LLM when the SDK is unavailable.
    """
    import os

    file_size = os.path.getsize(binary_path) if os.path.exists(binary_path) else 0
    context = (
        f"Binary: {binary_path}\n"
        f"Size: {file_size} bytes\n"
        f"Analysis type: {analysis_type}\n\n"
        "Use the Claude Agent's built-in tools (Read, Edit, Bash, Glob, Grep) "
        "to analyze the binary and report findings."
    )

    return coding_query(
        task=f"Perform {analysis_type} analysis on the given binary and report findings.",
        context=context,
        agent_name=agent_name,
        phase=phase,
    )
