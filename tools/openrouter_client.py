"""OpenRouter LLM client using LangChain + ChatOpenAI (OpenAI-compatible API)."""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

load_dotenv()

logger = logging.getLogger("mordor.openrouter")

# Configuration from environment
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_KEY")
GANDALF_MODEL = os.getenv("GANDALF_MODEL")
SARUMAN_MODEL = os.getenv("SARUMAN_MODEL")

# App attribution for OpenRouter
APP_NAME = "MORDOR"
APP_URL = "https://github.com/daemon-blockint-tech/MORDOR.git"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Default request timeout (seconds) per API call — prevents infinite hangs
DEFAULT_REQUEST_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Circuit breaker for structured output methods.
# Once a method fails (404 / 400 / unsupported), skip it for ALL subsequent
# calls in this process to avoid compounding 30s timeouts across 10+ agents.
# ---------------------------------------------------------------------------
_circuit_lock = threading.Lock()
_broken_methods: set[str] = set()  # e.g. {"function_calling", "json_schema"}


def _trip_breaker(method: str) -> None:
    with _circuit_lock:
        if method not in _broken_methods:
            logger.warning("Circuit breaker TRIPPED for method '%s' — skipping in future calls", method)
            _broken_methods.add(method)


def _is_broken(method: str) -> bool:
    with _circuit_lock:
        return method in _broken_methods


def reset_circuit_breaker() -> None:
    """Reset the circuit breaker (useful for tests or after model change)."""
    with _circuit_lock:
        _broken_methods.clear()
        logger.info("Circuit breaker RESET — all methods re-enabled")


# ---------------------------------------------------------------------------
# Single-turn provider workaround (Morph / Kimi K2.6)
# Morph rejects ANY request with >1 message in the messages array, including
# [system, user]. We preemptively collapse system into the first user message.
# ---------------------------------------------------------------------------
def _needs_single_turn_collapse(model: str | None) -> bool:
    """Detect models known to route through single-turn-only providers (Morph)."""
    m = (model or GANDALF_MODEL or "").lower()
    return "kimi" in m or "moonshot" in m or "morph" in m


def _collapse_messages(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    Collapse system+user messages for single-turn providers like Morph.
    Returns a single-message list: [user] with the system prompt prepended.
    """
    if len(messages) <= 1:
        return messages

    system_parts = [m.get("content", "") for m in messages if m.get("role") == "system"]
    non_system = [m for m in messages if m.get("role") != "system"]

    if not system_parts:
        return messages

    system_block = "\n\n".join(system_parts)

    result: list[dict[str, str]] = []
    prepended = False
    for msg in non_system:
        if msg.get("role") == "user" and not prepended:
            content = msg.get("content", "")
            new_content = f"[System instruction: {system_block}]\n\n{content}"
            result.append({"role": "user", "content": new_content})
            prepended = True
        else:
            result.append(msg)

    return result if prepended else messages


def get_model(
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 8192,
    timeout: int | None = None,
) -> ChatOpenAI:
    """
    Create a ChatOpenAI instance pointed at OpenRouter's API.
    
    Args:
        model: Model identifier (e.g., "openai/gpt-4o-mini", "anthropic/claude-sonnet-4.5").
               Defaults to GANDALF_MODEL from environment.
        temperature: Sampling temperature (0.0 to 1.0).
        max_tokens: Maximum tokens in the response.
        timeout: Request timeout in seconds. Defaults to DEFAULT_REQUEST_TIMEOUT.
    
    Returns:
        Configured ChatOpenAI instance pointing at OpenRouter.
    """
    if not OPENROUTER_API_KEY:
        raise ValueError(
            "OPENROUTER_API_KEY not set. Please set it in your .env file."
        )
    
    return ChatOpenAI(
        model=model or GANDALF_MODEL,
        temperature=temperature,
        max_tokens=max_tokens,
        api_key=OPENROUTER_API_KEY,
        base_url=OPENROUTER_BASE_URL,
        default_headers={
            "HTTP-Referer": APP_URL,
            "X-Title": APP_NAME,
        },
        request_timeout=timeout or DEFAULT_REQUEST_TIMEOUT,
    )


def _dicts_to_lc(messages: list[dict[str, str]]) -> list:
    """Convert dict messages to LangChain message objects."""
    lc_messages = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            lc_messages.append(SystemMessage(content=content))
        elif role == "user":
            lc_messages.append(HumanMessage(content=content))
        elif role == "assistant":
            lc_messages.append(AIMessage(content=content))
    return lc_messages


def _track_usage(response: Any, agent_name: str = "", phase: str = "") -> None:
    """Record token usage into the global cost tracker."""
    try:
        from tools.cost_tracker import get_tracker
        tracker = get_tracker()
        usage = getattr(response, "usage_metadata", None)
        if tracker:
            tracker.start_phase(agent_name=agent_name, phase=phase)
            tracker.record_usage(usage)
    except Exception:
        pass


def chat(
    messages: list[dict[str, str]],
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 8192,
    stream: bool = False,
    agent_name: str = "",
    phase: str = "",
) -> str | None:
    """
    Send a chat completion request to OpenRouter.
    
    Args:
        messages: List of message dicts with "role" and "content" keys.
        model: Model identifier. Defaults to GANDALF_MODEL.
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.
        stream: Whether to stream the response (not yet implemented).
        agent_name: Agent name for cost tracking.
        phase: Phase name for cost tracking.
    
    Returns:
        The assistant's response content, or None on error.
    """
    if not OPENROUTER_API_KEY:
        logger.warning("OPENROUTER_API_KEY not set — returning None")
        return None
    
    try:
        llm = get_model(model=model, temperature=temperature, max_tokens=max_tokens)
        prepared = _collapse_messages(messages) if _needs_single_turn_collapse(model) else messages
        lc_messages = _dicts_to_lc(prepared)
        response = llm.invoke(lc_messages)
        
        if agent_name:
            _track_usage(response, agent_name=agent_name, phase=phase)
        
        return response.content
    
    except Exception as exc:
        logger.error("OpenRouter call failed: %s", exc, exc_info=True)
        return None


def chat_json(
    messages: list[dict[str, str]],
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 8192,
    agent_name: str = "",
    phase: str = "",
) -> dict | list | None:
    """
    Send a chat completion request expecting JSON response.
    
    Args:
        messages: List of message dicts with "role" and "content" keys.
        model: Model identifier. Defaults to GANDALF_MODEL.
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.
        agent_name: Agent name for cost tracking.
        phase: Phase name for cost tracking.
    
    Returns:
        Parsed JSON response (dict or list), or None on error.
    """
    result = chat(messages, model=model, temperature=temperature, max_tokens=max_tokens,
                  agent_name=agent_name, phase=phase)
    if not result:
        return None
    
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        logger.warning("OpenRouter response was not valid JSON: %.200s", result)
        return None


def _plain_chat_to_schema(
    messages: list[dict[str, str]],
    schema: type[BaseModel],
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 8192,
    agent_name: str = "",
    phase: str = "",
) -> BaseModel | None:
    """Tier-3 fallback: plain chat() → extract JSON → validate with Pydantic schema."""
    # Append JSON instruction to the last user message
    enriched = list(messages)
    schema_hint = schema.model_json_schema()
    json_instruction = (
        "\n\nIMPORTANT: Respond with ONLY a valid JSON object matching this schema "
        "(no markdown, no extra text):\n"
        f"{json.dumps(schema_hint, indent=2)}"
    )
    if enriched and enriched[-1].get("role") == "user":
        enriched[-1] = {
            "role": "user",
            "content": enriched[-1]["content"] + json_instruction,
        }
    else:
        enriched.append({"role": "user", "content": json_instruction})

    raw = chat(
        enriched, model=model, temperature=temperature,
        max_tokens=max_tokens, agent_name=agent_name, phase=phase,
    )
    if not raw:
        return None

    # Strip markdown fences if present
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end])
            except json.JSONDecodeError:
                logger.warning("Tier-3 fallback: could not parse JSON from response")
                return None
        else:
            logger.warning("Tier-3 fallback: no JSON object found in response")
            return None

    try:
        return schema.model_validate(data)
    except Exception as exc:
        logger.warning("Tier-3 fallback: Pydantic validation failed: %s", exc)
        return None


def chat_structured(
    messages: list[dict[str, str]],
    schema: type[BaseModel],
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 8192,
    agent_name: str = "",
    phase: str = "",
    method: str = "function_calling",
) -> BaseModel | None:
    """
    Send a chat completion request with structured output using Pydantic schema.
    
    Three-tier fallback with circuit breaker:
      1. function_calling (LangChain with_structured_output)
      2. json_schema (LangChain with_structured_output)
      3. plain chat() + JSON parse + Pydantic validate
    
    Once a method fails with a provider-level error (404, 400), the circuit
    breaker trips and that method is skipped for ALL subsequent calls in
    the process — preventing compounding 30s timeouts across 10+ agents.
    
    Args:
        messages: List of message dicts with "role" and "content" keys.
        schema: Pydantic model class defining the expected output structure.
        model: Model identifier. Defaults to GANDALF_MODEL.
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.
        agent_name: Agent name for cost tracking.
        phase: Phase name for cost tracking.
        method: Preferred structured output method ("function_calling" or "json_schema").
    
    Returns:
        Instance of the schema class, or None on error.
    """
    if not OPENROUTER_API_KEY:
        logger.warning("OPENROUTER_API_KEY not set — returning None")
        return None
    
    # Build ordered method list: preferred first, then alternative
    structured_methods = [method]
    alt = "json_schema" if method == "function_calling" else "function_calling"
    structured_methods.append(alt)
    
    last_error = None

    # --- Tier 1 & 2: LangChain structured output methods ---
    for attempt_method in structured_methods:
        if _is_broken(attempt_method):
            logger.debug(
                "Skipping method='%s' (circuit breaker tripped) for agent=%s",
                attempt_method, agent_name,
            )
            continue

        try:
            llm = get_model(model=model, temperature=temperature, max_tokens=max_tokens)
            structured_llm = llm.with_structured_output(schema, method=attempt_method)
            prepared = _collapse_messages(messages) if _needs_single_turn_collapse(model) else messages
            lc_messages = _dicts_to_lc(prepared)
            response = structured_llm.invoke(lc_messages)
            
            if agent_name:
                _track_usage(response, agent_name=agent_name, phase=phase)
            
            if response is not None:
                return response
        
        except Exception as exc:
            last_error = exc
            exc_str = str(exc).lower()
            logger.warning(
                "Structured output method='%s' failed for agent=%s: %s",
                attempt_method, agent_name, exc,
            )
            # Trip breaker on provider-level failures (not transient network errors)
            if any(code in exc_str for code in ["404", "400", "not found", "not support", "multi-turn"]):
                _trip_breaker(attempt_method)
            continue

    # --- Tier 3: Plain chat + JSON parse + Pydantic validate ---
    logger.info(
        "Falling back to plain-chat JSON for agent=%s schema=%s",
        agent_name, schema.__name__,
    )
    try:
        result = _plain_chat_to_schema(
            messages, schema,
            model=model, temperature=temperature, max_tokens=max_tokens,
            agent_name=agent_name, phase=phase,
        )
        if result is not None:
            return result
    except Exception as exc:
        last_error = exc
        logger.warning("Tier-3 plain-chat fallback failed for agent=%s: %s", agent_name, exc)

    logger.error(
        "All structured output methods failed for agent=%s. Last error: %s",
        agent_name, last_error,
    )
    return None


def chat_multimodal(
    messages: list[dict[str, str]],
    image_data: list[dict[str, str]] | None = None,
    model: str | None = None,
    temperature: float = 0.3,
    max_tokens: int = 4096,
    agent_name: str = "multimodal",
    phase: str = "",
) -> str | None:
    """
    Send a multimodal chat completion with image support.
    
    Args:
        messages: List of message dicts with "role" and "content" keys.
        image_data: List of image dicts with "type" ("image_url" or "base64"),
                    "source" (url or base64 data), and optional "detail".
        model: Model identifier (must support vision).
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.
        agent_name: Agent name for cost tracking.
        phase: Phase name for cost tracking.
    
    Returns:
        The assistant's response content, or None on error.
    """
    if not OPENROUTER_API_KEY:
        logger.warning("OPENROUTER_API_KEY not set — returning None")
        return None
    
    try:
        if model is None:
            from tools.model_router import get_agent_model
            cfg = get_agent_model("multimodal")
            model = cfg.model_id
            if not cfg.supports_vision:
                logger.warning("Model %s may not support vision", model)
        
        llm = get_model(model=model, temperature=temperature, max_tokens=max_tokens)
        prepared = _collapse_messages(messages) if _needs_single_turn_collapse(model) else messages
        lc_messages = _dicts_to_lc(prepared)
        
        if image_data:
            for img in image_data:
                img_source = img.get("source", "")
                detail = img.get("detail", "auto")
                content_block = {
                    "type": "image_url",
                    "image_url": {
                        "url": img_source,
                        "detail": detail,
                    },
                }
                # Append image to the last user message
                if lc_messages and hasattr(lc_messages[-1], "content"):
                    existing = lc_messages[-1].content
                    if isinstance(existing, str):
                        from langchain_core.messages import HumanMessage
                        lc_messages[-1] = HumanMessage(content=[
                            {"type": "text", "text": existing},
                            content_block,
                        ])
        
        response = llm.invoke(lc_messages)
        
        if agent_name:
            _track_usage(response, agent_name=agent_name, phase=phase)
        
        return response.content
    
    except Exception as exc:
        logger.error("OpenRouter multimodal call failed: %s", exc, exc_info=True)
        return None


def structured_factory(
    schema: type[BaseModel],
    agent_name: str = "",
    phase: str = "",
    model: str | None = None,
    temperature: float | None = None,
) -> Any:
    """
    Factory returning a callable that sends messages and returns structured Pydantic output.
    
    Useful for LangChain expression language chains and repeated calls with the same schema.
    
    Args:
        schema: Pydantic model for structured output.
        agent_name: Agent name for cost tracking.
        phase: Phase name for cost tracking.
        model: Model identifier override.
        temperature: Temperature override.
    
    Returns:
        A callable: fn(messages: list[dict]) -> schema | None
    """
    from tools.model_router import get_agent_model
    cfg = get_agent_model(agent_name) if agent_name and not model else None
    resolved_model = model or (cfg.model_id if cfg else None)
    resolved_temp = temperature if temperature is not None else (cfg.temperature if cfg else 0.3)
    resolved_tokens = cfg.max_tokens if cfg else 2048
    
    def _call(messages: list[dict[str, str]]) -> BaseModel | None:
        return chat_structured(
            messages=messages,
            schema=schema,
            model=resolved_model,
            temperature=resolved_temp,
            max_tokens=resolved_tokens,
            agent_name=agent_name,
            phase=phase,
        )
    
    return _call
