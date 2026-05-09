"""OpenCode SDK adapter — optional coding-agent integration.

Communicates with a running OpenCode server via its HTTP REST API
(https://opencode.ai/docs/sdk/). The OpenCode SDK is TypeScript/JS;
this adapter provides Python wrappers.

Gate check: OPENCODE_ENABLED=true in .env (default: disabled).
Server expected at the URL configured by OPENCODE_URL (default: http://127.0.0.1:4096).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx
from dotenv import load_dotenv

from tools.openrouter_client import chat, chat_structured

load_dotenv()

logger = logging.getLogger("mordor.tools.opencode")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPENCODE_ENABLED = os.getenv("OPENCODE_ENABLED", "").lower() in ("1", "true", "yes")
OPENCODE_URL = os.getenv("OPENCODE_URL", "http://127.0.0.1:4096")
OPENCODE_TIMEOUT = int(os.getenv("OPENCODE_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Gate check
# ---------------------------------------------------------------------------
def is_available() -> bool:
    """Check if OpenCode integration is enabled AND the server is reachable."""
    if not OPENCODE_ENABLED:
        return False
    try:
        resp = httpx.get(f"{OPENCODE_URL}/health", timeout=OPENCODE_TIMEOUT)
        return resp.status_code == 200
    except Exception as exc:
        logger.debug("OpenCode server not reachable at %s: %s", OPENCODE_URL, exc)
        return False


def ensure_available() -> None:
    """Raise RuntimeError if OpenCode is not available."""
    if not is_available():
        raise RuntimeError(
            "OpenCode is not available. Set OPENCODE_ENABLED=true and ensure "
            f"the server is running at {OPENCODE_URL}."
        )

# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------
def create_session(title: str = "MORDOR analysis task") -> str | None:
    """Create a new OpenCode session and return its ID, or None on failure."""
    try:
        resp = httpx.post(
            f"{OPENCODE_URL}/sessions",
            json={"title": title},
            timeout=OPENCODE_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        session_id = data.get("id")
        logger.info("OpenCode session created: %s", session_id)
        return session_id
    except Exception as exc:
        logger.warning("OpenCode create_session failed: %s", exc)
        return None


def send_prompt(
    session_id: str,
    prompt: str,
    structured_schema: dict[str, Any] | None = None,
) -> str | None:
    """Send a prompt to an existing OpenCode session.

    Args:
        session_id: OpenCode session ID.
        prompt: Text prompt to send.
        structured_schema: Optional JSON schema for structured output.

    Returns:
        The assistant's response text, or None on failure.
    """
    body: dict[str, Any] = {
        "parts": [{"type": "text", "text": prompt}],
    }
    if structured_schema:
        body["format"] = {"type": "json_schema", "schema": structured_schema}

    try:
        resp = httpx.post(
            f"{OPENCODE_URL}/sessions/{session_id}/prompt",
            json=body,
            timeout=OPENCODE_TIMEOUT * 3,  # prompts may take longer
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("content") or json.dumps(data.get("info", {}))
    except Exception as exc:
        logger.warning("OpenCode send_prompt failed: %s", exc)
        return None


def list_sessions() -> list[dict[str, Any]]:
    """List all OpenCode sessions."""
    try:
        resp = httpx.get(f"{OPENCODE_URL}/sessions", timeout=OPENCODE_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("OpenCode list_sessions failed: %s", exc)
        return []


def delete_session(session_id: str) -> bool:
    """Delete an OpenCode session."""
    try:
        resp = httpx.delete(
            f"{OPENCODE_URL}/sessions/{session_id}",
            timeout=OPENCODE_TIMEOUT,
        )
        return resp.status_code == 200
    except Exception as exc:
        logger.warning("OpenCode delete_session failed: %s", exc)
        return False

# ---------------------------------------------------------------------------
# Integrated coding-query helper (used by agents)
# ---------------------------------------------------------------------------
def coding_query(
    task: str,
    context: str = "",
    model_override: str | None = None,
    agent_name: str = "opencode",
    phase: str = "",
    structured_schema: type | None = None,
) -> str | dict[str, Any] | list[Any] | None:
    """Execute a coding-oriented query, preferring OpenCode when available.

    Falls back to the standard LLM chat() / chat_structured() pipeline
    when the OpenCode server is not running or not enabled.

    Args:
        task: The coding task description.
        context: Additional context (file paths, code snippets, etc.).
        model_override: Model name override (passed to LLM fallback).
        agent_name: Agent name for cost tracking (LLM fallback).
        phase: Phase name for cost tracking (LLM fallback).
        structured_schema: Optional Pydantic schema for structured output.

    Returns:
        Response text (str) or structured dict/list, or None on failure.
    """
    if not is_available():
        logger.info("OpenCode not available — falling back to LLM for 'coding_query'")
        return _llm_fallback(task, context, model_override, agent_name, phase, structured_schema)

    session_id = create_session(f"MORDOR {agent_name} — {task[:60]}")
    if not session_id:
        logger.warning("OpenCode session creation failed — falling back to LLM")
        return _llm_fallback(task, context, model_override, agent_name, phase, structured_schema)

    try:
        prompt_parts = [f"Task: {task}"]
        if context:
            prompt_parts.append(f"Context:\n{context}")

        schema_dict = None
        if structured_schema is not None:
            schema_dict = structured_schema.model_json_schema()

        full_prompt = "\n\n".join(prompt_parts)
        result = send_prompt(session_id, full_prompt, structured_schema=schema_dict)

        if result is None:
            return _llm_fallback(task, context, model_override, agent_name, phase, structured_schema)

        # Try to parse as JSON if structured output was requested
        if structured_schema is not None and result:
            try:
                return json.loads(result)
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    finally:
        # Clean up the session to avoid cluttering the server
        delete_session(session_id)


def _llm_fallback(
    task: str,
    context: str = "",
    model_override: str | None = None,
    agent_name: str = "opencode",
    phase: str = "",
    structured_schema: type | None = None,
) -> str | dict[str, Any] | list[Any] | None:
    """Fallback: use the standard LLM pipeline instead of OpenCode."""
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


def run_opencode_analysis(
    binary_path: str,
    analysis_type: str = "decompile",
    agent_name: str = "opencode",
    phase: str = "",
) -> str | None:
    """Run an OpenCode-assisted binary analysis task.

    Example analysis_type values: "decompile", "disassemble", "extract_strings",
    "identify_packer", "find_suspicious_calls".

    Falls back to LLM when OpenCode server is unavailable.
    """
    import os

    file_size = os.path.getsize(binary_path) if os.path.exists(binary_path) else 0
    context = (
        f"Binary: {binary_path}\n"
        f"Size: {file_size} bytes\n"
        f"Analysis type: {analysis_type}\n\n"
        "Available tools: grep, strings, xxd, file, objdump (if on Linux)"
    )

    return coding_query(
        task=f"Perform {analysis_type} analysis on the given binary and report findings.",
        context=context,
        agent_name=agent_name,
        phase=phase,
    )
