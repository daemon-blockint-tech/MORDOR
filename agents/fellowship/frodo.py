from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import FrodoHookSchema
from tools.frida_tools import attach_hooks as real_attach_hooks
from tools.openrouter_client import chat_structured

logger = logging.getLogger("mordor.agents.frodo")


def run_hooks(suspicious_functions: list[str], binary_path: str, tier: str = "standard") -> dict:
    if not suspicious_functions:
        return {"hooks": [], "results": [], "status": "no_functions"}

    frida_result = real_attach_hooks(binary_path, suspicious_functions)
    if frida_result.get("status") == "ok":
        return {
            "hooks": [{"function": fn, "hook_type": "interceptor"} for fn in suspicious_functions],
            "results": frida_result.get("results", []),
            "status": "ok",
        }

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are FRODO, a Frida runtime hooking agent. "
                "Given suspicious functions, describe the hooks to attach and expected observations.",
            },
            {
                "role": "user",
                "content": (
                    f"Binary: {binary_path}\n"
                    f"Suspicious functions: {suspicious_functions}\n"
                    "Describe Frida hooks: intercept parameters, return values, and stack traces."
                ),
            },
        ]
        result = chat_structured(
            messages, schema=FrodoHookSchema,
            temperature=0.3, agent_name="frodo", phase="validate",
        )
        if result is not None:
            return result.model_dump()
    return {"hooks": [], "results": [], "status": "llm_failed"}
