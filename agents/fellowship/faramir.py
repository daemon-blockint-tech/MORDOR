from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import FaramirYARASchema
from tools.openrouter_client import chat_structured
from tools.safe_util import sanitize_for_prompt
from tools.yara_tools import scan_file

logger = logging.getLogger("mordor.agents.faramir")


def scan_with_yara(binary_path: str, rules_path: str | None = None, tier: str = "standard") -> dict:
    matches = scan_file(binary_path, rules_path)
    rules_applied = len(matches)

    if matches:
        return {"matches": matches, "rules_applied": rules_applied, "status": "ok"}

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are FARAMIR, a YARA scanning agent. "
                "The YARA engine is unavailable on this system. "
                "Describe expected rule matches and indicators for this binary.",
            },
            {
                "role": "user",
                "content": f"Describe expected YARA matches for: {sanitize_for_prompt(binary_path)}\nRules: {rules_path or 'default rules'}",
            },
        ]
        result = chat_structured(
            messages, schema=FaramirYARASchema,
            temperature=0.2, agent_name="faramir", phase="validate",
        )
        if result is not None:
            return result.model_dump()
    return {"matches": [], "rules_applied": 0, "status": "llm_failed"}
