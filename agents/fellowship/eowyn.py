from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import EowynMemorySchema
from tools.openrouter_client import chat_structured
from tools.volatility_tools import analyze_dump as real_analyze_dump

logger = logging.getLogger("mordor.agents.eowyn")


def analyze_memory(dump_path: str, tier: str = "standard") -> dict:
    vol_result = real_analyze_dump(dump_path)
    if vol_result.get("status") == "ok":
        processes_text = vol_result.get("processes", "")
        return {
            "processes": [{"name": line.split()[0] if line.strip() else "unknown", "pid": "?"} for line in processes_text.split("\n") if line.strip()][:50],
            "network_connections": [],
            "registry_keys": [],
            "suspicious_indicators": [],
            "status": "ok",
        }

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are EOWYN, a memory forensics analyst using Volatility3. "
                "Given a memory dump path, describe expected findings: processes, "
                "network connections, registry keys, and suspicious indicators.",
            },
            {
                "role": "user",
                "content": f"Analyze this memory dump: {dump_path}",
            },
        ]
        result = chat_structured(
            messages, schema=EowynMemorySchema,
            temperature=0.3, agent_name="eowyn", phase="validate",
        )
        if result is not None:
            return result.model_dump()
    return {"processes": [], "network_connections": [], "registry_keys": [],
            "suspicious_indicators": [], "status": "llm_failed"}
