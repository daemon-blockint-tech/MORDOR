from __future__ import annotations

from agents.gates import skip_llm
from agents.schemas import BoromirTriageSchema, load_system_prompt
from tools.openrouter_client import chat_structured


def triage(signals: list[dict], tier: str = "standard") -> dict:
    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": load_system_prompt("boromir") or (
                    "You are BOROMIR, a triage and confidence-scoring agent. "
                    "Given a list of signals from binary analysis, filter out noise and "
                    "assign confidence scores."
                ),
            },
            {
                "role": "user",
                "content": f"Triage these signals: {signals}",
            },
        ]
        result = chat_structured(
            messages, schema=BoromirTriageSchema,
            temperature=0.2, agent_name="boromir", phase="filter",
        )
        if result is not None:
            return result.model_dump()
    return {"filtered_signals": [], "confidence_score": 0.0, "classification": "info"}
