from __future__ import annotations

from agents.gates import skip_llm
from agents.schemas import GollumReviewSchema, load_system_prompt
from tools.openrouter_client import chat_structured


def adversarial_review(findings: list[dict], tier: str = "standard") -> dict:
    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": load_system_prompt("gollum") or (
                    "You are GOLLUM, an adversarial reviewer. "
                    "Your job: for each finding, give 3 reasons it could be BENIGN before flagging."
                ),
            },
            {
                "role": "user",
                "content": f"Review these findings for false positives: {findings}",
            },
        ]
        result = chat_structured(
            messages, schema=GollumReviewSchema,
            temperature=0.2, agent_name="gollum", phase="filter",
        )
        if result is not None:
            return result.model_dump()
    return {"benign_explanations": [], "confirmed_flags": [], "dismissed_flags": []}
