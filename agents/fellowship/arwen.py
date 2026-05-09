from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import ArwenDecodeSchema
from tools.cyberchef_tools import decode_base64, decode_hex, decode_url, try_all
from tools.openrouter_client import chat_structured

logger = logging.getLogger("mordor.agents.arwen")


def decode_payload(payload: str, encoding: str = "auto", tier: str = "standard") -> dict:
    if encoding == "base64":
        decoded = decode_base64(payload)
        if decoded:
            return {"original": payload, "decoded": decoded, "encoding_used": "base64", "decoded_type": "text", "status": "ok"}
    elif encoding == "hex":
        decoded = decode_hex(payload)
        if decoded:
            return {"original": payload, "decoded": decoded, "encoding_used": "hex", "decoded_type": "text", "status": "ok"}
    elif encoding == "url":
        decoded = decode_url(payload)
        if decoded:
            return {"original": payload, "decoded": decoded, "encoding_used": "url", "decoded_type": "text", "status": "ok"}

    if encoding == "auto":
        results = try_all(payload)
        if results:
            best = results[0]
            return {
                "original": payload,
                "decoded": best["decoded"],
                "encoding_used": best["encoding"],
                "decoded_type": "text",
                "status": "ok",
            }

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are ARWEN, a deobfuscation and decoding expert. "
                "Given an encoded or obfuscated payload, decode it and identify the encoding method.",
            },
            {
                "role": "user",
                "content": f"Decode this payload (encoding hint: {encoding}):\n{payload[:2000]}",
            },
        ]
        result = chat_structured(
            messages, schema=ArwenDecodeSchema,
            temperature=0.2, agent_name="arwen", phase="validate",
        )
        if result is not None:
            return result.model_dump()
    return {"original": payload, "decoded": "", "encoding_used": encoding, "decoded_type": "unknown", "status": "llm_failed"}
