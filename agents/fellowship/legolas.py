from __future__ import annotations

import logging

from agents.gates import skip_llm
from agents.schemas import LegolasAnnotationSchema, load_system_prompt
from tools.openrouter_client import chat_structured
from tools.radare2_mcp import analyze_binary as r2_analyze

logger = logging.getLogger("mordor.agents.legolas")


def run_static_analysis(binary_path: str, file_type: str | None = None, tier: str = "standard") -> dict:
    r2_result = r2_analyze(binary_path)
    r2_ok = r2_result.get("status") == "ok"

    file_hint = f" (type: {file_type})" if file_type else ""
    llm_result = chat_structured(
        [
            {
                "role": "system",
                "content": load_system_prompt("legolas") or (
                    "You are LEGOLAS, a static analysis expert. "
                    "Given radare2 analysis results, annotate suspicious indicators."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Annotate this binary: {binary_path}{file_hint}\n"
                    f"Functions: {len(r2_result.get('functions', []))}\n"
                    f"Imports: {[i.get('name','') for i in r2_result.get('imports', [])[:20]]}\n"
                    f"Sections: {[s.get('name','') for s in r2_result.get('sections', [])]}\n"
                    f"Strings sample: {[s.get('value','') for s in r2_result.get('strings', [])[:15]]}"
                ),
            },
        ],
        schema=LegolasAnnotationSchema,
        temperature=0.2,
        agent_name="legolas",
        phase="fingerprint",
    ) if r2_ok and not skip_llm(tier) else None

    r2_info = r2_result.get("info", {})
    detected_type = file_type or r2_info.get("type") or r2_info.get("format") or r2_info.get("bintype")

    result = {
        "binary_path": binary_path,
        "sections": r2_result.get("sections", []),
        "functions": r2_result.get("functions", []),
        "imports": r2_result.get("imports", []),
        "exports": r2_result.get("exports", []),
        "strings": r2_result.get("strings", []),
        "file_type": detected_type,
        "crypto_constants": [],
        "packer_hints": [],
        "r2_status": r2_result.get("status"),
    }

    if llm_result:
        result["crypto_constants"] = llm_result.crypto_constants
        result["packer_hints"] = llm_result.packer_hints
        result["annotations"] = llm_result.annotations
    else:
        result["annotations"] = []

    return result
