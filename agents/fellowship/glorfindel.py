"""GLORFINDEL — IDA Pro / Hex-Rays Deep Decompilation Agent.

Three-phase analysis:
  1. Signature — FLIRT-based known library function identification
  2. Local — Decompile functions matching suspicious patterns
  3. Full — Comprehensive decompilation of all non-library functions
"""
from __future__ import annotations

import logging
from typing import Any

from tools.hexrays_mcp import (
    analyze_binary as ida_analyze,
    decompile_function,
    is_available as ida_available,
    list_functions,
)

logger = logging.getLogger("mordor.agents.glorfindel")


def run_decompilation(
    binary_path: str,
    suspicious_functions: list[str] | None = None,
    tier: str = "standard",
) -> dict[str, Any]:
    available = ida_available()
    if not available:
        return {
            "status": "unavailable",
            "functions_decompiled": 0,
            "signatures_matched": 0,
            "decompiled_functions": [],
            "signatures": [],
            "analysis_phases_completed": [],
            "ida_available": False,
        }

    phases_completed = []
    signatures = []
    decompiled = []

    phase1 = ida_analyze(binary_path)
    if phase1.get("status") != "unavailable":
        signatures = phase1.get("signatures", [])
        if tier in ("standard", "deep") and phase1.get("signature_count", 0) > 0:
            phases_completed.append("signature")

    if tier == "deep":
        all_funcs = list_functions(binary_path)
        lib_funcs = {s.get("function", "") for s in signatures}

        targets = set()
        if suspicious_functions:
            targets.update(suspicious_functions)
        for f in all_funcs:
            fn = f.get("name", "")
            if fn and fn not in lib_funcs:
                targets.add(fn)

        for fn in list(targets)[:100]:
            result = decompile_function(binary_path, fn)
            if result.get("status") == "ok" and result.get("decompiled"):
                pseudocode = result.get("decompiled", "")
                has_suspicious = any(
                    kw in pseudocode.lower()
                    for kw in ["virtualalloc", "writeprocessmemory", "createremotethread",
                               "internetopen", "httpsendrequest", "regsetvalue",
                               "cryptdecrypt", "xorencrypt", "rc4", "base64",
                               "socket", "connect", "send", "recv"]
                )
                decompiled.append({
                    "name": fn,
                    "pseudocode": pseudocode[:2000],
                    "ast_lines": result.get("ast_lines", [])[:50],
                    "suspicious": has_suspicious,
                })

        phases_completed.append("full")
    elif tier == "standard":
        if suspicious_functions:
            for fn in suspicious_functions[:30]:
                result = decompile_function(binary_path, fn)
                if result.get("status") == "ok" and result.get("decompiled"):
                    decompiled.append({
                        "name": fn,
                        "pseudocode": result["decompiled"][:2000],
                        "ast_lines": result.get("ast_lines", [])[:50],
                        "suspicious": True,
                    })
        phases_completed.append("local")

    suspicious_count = sum(1 for d in decompiled if d.get("suspicious"))
    logger.info(
        "Glorfindel: %d functions decompiled, %d suspicious, %d sigs, phases=%s",
        len(decompiled), suspicious_count, len(signatures), phases_completed,
    )

    return {
        "status": "ok",
        "functions_decompiled": len(decompiled),
        "signatures_matched": len(signatures),
        "decompiled_functions": decompiled,
        "signatures": signatures,
        "analysis_phases_completed": phases_completed,
        "ida_available": True,
    }
