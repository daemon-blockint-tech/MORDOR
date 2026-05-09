from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("mordor.saruman")

DEEP_ANALYSIS_PLAN_TEMPLATE = """You are SARUMAN, the Deep Analyzer. You are activated only for
CRITICAL-confidence hypotheses. Analyze the following hypothesis and provide a detailed technical
assessment:

SHA256: {sha256}
File Type: {file_type}
Hypothesis: {hypothesis}
Evidence: {evidence}

Provide:
1. Technical verification of the hypothesis
2. Potential attack chains
3. Specific functions to investigate
4. Recommended dynamic analysis hooks
"""


def build_deep_analysis_plan(
    sha256: str,
    file_type: str,
    hypotheses: list[dict[str, Any]],
    tier: str = "standard",
) -> dict[str, Any]:
    from tools.openrouter_client import chat_json

    ranked = sorted(hypotheses, key=lambda h: h.get("risk_score", 0), reverse=True)

    plan = {
        "sha256": sha256,
        "file_type": file_type,
        "tier": tier,
        "total_hypotheses": len(ranked),
        "saruman_activated": False,
        "critical_hypotheses": [],
        "analysis_plan": [],
        "investigation_functions": [],
    }

    critical = [h for h in ranked if h.get("risk_score", 0) >= 85]
    plan["critical_hypotheses"] = [
        {
            "category": h.get("category", "unknown"),
            "description": h.get("description", ""),
            "risk_score": h.get("risk_score", 0),
            "confidence": h.get("confidence", 0),
        }
        for h in critical
    ]

    if tier == "deep" or (critical and tier == "standard"):
        plan["saruman_activated"] = True
        for h in critical[:3]:
            prompt = DEEP_ANALYSIS_PLAN_TEMPLATE.format(
                sha256=sha256,
                file_type=file_type,
                hypothesis=h.get("description", ""),
                evidence="\n".join(h.get("evidence", [])),
            )
            try:
                result = chat_json(prompt)
                plan["analysis_plan"].append(result)
                for fn in result.get("functions", []):
                    plan["investigation_functions"].append(fn)
            except Exception as e:
                logger.error("SARUMAN analysis failed for hypothesis: %s", e)

    for h in ranked[:5]:
        plan["analysis_plan"].append({
            "category": h.get("category", "unknown"),
            "description": h.get("description", ""),
            "risk_score": h.get("risk_score", 0),
            "confidence": h.get("confidence", 0),
            "functions": h.get("functions", []),
        })

    return plan
