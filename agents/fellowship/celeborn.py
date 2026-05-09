"""CELEBORN — Behavioral Timeline Synthesis & Correlation Agent.

Synthesizes findings from all prior analysis phases into a coherent
chronological behavioral timeline. Groups related behaviors, identifies
coverage gaps, and produces an executive narrative summary.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("mordor.agents.celeborn")


_TIMELINE_ORDER = [
    "execution", "persistence", "defense_evasion",
    "credential_access", "discovery", "collection",
    "command_and_control", "exfiltration", "impact",
]


def build_timeline(state: dict[str, Any], tier: str = "standard") -> dict[str, Any]:
    artifacts = state.get("artifacts", {})
    hypotheses = state.get("hypotheses", [])
    phase_results = state.get("phase_results", [])

    timeline = []
    behavioral_groups = {}
    all_evidence = set()

    for h in hypotheses:
        cat = h.get("category", "unknown")
        for e in h.get("evidence", []):
            all_evidence.add(str(e))

        group = behavioral_groups.setdefault(cat, {
            "category": cat,
            "confidence": h.get("confidence", 0),
            "risk_score": h.get("risk_score", 0),
            "evidence": [],
            "functions": [],
        })
        group["evidence"].extend(h.get("evidence", []))
        group["functions"].extend(h.get("functions", []))

        timeline.append({
            "phase": cat,
            "event": h.get("description", ""),
            "confidence": h.get("confidence", 0),
            "source": "hypothesis",
            "risk_score": h.get("risk_score", 0),
        })

    for pr in phase_results:
        phase_name = pr.get("phase", "")
        for key in ("status", "signals_in", "signals_out", "count", "hooks", "iocs_found"):
            if key in pr:
                timeline.append({
                    "phase": phase_name,
                    "event": f"{key}: {pr[key]}",
                    "confidence": 100,
                    "source": "phase_result",
                    "risk_score": 0,
                })

    filtered = artifacts.get("filtered_signals", [])
    for sig in filtered:
        sig_type = sig.get("type", "unknown") if isinstance(sig, dict) else "unknown"
        sig_val = (sig.get("value") or sig.get("signal") or "") if isinstance(sig, dict) else str(sig)
        sig_cat = sig.get("category", sig_type) if isinstance(sig, dict) else "unknown"
        timeline.append({
            "phase": sig_cat,
            "event": f"[{sig_type}] {sig_val}",
            "confidence": sig.get("confidence", 50) if isinstance(sig, dict) else 50,
            "source": "filtered_signal",
            "risk_score": 0,
        })

    timeline.sort(key=lambda e: (
        _TIMELINE_ORDER.index(e["phase"]) if e["phase"] in _TIMELINE_ORDER else 99,
        -e.get("confidence", 0),
    ))

    for g in behavioral_groups.values():
        g["evidence"] = list(dict.fromkeys(g["evidence"]))[:20]
        g["functions"] = list(dict.fromkeys(g["functions"]))[:20]

    coverage_gaps = _identify_gaps(behavioral_groups, artifacts)

    narrative = _build_narrative(behavioral_groups, state)

    logger.info(
        "Celeborn: %d timeline events, %d behavioral groups, %d gaps",
        len(timeline), len(behavioral_groups), len(coverage_gaps),
    )

    return {
        "status": "ok",
        "timeline": timeline,
        "behavioral_groups": list(behavioral_groups.values()),
        "coverage_gaps": coverage_gaps,
        "narrative": narrative,
    }


def _identify_gaps(
    groups: dict[str, Any],
    artifacts: dict[str, Any],
) -> list[str]:
    gaps = []
    present = set(groups.keys())
    expected = {"persistence", "c2", "injection", "collection", "exfiltration"}
    missing = expected - present
    for m in missing:
        gaps.append(f"No {m} hypothesis — check for false negative")

    metadata = artifacts.get("metadata", {})
    if not metadata.get("network_activity") and "c2" in present:
        gaps.append("C2 suspected but no network artifacts captured")
    return gaps


def _build_narrative(
    groups: dict[str, Any],
    state: dict[str, Any],
) -> str:
    lines = []
    confidence = state.get("confidence_overall", 0)
    metadata = state.get("artifacts", {}).get("metadata", {})

    if confidence >= 85:
        lines.append(f"CRITICAL: Binary exhibits strong malicious indicators (confidence: {confidence:.0f}%).")
    elif confidence >= 50:
        lines.append(f"SUSPICIOUS: Binary shows concerning patterns (confidence: {confidence:.0f}%).")
    else:
        lines.append(f"INFO: No strong malicious indicators found (confidence: {confidence:.0f}%).")

    file_type = metadata.get("file_type", "unknown")
    lines.append(f"Type: {file_type} | SHA256: {state.get('sha256', 'unknown')[:16]}...")

    prioritized = sorted(
        groups.values(),
        key=lambda g: (g.get("risk_score", 0), g.get("confidence", 0)),
        reverse=True,
    )
    for g in prioritized:
        cat = g.get("category", "unknown")
        conf = g.get("confidence", 0)
        risk = g.get("risk_score", 0)
        evidence = g.get("evidence", [])
        funcs = g.get("functions", [])
        lines.append("")
        lines.append(f"[{cat.upper()}] confidence={conf:.0f}% risk={risk:.0f}")
        for e in evidence[:5]:
            lines.append(f"  - {e[:120]}")
        if funcs:
            lines.append(f"  functions: {', '.join(funcs[:8])}")

    return "\n".join(lines)
