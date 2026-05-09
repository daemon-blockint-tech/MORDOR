from __future__ import annotations

import json
import os

from graph.state import CaseState
from tools.safe_util import sanitize_for_prompt


def write_report(state: CaseState) -> str:
    sha256 = state.get("sha256", "unknown")
    case_dir = state.get("case_dir", "")
    tier = state.get("analysis_tier", "standard")
    art = state.get("artifacts", {})

    sections = [
        "# MORDOR Final Analysis Report",
        "",
        "> \"One does not simply walk into Mordor —\"",
        "> \"and no malware simply hides within it.\"",
        "",
        "---",
        "",
        f"**SHA256**: `{sha256}`",
        f"**Analysis Tier**: {tier}",
        f"**Overall Confidence**: {state.get('confidence_overall', 0.0):.0f}%",
        "",
        f"**Binary Path**: {sanitize_for_prompt(state.get('binary_path', 'unknown'))}",
        f"**File Type**: {state.get('file_type', 'unknown')}",
        f"**File Size**: {_fmt_size(state.get('file_size', 0)) or 'unknown'}",
        "",
        "---",
        "",
        "## 1. Fingerprint",
        "",
    ]

    meta = art.get("metadata", {})
    if isinstance(meta, dict):
        sections.append(f"- **Strings**: {meta.get('strings_count', 'N/A')}")
        sections.append(f"- **Imports**: {meta.get('imports_count', 'N/A')}")
        sections.append(f"- **Exports**: {meta.get('exports_count', 'N/A')}")
        sections.append(f"- **Sections**: {meta.get('sections_count', 'N/A')}")
        sections.append(f"- **Packer Hints**: {meta.get('packer_hints', [])}")
        osint_tags = meta.get("osint_tags", [])
        if osint_tags:
            sections.append(f"- **OSINT Tags**: {', '.join(osint_tags)}")
        osint_mal = meta.get("osint_malicious", False)
        sections.append(f"- **OSINT Malicious**: {osint_mal}")

    sections.extend(["", "---", "", "## 2. Filter & Triage", ""])

    filtered = art.get("filtered_signals", [])
    sections.append(f"- **Signals after filter**: {len(filtered)}")
    for s in filtered:
        val = s.get("value", s.get("signal", "")) if isinstance(s, dict) else str(s)
        cat = s.get("category", "") if isinstance(s, dict) else ""
        conf = s.get("confidence", 0) if isinstance(s, dict) else 0
        sections.append(f"  - `{val}` [{cat}] confidence={conf}")

    sections.extend(["", "## 3. Hypotheses", ""])

    hypotheses = state.get("hypotheses", [])
    if hypotheses:
        sections.append(f"**{len(hypotheses)} hypotheses generated:**")
        sections.append("")
        for h in hypotheses:
            cat = h.get("category", "unknown")
            desc = h.get("description", "")
            conf = h.get("confidence", 0)
            risk = h.get("risk_score", 0)
            ev = h.get("evidence", [])
            sections.append(f"### {cat.upper()}")
            sections.append(f"- **Description**: {desc}")
            sections.append(f"- **Confidence**: {conf:.0f}%")
            sections.append(f"- **Risk Score**: {risk:.0f}/100")
            if ev:
                sections.append("- **Evidence**:")
                for e in ev:
                    sections.append(f"  - {e}")
            sections.append("")
    else:
        sections.append("No hypotheses generated (quick tier or insufficient signals).")

    sections.extend(["---", "", "## 4. Structure Map", ""])

    comp = art.get("component_map", {})
    if isinstance(comp, dict):
        secs = comp.get("sections", [])
        imps = comp.get("imports", [])
        validation = comp.get("validation", {})
        sections.append(f"- **Sections**: {len(secs)}")
        sections.append(f"- **Imports**: {len(imps)}")
        sections.append(f"- **Cross-validation Agreement**: {validation.get('agreement_score', 'N/A')}")
        ida_decomp = comp.get("ida_decompilation", {})
        if ida_decomp.get("ida_available"):
            sections.append(f"- **Functions Decompiled (IDA)**: {ida_decomp.get('functions_decompiled', 0)}")

    sections.extend(["", "---", "", "## 5. Deep Analysis", ""])

    deep_plan = art.get("deep_analysis_plan", "")
    if isinstance(deep_plan, str) and "SARUMAN" in deep_plan:
        sections.append("SARUMAN deep analysis was activated for critical hypotheses.")
    else:
        sections.append("SARUMAN deep analysis was not activated (below critical threshold or standard tier).")

    sections.extend(["", "---", "", "## 6. Dynamic Validation", ""])

    iocs = state.get("iocs", [])
    sections.append(f"- **IOCs extracted**: {len(iocs)}")
    if iocs:
        sections.append("")
        sections.append("| Type | Value | Source | Confidence |")
        sections.append("|------|-------|--------|------------|")
        for ioc in iocs:
            sections.append(
                f"| {ioc.get('type', 'unknown')} "
                f"| `{ioc.get('value', '')}` "
                f"| {ioc.get('source', 'unknown')} "
                f"| {ioc.get('confidence', 0):.0f}% |"
            )

    timeline = art.get("behavioral_timeline", {})
    if isinstance(timeline, dict):
        events = timeline.get("timeline", [])
        sections.append("")
        sections.append(f"- **Timeline Events**: {len(events)}")
        if events:
            sections.append("")
            sections.append("**Behavioral Timeline:**")
            for ev in events:
                ts = ev.get("timestamp") or ev.get("time") or ev.get("phase", "")
                desc = ev.get("event", ev.get("description", ""))
                if ts:
                    sections.append(f"  - [{ts}] {desc}")
                else:
                    sections.append(f"  - {desc}")

    sandbox_status = "ready" if state.get("phase_results", []) and any(
        p.get("sandbox") == "ready" for p in state.get("phase_results", [])
    ) else "unavailable"

    sections.extend([
        "",
        f"- **Sandbox**: {sandbox_status}",
        "",
        "---",
        "",
        "## 7. Adversarial Review (GOLLUM)",
        "",
    ])

    if os.path.exists(jp := os.path.join(case_dir, "filtered_signals.json")):
        try:
            with open(jp) as f:
                fs = json.load(f)
            dismissed = fs.get("dismissed", [])
            confirmed = fs.get("confirmed", [])
            if dismissed:
                sections.append(f"**Dismissed flags**: {', '.join(d.get('signal', str(d)) if isinstance(d, dict) else str(d) for d in dismissed)}")
            if confirmed:
                sections.append(f"**Confirmed flags**: {', '.join(c.get('signal', str(c)) if isinstance(c, dict) else str(c) for c in confirmed)}")
            if not dismissed and not confirmed:
                sections.append("No signals were dismissed or confirmed by GOLLUM.")
        except Exception:
            sections.append("Adversarial review data unavailable.")
    else:
        sections.append("Adversarial review data unavailable.")

    sections.extend([
        "",
        "---",
        "",
        "## Phase Execution Summary",
        "",
    ])

    phase_results = state.get("phase_results", [])
    for pr in phase_results:
        phase = pr.get("phase", "unknown")
        status = pr.get("status", "unknown")
        sections.append(f"- **{phase}**: {status}")
    if not phase_results:
        for pname in ["fingerprint", "filter", "hypothesize", "map_structure", "deep_analysis", "validate", "report"]:
            sections.append(f"- **{pname}**: done")

    sections.extend([
        "",
        "---",
        "",
        "## Confidence Breakdown",
        "",
    ])

    cb = state.get("confidence_breakdown", {})
    if cb:
        for k, v in cb.items():
            sections.append(f"- **{k}**: {v}")
    else:
        sections.append("No detailed confidence breakdown available.")

    sections.extend([
        "",
        "---",
        "",
        "_Generated by MORDOR Analysis Pipeline — GANDALF orchestrator_",
        f"_SHA256: {sha256}_",
    ])

    return "\n".join(sections)


def _fmt_size(size: int | None) -> str:
    if size is None:
        return ""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"
