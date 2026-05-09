from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from langgraph.types import Command

from agents.analysis_journal import AnalysisJournal
from agents.fellowship import (
    adversarial_review,
    audit_dependencies,
    build_timeline,
    cross_validate,
    decode_payload,
    export_sigma,
    export_stix2,
    export_yara,
    run_decompilation,
    run_hooks,
    run_in_sandbox,
    run_osint,
    run_static_analysis,
    scan_with_yara,
    trace_binary,
    triage,
    verify_sandbox,
    write_artifact as write_case_artifact,
    write_report,
    analyze_with_ida,
)
from agents.gates import needs_extra_validation, skip_llm
from agents.schemas import load_system_prompt
from graph.edges import route_by_tier
from graph.state import CaseState
from tools.openrouter_client import chat_json


def phase_fingerprint(state: CaseState) -> Command[Literal["filter", "report", "error"]]:
    case_dir = state["case_dir"]
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(case_dir)
    Path(case_dir).mkdir(parents=True, exist_ok=True, mode=0o750)

    with journal.timed(agent="aragorn", phase="fingerprint", tier=tier, action="osint", tool_used="shodan"):
        aragorn_result = run_osint(state["sha256"], tier=tier)

    with journal.timed(agent="legolas", phase="fingerprint", tier=tier, action="static_analysis", tool_used="radare2"):
        legolas_result = run_static_analysis(state["binary_path"], state.get("file_type"), tier=tier)

    with journal.timed(agent="merry", phase="fingerprint", tier=tier, action="audit_dependencies", tool_used="otool"):
        merry_result = audit_dependencies(state["binary_path"], tier=tier)

    raw_strings = legolas_result.get("strings", [])
    imports = legolas_result.get("imports", [])
    exports = legolas_result.get("exports", [])
    sections = legolas_result.get("sections", [])
    crypto_indicators = legolas_result.get("crypto_constants", [])
    packer_hints = legolas_result.get("packer_hints", [])

    metadata = {
        "sha256": state["sha256"],
        "file_type": state.get("file_type") or legolas_result.get("file_type") or "unknown",
        "file_size": state.get("file_size"),
        "strings_count": len(raw_strings),
        "imports_count": len(imports),
        "exports_count": len(exports),
        "sections_count": len(sections),
        "packer_hints": packer_hints,
        "osint_tags": aragorn_result.get("tags", []),
        "osint_malicious": aragorn_result.get("threat_intel", {}).get("malicious", False),
    }

    write_case_artifact(case_dir, "metadata.json", metadata)
    write_case_artifact(
        case_dir,
        "raw_strings.txt",
        "\n".join(
            s["value"] if isinstance(s, dict) else str(s) for s in raw_strings
        ),
    )
    write_case_artifact(case_dir, "imports.json", imports)
    write_case_artifact(
        case_dir,
        "crypto_indicators.txt",
        "\n".join(str(c) for c in crypto_indicators),
    )

    journal.record(agent="gandalf", phase="fingerprint", tier=tier, action="complete", status="ok",
                   result_summary=f"fingerprint done: {len(raw_strings)} strings, {len(imports)} imports, {len(sections)} sections")

    return Command(
        update={
            "phase_results": [
                {
                    "phase": "fingerprint",
                    "status": "done",
                    "osint": aragorn_result,
                    "static": legolas_result,
                    "deps": merry_result,
                }
            ],
            "file_type": state.get("file_type") or legolas_result.get("file_type") or "unknown",
            "artifacts": {
                "metadata": metadata,
                "raw_strings": raw_strings,
                "imports": imports,
                "crypto_indicators": crypto_indicators,
            },
        },
        goto=route_by_tier(state),
    )


def phase_filter(state: CaseState) -> Command[Literal["hypothesize", "error"]]:
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(state["case_dir"])
    artifacts = state.get("artifacts", {})
    signals = []

    for imp in artifacts.get("imports", []):
        name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
        signals.append({"type": "import", "value": name})

    for string in artifacts.get("raw_strings", []):
        val = string.get("value", "") if isinstance(string, dict) else str(string)
        if any(kw in val.lower() for kw in ["http", "encrypt", "decrypt", "api.", "socket"]):
            signals.append({"type": "string", "value": val})

    with journal.timed(agent="boromir", phase="filter", tier=tier, action="triage", llm_called=not skip_llm(tier)):
        boromir_result = triage(signals, tier=tier)

    with journal.timed(agent="gollum", phase="filter", tier=tier, action="adversarial_review", llm_called=not skip_llm(tier)):
        gollum_result = adversarial_review(boromir_result.get("filtered_signals", []), tier=tier)

    filtered = boromir_result.get("filtered_signals", [])
    dismissed = gollum_result.get("dismissed_flags", [])
    confirmed = gollum_result.get("confirmed_flags", [])
    final_signals = [s for s in filtered if s.get("signal") not in dismissed]

    confidence = max(0.0, min(100.0, float(boromir_result.get("confidence_score", 0.0))))

    write_case_artifact(state["case_dir"], "filtered_signals.json", {
        "signals": final_signals,
        "dismissed": dismissed,
        "confirmed": confirmed,
        "confidence": confidence,
    })

    journal.record(agent="gandalf", phase="filter", tier=tier, action="complete", status="ok",
                   result_summary=f"filter: {len(signals)} in, {len(final_signals)} out, {len(dismissed)} dismissed")

    return Command(
        update={
            "phase_results": [
                {
                    "phase": "filter",
                    "status": "done",
                    "signals_in": len(signals),
                    "signals_out": len(final_signals),
                    "dismissed": len(dismissed),
                }
            ],
            "artifacts": {
                **artifacts,
                "filtered_signals": final_signals,
            },
            "confidence_overall": confidence,
        },
        goto="hypothesize",
    )


def phase_hypothesize(state: CaseState) -> Command[Literal["map_structure", "error"]]:
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(state["case_dir"])
    filtered = state.get("artifacts", {}).get("filtered_signals", [])
    metadata = state.get("artifacts", {}).get("metadata", {})

    if not skip_llm(tier):
        system_content = load_system_prompt("gandalf") or "You are GANDALF, malware analysis orchestrator."
        prompt = (
            f"SHA256: {state['sha256']}\n"
            f"File type: {metadata.get('file_type', 'unknown')}\n"
            f"Filtered signals ({len(filtered)}): {json.dumps(filtered[:30])}\n\n"
            "Build hypotheses per category: persistence, c2, injection, collection, exfiltration.\n"
            "Return JSON array: [{ \"category\": str, \"description\": str, "
            "\"confidence\": float (0-100), \"evidence\": [str], "
            "\"functions\": [str], \"risk_score\": float (0-100) }]"
        )

        with journal.timed(agent="gandalf", phase="hypothesize", tier=tier, action="generate_hypotheses", llm_called=True):
            result = chat_json(
                [{"role": "system", "content": system_content},
                 {"role": "user", "content": prompt}],
                temperature=0.3,
            )
        hypotheses = result if isinstance(result, list) else []
    else:
        hypotheses = []
        journal.record(agent="gandalf", phase="hypothesize", tier=tier, action="generate_hypotheses", status="skipped",
                       result_summary="LLM skipped in QUICK tier")

    with journal.timed(agent="boromir", phase="hypothesize", tier=tier, action="triage_hypotheses", llm_called=not skip_llm(tier)):
        boromir_result = triage(hypotheses, tier=tier)
    overall_conf = max(0.0, min(100.0, float(boromir_result.get("confidence_score", 50.0))))

    md_lines = ["# MORDOR Analysis Hypotheses", ""]
    for h in hypotheses:
        md_lines.append(f"## {h.get('category', 'unknown').upper()}")
        md_lines.append(f"**Description**: {h.get('description', '')}")
        md_lines.append(f"**Confidence**: {h.get('confidence', 0):.0f}%")
        md_lines.append(f"**Risk Score**: {h.get('risk_score', 0):.0f}")
        if h.get("evidence"):
            md_lines.append("**Evidence**:")
            for e in h["evidence"]:
                md_lines.append(f"  - {e}")
        md_lines.append("")

    write_case_artifact(state["case_dir"], "hypotheses.md", "\n".join(md_lines))

    journal.record(agent="gandalf", phase="hypothesize", tier=tier, action="complete", status="ok",
                   result_summary=f"hypothesize: {len(hypotheses)} hypotheses generated")

    return Command(
        update={
            "phase_results": [{"phase": "hypothesize", "status": "done", "count": len(hypotheses)}],
            "hypotheses": hypotheses,
            "confidence_overall": overall_conf,
        },
        goto="map_structure",
    )


def phase_map_structure(state: CaseState) -> Command[Literal["deep_analysis", "error"]]:
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(state["case_dir"])

    with journal.timed(agent="legolas", phase="map_structure", tier=tier, action="static_analysis", tool_used="radare2"):
        legolas_result = run_static_analysis(state["binary_path"], state.get("file_type"), tier=tier)
    elrond_result = cross_validate(legolas_result)

    with journal.timed(agent="glorfindel", phase="map_structure", tier=tier, action="ida_decompile", tool_used="hexrays"):
        hypotheses = state.get("hypotheses", [])
        suspicious = list({fn for h in hypotheses for fn in h.get("functions", [])})
        glorfindel_result = run_decompilation(state["binary_path"], suspicious_functions=suspicious, tier=tier)

    with journal.timed(agent="galadriel", phase="map_structure", tier=tier, action="ida_extract", tool_used="idapython"):
        galadriel_result = analyze_with_ida(state["binary_path"], state.get("file_type"), tier=tier)

    component_map = {
        "sections": legolas_result.get("sections", []),
        "imports": legolas_result.get("imports", []),
        "exports": legolas_result.get("exports", []),
        "functions_analyzed": len(legolas_result.get("strings", [])),
        "validation": elrond_result,
        "ida_decompilation": {
            "status": glorfindel_result.get("status", "unavailable"),
            "functions_decompiled": glorfindel_result.get("functions_decompiled", 0),
            "signatures_matched": glorfindel_result.get("signatures_matched", 0),
            "ida_available": glorfindel_result.get("ida_available", False),
        },
        "ida_extraction": galadriel_result,
    }

    dot_lines = ["digraph call_graph {"]
    for section in legolas_result.get("sections", []):
        name = section.get("name", "unknown") if isinstance(section, dict) else str(section)
        dot_lines.append(f'    "{name}" [shape=box];')
    for imp in legolas_result.get("imports", []):
        name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
        dot_lines.append(f'    "binary" -> "{name}";')
    dot_lines.append("}")

    write_case_artifact(state["case_dir"], "component_map.json", component_map)
    write_case_artifact(state["case_dir"], "call_graph.dot", "\n".join(dot_lines))

    journal.record(agent="gandalf", phase="map_structure", tier=tier, action="complete", status="ok",
                   result_summary=f"map_structure: {len(component_map['sections'])} sections, agreement {elrond_result.get('agreement_score', 0):.0%}, ida={glorfindel_result.get('status', 'unavailable')}")

    return Command(
        update={
            "phase_results": [
                {
                    "phase": "map_structure",
                    "status": "done",
                    "sections": len(legolas_result.get("sections", [])),
                    "agreement": elrond_result.get("agreement_score", 0),
                    "ida_decompiled": glorfindel_result.get("functions_decompiled", 0),
                }
            ],
            "artifacts": {
                **state.get("artifacts", {}),
                "component_map": component_map,
                "call_graph": "\n".join(dot_lines),
                "ida_analysis": glorfindel_result,
            },
            "confidence_breakdown": {
            "cross_validation": elrond_result.get("agreement_score", 0) or elrond_result.get("agreement_score", 0),
        },
        },
        goto="deep_analysis",
    )


def phase_deep_analysis(state: CaseState) -> Command[Literal["validate", "error"]]:
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(state["case_dir"])
    hypotheses = state.get("hypotheses", [])

    suspicious = sorted(
        hypotheses,
        key=lambda h: (h.get("risk_score", 0), h.get("confidence", 0)),
        reverse=True,
    )

    md_lines = ["# Deep Analysis Plan", ""]
    md_lines.append(f"**Overall Confidence**: {state.get('confidence_overall', 0):.0f}%")
    md_lines.append(f"**Tier**: {tier}")
    md_lines.append("")
    md_lines.append("## Ranked Hypotheses (by risk score)")
    md_lines.append("")

    for rank, h in enumerate(suspicious, 1):
        md_lines.append(f"### {rank}. {h.get('category', 'unknown')}")
        md_lines.append(f"- **Risk**: {h.get('risk_score', 0):.0f}/100")
        md_lines.append(f"- **Confidence**: {h.get('confidence', 0):.0f}%")
        md_lines.append(f"- **Description**: {h.get('description', '')}")
        if h.get("evidence"):
            md_lines.append("- **Evidence**:")
            for e in h["evidence"]:
                md_lines.append(f"  - {e}")
        md_lines.append("")

    md_lines.append("## Functions to Investigate")
    for h in suspicious:
        for fn in h.get("functions", []):
            md_lines.append(f"- `{fn}`")

    saruman_analysis = None
    if needs_extra_validation(tier) and suspicious:
        from agents.fellowship.saruman import analyze_with_structured_output

        critical = [h for h in suspicious if h.get("confidence", 0) >= 85]
        if critical:
            with journal.timed(agent="saruman", phase="deep_analysis", tier=tier, action="deep_analyze_critical", llm_called=True):
                saruman_analysis = analyze_with_structured_output(
                    binary_path=state["binary_path"],
                    hypotheses=critical,
                    tier=tier,
                )
            md_lines.append("")
            md_lines.append("## SARUMAN Deep Analysis (CRITICAL)")
            if saruman_analysis:
                md_lines.append(str(saruman_analysis))

    write_case_artifact(state["case_dir"], "deep_analysis_plan.md", "\n".join(md_lines))

    journal.record(agent="gandalf", phase="deep_analysis", tier=tier, action="complete", status="ok",
                   result_summary=f"deep_analysis: {len(suspicious)} ranked, saruman={'yes' if saruman_analysis else 'no'}")

    return Command(
        update={
            "phase_results": [
                {
                    "phase": "deep_analysis",
                    "status": "done",
                    "hypotheses_ranked": len(suspicious),
                    "saruman_activated": saruman_analysis is not None,
                }
            ],
            "artifacts": {
                **state.get("artifacts", {}),
                "deep_analysis_plan": "\n".join(md_lines),
            },
        },
        goto="validate",
    )


def phase_validate(state: CaseState) -> Command[Literal["report", "error"]]:
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(state["case_dir"])
    artifacts = state.get("artifacts", {})
    hypotheses = state.get("hypotheses", [])

    suspicious_functions = []
    for h in hypotheses:
        suspicious_functions.extend(h.get("functions", []))
    suspicious_functions = list(set(suspicious_functions))

    sandbox_ready = verify_sandbox()
    sandbox_status = "ready" if sandbox_ready else "unavailable"

    with journal.timed(agent="frodo", phase="validate", tier=tier, action="run_hooks", tool_used="frida", llm_called=not skip_llm(tier)):
        frida_result = run_hooks(suspicious_functions, state["binary_path"], tier=tier)

    with journal.timed(agent="gimli", phase="validate", tier=tier, action="trace_binary", tool_used="x64dbg", llm_called=not skip_llm(tier)):
        trace_binary(state["binary_path"], tier=tier)

    with journal.timed(agent="faramir", phase="validate", tier=tier, action="scan_yara", tool_used="yara", llm_called=not skip_llm(tier)):
        faramir_result = scan_with_yara(state["binary_path"], tier=tier)

    if sandbox_ready:
        with journal.timed(agent="treebeard", phase="validate", tier=tier, action="run_sandbox", tool_used="docker", llm_called=not skip_llm(tier)):
            run_in_sandbox(state["binary_path"], tier=tier)

    decoded = []
    for signal in artifacts.get("filtered_signals", []):
        val = (signal.get("value") or "") if isinstance(signal, dict) else str(signal)
        if any(enc in val for enc in ["==", "0x", "\\x"]):
            d = decode_payload(val, tier=tier)
            if d.get("decoded"):
                decoded.append(d)

    iocs = []
    for signal in artifacts.get("filtered_signals", []):
        val = (signal.get("value") or signal.get("signal") or "") if isinstance(signal, dict) else str(signal)
        iocs.append({"value": val, "type": "url" if val.startswith("http") else "file_path", "source": "filter", "confidence": signal.get("confidence", 50) if isinstance(signal, dict) else 50, "tags": [signal.get("category", "unknown")] if isinstance(signal, dict) else ["unknown"]})
    for h in hypotheses:
        for e in h.get("evidence", []):
            if e not in [i["value"] for i in iocs]:
                iocs.append({"value": e, "type": "file_path", "source": "hypothesis", "confidence": h.get("confidence", 50), "tags": [h.get("category", "unknown")]})

    if needs_extra_validation(tier) and hypotheses:
        from agents.fellowship.saruman import generate_mitre_mapping

        with journal.timed(agent="saruman", phase="validate", tier=tier, action="mitre_mapping", llm_called=True):
            mitre_result = generate_mitre_mapping(hypotheses, tier=tier)
        if mitre_result:
            write_case_artifact(state["case_dir"], "mitre_mapping.json", mitre_result)

    with journal.timed(agent="celeborn", phase="validate", tier=tier, action="build_timeline", llm_called=not skip_llm(tier)):
        timeline_result = build_timeline(dict(state), tier=tier)

    write_case_artifact(state["case_dir"], "frida_hooks.log", str(frida_result))
    write_case_artifact(state["case_dir"], "yara_hits.txt", str(faramir_result))
    write_case_artifact(state["case_dir"], "decoded_payloads.json", decoded)
    write_case_artifact(state["case_dir"], "behavioral_timeline.json", timeline_result)

    journal.record(agent="gandalf", phase="validate", tier=tier, action="complete", status="ok",
                   result_summary=f"validate: sandbox={sandbox_status}, hooks={frida_result.get('hooks_attached', 0)}, iocs={len(iocs)}, timeline={len(timeline_result.get('timeline', []))} events")

    return Command(
        update={
            "phase_results": [
                {
                    "phase": "validate",
                    "status": "done",
                    "sandbox": sandbox_status,
                    "hooks": frida_result.get("hooks_attached", 0),
                    "iocs_found": len(iocs),
                }
            ],
            "iocs": iocs,
            "artifacts": {
                **artifacts,
                "frida_hooks_log": str(frida_result),
                "decoded_payloads": decoded,
                "behavioral_timeline": timeline_result,
            },
        },
        goto="report",
    )


def phase_report(state: CaseState) -> dict:
    tier = state.get("analysis_tier", "standard")
    journal = AnalysisJournal(state["case_dir"])

    report = write_report(state)

    write_case_artifact(state["case_dir"], "final_report.md", report)

    iocs = state.get("iocs", [])
    if iocs:
        stix = export_stix2(iocs)
        yara = export_yara(iocs)
        sigma = export_sigma(iocs)
        write_case_artifact(state["case_dir"], "ioc_stix2.json", stix)
        write_case_artifact(state["case_dir"], "ioc_yara.yar", yara)
        write_case_artifact(state["case_dir"], "ioc_sigma.yml", sigma)

    journal.record(agent="gandalf_white", phase="report", tier=tier, action="write_report", status="ok",
                   result_summary=f"report generated, {len(iocs)} IoCs exported")

    summary = journal.summary()
    write_case_artifact(state["case_dir"], "analysis_journal_summary.json", summary)

    return {
        "current_phase": "report",
        "phase_results": [{"phase": "report", "status": "done"}],
        "artifacts": {**state.get("artifacts", {}), "final_report": report},
    }


def handle_error(state: CaseState) -> dict:
    error_count = state.get("error_count", 0) + 1
    if error_count >= 3:
        import logging
        logger = logging.getLogger("mordor.pipeline")
        logger.critical(f"PIPELINE ALERT: Repeated component failures detected (count: {error_count}). Halting analysis.")
        return {"current_phase": "error", "error_count": error_count}
        
    return {
        "current_phase": "error" if error_count >= 3 else "done",
        "error_count": error_count,
    }
