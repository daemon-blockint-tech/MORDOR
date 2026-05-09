from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

BINARY = "/bin/ls"


def test_legolas_returns_binary_path():
    from agents.fellowship.legolas import run_static_analysis
    result = run_static_analysis(BINARY)
    assert result.get("binary_path") == BINARY, "Missing binary_path"
    assert result.get("r2_status") == "ok", f"r2 failed: {result.get('r2_status')}"
    assert len(result.get("functions", [])) > 0, "No functions found"
    assert len(result.get("imports", [])) > 0, "No imports found"
    assert len(result.get("strings", [])) > 0, "No strings found"


def test_elrond_cross_validate():
    from agents.fellowship.legolas import run_static_analysis
    from agents.fellowship.elrond import cross_validate

    legolas_result = run_static_analysis(BINARY)
    elrond_result = cross_validate(legolas_result)

    assert elrond_result.get("status") == "ok", f"ELROND failed: {elrond_result.get('status')}"
    assert elrond_result.get("agreement_score", 0) > 0.5, "Low agreement score"
    assert elrond_result.get("confirmed_import_count", 0) > 0, "No imports confirmed"


def test_r2_analyze():
    from tools.radare2_mcp import analyze_binary, is_available

    assert is_available(), "radare2 not available"
    result = analyze_binary(BINARY)
    assert result.get("status") == "ok", f"r2 failed: {result.get('status')}"
    assert len(result.get("sections", [])) > 0, "No sections"
    assert len(result.get("imports", [])) > 0, "No imports"


def test_r2_call_graph():
    from tools.radare2_mcp import extract_call_graph
    result = extract_call_graph(BINARY)
    assert result.get("status") == "ok"
    assert len(result.get("nodes", [])) > 0, "No call graph nodes"


def test_r2_decompile():
    from tools.radare2_mcp import decompile_function
    result = decompile_function(BINARY, "main")
    assert result.get("status") == "ok" or result.get("status") == "error"


def test_pipeline_phases():
    from graph.nodes import (
        phase_deep_analysis,
        phase_filter,
        phase_fingerprint,
        phase_hypothesize,
        phase_map_structure,
        phase_report,
        phase_validate,
    )

    base_state = {
        "binary_path": BINARY,
        "sha256": "test-smoke",
        "case_dir": "/tmp/mordor_smoke",
        "current_phase": "fingerprint",
        "error": None,
        "error_count": 0,
        "phase_results": [],
        "hypotheses": [],
        "iocs": [],
        "artifacts": {},
        "confidence_overall": 0.0,
        "confidence_breakdown": {},
        "file_type": "mach-o",
        "file_size": None,
    }

    r = phase_fingerprint(base_state)
    assert r.goto == "filter", f"Expected filter, got {r.goto}"
    assert len(r.update["artifacts"]["imports"]) > 0

    state = {**base_state, **r.update, "phase_results": [*base_state["phase_results"], *r.update.get("phase_results", [])]}
    r = phase_filter(state)
    assert r.goto == "hypothesize"

    state = {**base_state, **r.update, "phase_results": [*state["phase_results"], *r.update.get("phase_results", [])]}
    r = phase_hypothesize(state)
    assert r.goto == "map_structure"

    state = {**base_state, **r.update, "phase_results": [*state["phase_results"], *r.update.get("phase_results", [])]}
    r = phase_map_structure(state)
    assert r.goto == "deep_analysis"

    state = {**base_state, **r.update, "phase_results": [*state["phase_results"], *r.update.get("phase_results", [])]}
    r = phase_deep_analysis(state)
    assert r.goto == "validate"

    state = {**base_state, **r.update, "phase_results": [*state["phase_results"], *r.update.get("phase_results", [])]}
    r = phase_validate(state)
    assert r.goto == "report"

    state = {**base_state, **r.update, "phase_results": [*state["phase_results"], *r.update.get("phase_results", [])]}
    r = phase_report(state)
    assert r.get("current_phase") == "report"


def test_pipeline_full_graph():
    from graph.pipeline import build_pipeline

    pipeline = build_pipeline()

    initial = {
        "binary_path": BINARY,
        "sha256": "test-graph",
        "case_dir": "/tmp/mordor_graph_test",
        "current_phase": "fingerprint",
        "error": None,
        "error_count": 0,
        "phase_results": [],
        "hypotheses": [],
        "iocs": [],
        "artifacts": {},
        "confidence_overall": 0.0,
        "confidence_breakdown": {},
        "file_type": "mach-o",
        "file_size": None,
    }

    result = pipeline.invoke(initial, {"configurable": {"thread_id": "smoke-test"}})
    assert result.get("current_phase") == "report", f"Pipeline ended at {result.get('current_phase')}"
    assert result.get("error") is None, f"Pipeline error: {result.get('error')}"


def test_artifact_writing():
    import json
    case_dir = "/tmp/mordor_artifact_test"
    from agents.fellowship.sam import write_artifact

    p1 = write_artifact(case_dir, "test_dict.json", {"key": "value"})
    assert p1.exists()
    assert json.loads(p1.read_text()) == {"key": "value"}

    p2 = write_artifact(case_dir, "test_list.json", [1, 2, 3])
    assert p2.exists()
    assert json.loads(p2.read_text()) == [1, 2, 3]

    p3 = write_artifact(case_dir, "test_str.txt", "hello")
    assert p3.exists()
    assert p3.read_text() == "hello"
