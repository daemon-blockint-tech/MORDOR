from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.fellowship.elrond import cross_validate
from agents.fellowship.legolas import run_static_analysis
from graph.pipeline import build_pipeline

SAMPLE_DIR = Path(__file__).resolve().parent / "samples"
BINARY = str(SAMPLE_DIR / "test_malware.x64")
BINARY_SHA256 = "ca9e240985471469d20d2b40a53df9764b47b4296ed1fa6ba4305e980fde06d7"
MIN_FUNCTIONS = 5
MIN_IMPORTS = 5
MIN_SECTIONS = 3


def test_r2_analyze_binary():
    result = run_static_analysis(BINARY, "mach-o")
    assert result.get("r2_status") == "ok", f"r2 failed: {result.get('r2_status')}"
    assert len(result.get("functions", [])) >= MIN_FUNCTIONS, f"Expected >= {MIN_FUNCTIONS} functions, got {len(result.get('functions', []))}"
    assert len(result.get("imports", [])) >= MIN_IMPORTS, f"Expected >= {MIN_IMPORTS} imports, got {len(result.get('imports', []))}"
    assert len(result.get("sections", [])) >= MIN_SECTIONS, f"Expected >= {MIN_SECTIONS} sections, got {len(result.get('sections', []))}"
    assert result.get("binary_path") == BINARY
    print(f"[PASS] r2 analyze: {len(result['functions'])} functions, {len(result['imports'])} imports, {len(result['sections'])} sections")


def test_cross_validation():
    legolas = run_static_analysis(BINARY, "mach-o")
    elrond = cross_validate(legolas)
    assert elrond.get("status") == "ok", f"ELROND failed: {elrond.get('status')}"
    assert elrond.get("agreement_score", 0) >= 0.8, f"Low agreement: {elrond.get('agreement_score')}"
    assert elrond.get("confirmed_import_count", 0) >= MIN_IMPORTS
    print(f"[PASS] cross-validation: {elrond['agreement_score']:.0%} agreement, {elrond['confirmed_import_count']} imports confirmed")


def test_pipeline_end_to_end():
    pipeline = build_pipeline()

    case_dir = tempfile.mkdtemp(prefix="mordor_smoke_")
    initial = {
        "binary_path": BINARY,
        "sha256": BINARY_SHA256,
        "case_dir": case_dir,
        "analysis_tier": "standard",
        "journal_path": f"{case_dir}/analysis_journal.jsonl",
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
        "file_size": 34160,
    }

    result = pipeline.invoke(initial, {"configurable": {"thread_id": "smoke-test"}})
    assert result.get("current_phase") == "report", f"Expected 'report', got '{result.get('current_phase')}'"
    phase_names = [pr["phase"] for pr in result.get("phase_results", [])]
    expected = ["fingerprint", "filter", "hypothesize", "map_structure", "deep_analysis", "validate", "report"]
    assert phase_names == expected, f"Phases out of order: {phase_names}"
    for pr in result.get("phase_results", []):
        assert pr.get("status") == "done", f"Phase {pr['phase']} not done: {pr}"
    print(f"[PASS] pipeline: {len(phase_names)} phases completed in order")

    metadata = result.get("artifacts", {}).get("metadata", {})
    assert metadata.get("imports_count", 0) >= MIN_IMPORTS
    assert metadata.get("sections_count", 0) >= MIN_SECTIONS
    print(f"[PASS] metadata: {metadata['imports_count']} imports, {metadata['sections_count']} sections")


if __name__ == "__main__":
    test_r2_analyze_binary()
    test_cross_validation()
    test_pipeline_end_to_end()
    print("\nAll smoke tests passed.")
