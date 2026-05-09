from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

BINARY = "tests/samples/test_malware.x64"
SHA256 = "ca9e240985471469d20d2b40a53df9764b47b4296ed1fa6ba4305e980fde06d7"


def _base_state(**overrides) -> dict:
    state = {
        "binary_path": BINARY,
        "sha256": SHA256,
        "case_dir": tempfile.mkdtemp(prefix="mordor_test_"),
        "analysis_tier": "quick",
        "journal_path": "/tmp/mordor_test_journal.jsonl",
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
    state.update(overrides)
    return state


# ── Routing tests ──────────────────────────────────────────────────────────


def test_route_by_tier_quick():
    from graph.edges import route_by_tier

    s = _base_state(analysis_tier="quick")
    assert route_by_tier(s) == "report"


def test_route_by_tier_standard():
    from graph.edges import route_by_tier

    s = _base_state(analysis_tier="standard")
    assert route_by_tier(s) == "filter"


def test_route_by_tier_deep():
    from graph.edges import route_by_tier

    s = _base_state(analysis_tier="deep")
    assert route_by_tier(s) == "filter"


def test_route_by_tier_default():
    from graph.edges import route_by_tier

    assert route_by_tier({}) == "filter"


def test_should_skip_deep_analysis_low_confidence():
    from graph.edges import should_skip_deep_analysis

    s = _base_state(confidence_overall=30.0, hypotheses=[])
    assert should_skip_deep_analysis(s) == "validate"


def test_should_skip_deep_analysis_high_confidence():
    from graph.edges import should_skip_deep_analysis

    s = _base_state(confidence_overall=80.0)
    s["hypotheses"] = [{"category": "c2", "confidence": 90, "risk_score": 85}]
    assert should_skip_deep_analysis(s) == "deep_analysis"


def test_route_after_error():
    from graph.edges import route_after_error

    s = _base_state(current_phase="filter", error_count=1)
    assert route_after_error(s) == "filter"


def test_route_after_error_maxed():
    from graph.edges import route_after_error

    s = _base_state(error_count=3)
    assert route_after_error(s) == "error"


def test_route_after_error_unknown_phase():
    from graph.edges import route_after_error

    s = _base_state(current_phase="nonexistent")
    assert route_after_error(s) == "fingerprint"


# ── Pipeline routing (quick tier skips LLM nodes) ─────────────────────────


def test_quick_tier_only_two_nodes():
    from graph.pipeline import build_pipeline

    pipeline = build_pipeline()
    initial = _base_state(analysis_tier="quick")

    events = []
    for event in pipeline.stream(initial, {"configurable": {"thread_id": "routing-test"}}):
        events.extend(event.keys())

    assert events == ["fingerprint", "report"], f"Expected [fingerprint, report], got {events}"


def test_quick_tier_phase_results():
    from graph.pipeline import build_pipeline

    pipeline = build_pipeline()
    initial = _base_state(analysis_tier="quick")

    result = pipeline.invoke(initial, {"configurable": {"thread_id": "quick-results"}})
    phase_names = [pr["phase"] for pr in result.get("phase_results", [])]
    assert phase_names == ["fingerprint", "report"], f"Got {phase_names}"


# ── Error handling tests ──────────────────────────────────────────────────


def test_handle_error_increments():
    from graph.nodes import handle_error

    s = _base_state(error_count=0)
    result = handle_error(s)
    assert result["error_count"] == 1


def test_handle_error_trips_at_three():
    from graph.nodes import handle_error

    s = _base_state(error_count=2)
    result = handle_error(s)
    assert result["error_count"] == 3


def test_error_node_executes():
    from graph.pipeline import build_pipeline

    pipeline = build_pipeline()
    initial = _base_state()

    result = pipeline.invoke(initial, {"configurable": {"thread_id": "error-test"}})
    errors = [pr for pr in result.get("phase_results", []) if pr.get("status") == "error"]
    assert len(errors) == 0, f"Unexpected errors: {errors}"


# ── Missing binary path ──────────────────────────────────────────────────


def test_fingerprint_missing_binary():
    from graph.nodes import phase_fingerprint

    s = _base_state(binary_path="/nonexistent/binary")
    result = phase_fingerprint(s)
    # Should still return Command, not crash
    assert hasattr(result, "goto")
    assert result.goto in ("filter", "report", "error")


# ── GLORFINDEL IDA fallback ─────────────────────────────────────────────


def test_glorfindel_ida_unavailable():
    from agents.fellowship.glorfindel import run_decompilation

    result = run_decompilation(BINARY, tier="quick")
    assert result.get("status") == "unavailable", f"Expected unavailable, got {result.get('status')}"
    assert result.get("ida_available") is False
    assert result.get("functions_decompiled") == 0
    assert result.get("signatures_matched") == 0


# ── CELEBORN quick tier ──────────────────────────────────────────────────


def test_celeborn_quick_tier():
    from agents.fellowship.celeborn import build_timeline

    s = _base_state()
    result = build_timeline(s, tier="quick")
    assert isinstance(result, dict)
    assert result.get("status") == "ok"
    assert "timeline" in result
    assert "behavioral_groups" in result
    assert "narrative" in result


# ── ELROND cross-validation ──────────────────────────────────────────────


def test_elrond_cross_validate_legolas():
    from agents.fellowship.elrond import cross_validate
    from agents.fellowship.legolas import run_static_analysis

    legolas = run_static_analysis(BINARY, "mach-o", tier="quick")
    assert legolas.get("r2_status") == "ok"

    elrond = cross_validate(legolas)
    assert elrond.get("status") == "ok"
    assert elrond.get("agreement_score", 0) >= 0.8
    assert elrond.get("confirmed_import_count", 0) > 0


# ── Pipeline quick tier artifact writing ─────────────────────────────────


def test_quick_tier_writes_artifacts():
    from graph.pipeline import build_pipeline

    pipeline = build_pipeline()
    case_dir = tempfile.mkdtemp(prefix="mordor_art_")
    initial = _base_state(analysis_tier="quick", case_dir=case_dir)

    pipeline.invoke(initial, {"configurable": {"thread_id": "art-test"}})

    artifacts = list(Path(case_dir).iterdir())
    names = {p.name for p in artifacts}

    assert "metadata.json" in names, f"Missing metadata.json in {names}"
    assert "raw_strings.txt" in names, f"Missing raw_strings.txt in {names}"
    assert "imports.json" in names, f"Missing imports.json in {names}"

    md = json.loads((Path(case_dir) / "metadata.json").read_text())
    assert md["sha256"] == SHA256
    assert md["strings_count"] > 0
    assert md["imports_count"] > 0


# ── CELEBORN standard tier (no API key = graceful None) ──────────────────


def test_celeborn_no_api_key():
    from agents.fellowship.celeborn import build_timeline

    os.environ.pop("OPENROUTER_API_KEY", None)
    os.environ.pop("OPENROUTER_KEY", None)

    s = _base_state()
    result = build_timeline(s, tier="standard")
    assert isinstance(result, dict)
    assert result.get("status") == "ok"
    assert "timeline" in result
    assert "narrative" in result
    assert "coverage_gaps" in result
