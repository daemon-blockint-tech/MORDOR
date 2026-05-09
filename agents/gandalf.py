from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from graph.state import CaseState


class GandalfOrchestrator:
    def __init__(self, pipeline: StateGraph | None = None):
        if pipeline is None:
            from graph.pipeline import build_pipeline

            pipeline = build_pipeline()
        self.pipeline = pipeline

    def _build_initial_state(self, binary_path: str, tier: str = "standard") -> CaseState:
        import hashlib
        import os

        from tools.safe_util import sanitize_path
        safe_path = sanitize_path(binary_path)
        with open(safe_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        case_dir = f"cases/{sha256}"

        return {
            "binary_path": binary_path,
            "sha256": sha256,
            "case_dir": case_dir,
            "analysis_tier": tier,
            "journal_path": os.path.join(case_dir, "analysis_journal.jsonl"),
            "current_phase": "fingerprint",
            "error": None,
            "error_count": 0,
            "phase_results": [],
            "hypotheses": [],
            "iocs": [],
            "artifacts": {},
            "confidence_overall": 0.0,
            "confidence_breakdown": {},
            "file_type": None,
            "file_size": os.path.getsize(safe_path),
            "cost_entries": [],
            "cost_summary": {},
        }

    def run(self, binary_path: str, tier: str = "standard", config: dict[str, Any] | None = None) -> dict[str, Any]:
        initial_state = self._build_initial_state(binary_path, tier)
        cfg = {
            "configurable": {
                "thread_id": initial_state["sha256"],
                **(config or {}),
            }
        }
        return self.pipeline.invoke(initial_state, cfg)

    def stream(self, binary_path: str, tier: str = "standard", config: dict[str, Any] | None = None):
        initial_state = self._build_initial_state(binary_path, tier)
        cfg = {
            "configurable": {
                "thread_id": initial_state["sha256"],
                **(config or {}),
            }
        }
        for event in self.pipeline.stream(initial_state, cfg):
            yield event
