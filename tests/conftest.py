from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Generator

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.dependencies import CaseManager, get_case_manager
from api.server import app

SAMPLE_DIR = Path(__file__).resolve().parent / "samples"
SAMPLE_BINARY = str(SAMPLE_DIR / "test_malware.x64")
SAMPLE_SHA256 = "ca9e240985471469d20d2b40a53df9764b47b4296ed1fa6ba4305e980fde06d7"


class MockPipeline:
    def __init__(self, events: list[dict[str, Any]] | None = None):
        self._events = events or []

    def stream(self, state: dict, config: dict | None = None):
        for event in self._events:
            yield event

    def invoke(self, state: dict, config: dict | None = None):
        return state


class MockOrchestrator:
    def __init__(self, events: list[dict[str, Any]] | None = None):
        self.pipeline = MockPipeline(events)
        self._last_binary = None
        self._last_tier = None

    def _build_initial_state(self, binary_path: str, tier: str = "standard") -> dict[str, Any]:
        self._last_binary = binary_path
        self._last_tier = tier
        return {
            "binary_path": binary_path,
            "sha256": "mock-sha256",
            "case_dir": "/tmp/mock-case",
            "analysis_tier": tier,
            "journal_path": "/tmp/mock-case/analysis_journal.jsonl",
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
            "file_size": 100,
        }


PHASE_EVENTS = [
    {"fingerprint": {"current_phase": "fingerprint", "phase_results": [{"phase": "fingerprint", "status": "done"}], "confidence_overall": 50.0, "error": None}},
    {"filter": {"current_phase": "filter", "phase_results": [{"phase": "filter", "status": "done"}], "confidence_overall": 60.0, "error": None}},
    {"hypothesize": {"current_phase": "hypothesize", "phase_results": [{"phase": "hypothesize", "status": "done"}], "confidence_overall": 70.0, "error": None}},
    {"map_structure": {"current_phase": "map_structure", "phase_results": [{"phase": "map_structure", "status": "done"}], "confidence_overall": 75.0, "error": None}},
    {"deep_analysis": {"current_phase": "deep_analysis", "phase_results": [{"phase": "deep_analysis", "status": "done"}], "confidence_overall": 80.0, "error": None}},
    {"validate": {"current_phase": "validate", "phase_results": [{"phase": "validate", "status": "done"}], "confidence_overall": 85.0, "error": None}},
    {"report": {"current_phase": "report", "phase_results": [{"phase": "report", "status": "done"}], "confidence_overall": 90.0, "error": None}},
]


def make_phase_events(count: int = 7) -> list[dict[str, Any]]:
    return PHASE_EVENTS[:count]


def make_error_event(msg: str = "test error") -> dict[str, Any]:
    return {"fingerprint": {"current_phase": "fingerprint", "phase_results": [], "confidence_overall": 0.0, "error": msg}}


@pytest.fixture
def case_manager(tmp_path: Path) -> CaseManager:
    cm = CaseManager(cases_dir=str(tmp_path / "cases"))
    return cm


@pytest.fixture
def client(case_manager: CaseManager) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_case_manager] = lambda: case_manager
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def sample_binary() -> str:
    return SAMPLE_BINARY


@pytest.fixture
def sample_sha256() -> str:
    return SAMPLE_SHA256
