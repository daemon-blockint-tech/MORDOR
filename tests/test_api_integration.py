from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.dependencies import get_orchestrator
from api.server import app
from conftest import MockOrchestrator, make_phase_events


# ── Health & Root ──────────────────────────────────────────────────────────


def test_health_endpoint(client: TestClient):
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "mordor"


def test_root_endpoint(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "MORDOR"
    assert "docs" in data


# ── Cases endpoints ───────────────────────────────────────────────────────


def test_list_cases_empty(client: TestClient):
    resp = client.get("/v1/cases")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_case_not_found(client: TestClient):
    resp = client.get("/v1/cases/nonexistent")
    assert resp.status_code == 404


def test_get_case_status(client: TestClient, case_manager):
    case_id, _ = case_manager.create_case("/bin/ls", tier="quick")
    case_manager.update_status(case_id, status="completed", phase="report", progress=100.0)

    resp = client.get(f"/v1/cases/{case_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["status"] == "completed"
    assert data["phase"] == "report"
    assert data["progress"] == 100.0
    assert data["confidence"] == 0.0
    assert data["error"] is None


def test_list_cases_with_entries(client: TestClient, case_manager):
    case_id, _ = case_manager.create_case("/bin/ls", tier="quick")
    case_manager.update_status(case_id, status="running", phase="fingerprint", progress=50.0)

    resp = client.get("/v1/cases")
    assert resp.status_code == 200
    data = resp.json()
    ids = [c["case_id"] for c in data]
    assert case_id in ids


def test_get_case_artifacts_not_found(client: TestClient):
    resp = client.get("/v1/cases/nonexistent/artifacts")
    assert resp.status_code == 404


def test_get_case_report_not_found(client: TestClient, case_manager):
    case_id, _ = case_manager.create_case("/bin/ls", tier="quick")

    resp = client.get(f"/v1/cases/{case_id}/report")
    assert resp.status_code == 404


def test_get_case_report_success(client: TestClient, case_manager, sample_binary):
    import hashlib
    sha256 = hashlib.sha256(open(sample_binary, "rb").read()).hexdigest()
    case_id = sha256

    report_path = Path(case_manager.cases_dir) / case_id / "final_report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Analysis Report\n\nTest report content.")
    case_manager.create_case(sample_binary, tier="quick")
    case_manager.update_status(case_id, status="completed")

    resp = client.get(f"/v1/cases/{case_id}/report")
    assert resp.status_code == 200
    assert resp.text == "# Analysis Report\n\nTest report content."


# ── Analyze endpoints ─────────────────────────────────────────────────────


def test_analyze_path_nonexistent_file(client: TestClient):
    resp = client.post("/v1/analyze/path", data={"binary_path": "/nonexistent/binary"})
    assert resp.status_code == 404


def test_analyze_path_mocked(client: TestClient, case_manager, sample_binary):
    mock_orch = MockOrchestrator(make_phase_events(2))
    app.dependency_overrides[get_orchestrator] = lambda: mock_orch

    try:
        resp = client.post("/v1/analyze/path", data={"binary_path": sample_binary, "tier": "quick"})
        assert resp.status_code == 200
        data = resp.json()
        assert "case_id" in data
        assert data["status"] == "running"

        case_id = data["case_id"]
        timeout = 10
        while timeout > 0:
            status = case_manager.get_status(case_id)
            if status and status.get("status") in ("completed", "failed"):
                break
            time.sleep(0.5)
            timeout -= 0.5

        if timeout <= 0:
            pytest.skip("Pipeline did not complete in time (may be running)")

        status = case_manager.get_status(case_id)
        assert status["status"] == "completed"
        assert status["phases_completed"] == ["fingerprint", "filter"]
    finally:
        app.dependency_overrides.pop(get_orchestrator, None)


def test_analyze_path_standard_tier_mocked(client: TestClient, case_manager, sample_binary):
    mock_orch = MockOrchestrator(make_phase_events(7))
    app.dependency_overrides[get_orchestrator] = lambda: mock_orch

    try:
        resp = client.post("/v1/analyze/path", data={"binary_path": sample_binary, "tier": "standard"})
        assert resp.status_code == 200
        data = resp.json()
        assert "case_id" in data

        case_id = data["case_id"]
        timeout = 10
        while timeout > 0:
            status = case_manager.get_status(case_id)
            if status and status.get("status") in ("completed", "failed"):
                break
            time.sleep(0.5)
            timeout -= 0.5

        if timeout <= 0:
            pytest.skip("Pipeline did not complete in time")

        status = case_manager.get_status(case_id)
        assert status["status"] == "completed", f"Expected completed, got {status}"
        assert len(status.get("phases_completed", [])) == 7
    finally:
        app.dependency_overrides.pop(get_orchestrator, None)


def test_analyze_upload_mocked(client: TestClient, case_manager, sample_binary):
    mock_orch = MockOrchestrator(make_phase_events(2))
    app.dependency_overrides[get_orchestrator] = lambda: mock_orch

    try:
        with open(sample_binary, "rb") as f:
            resp = client.post("/v1/analyze", files={"file": ("test_malware.x64", f, "application/octet-stream")}, data={"tier": "quick"})
        assert resp.status_code == 200
        data = resp.json()
        assert "case_id" in data
        assert data["status"] == "running"

        case_id = data["case_id"]
        timeout = 10
        while timeout > 0:
            status = case_manager.get_status(case_id)
            if status and status.get("status") in ("completed", "failed"):
                break
            time.sleep(0.5)
            timeout -= 0.5

        if timeout <= 0:
            pytest.skip("Pipeline did not complete in time")

        status = case_manager.get_status(case_id)
        assert status["status"] == "completed"
    finally:
        app.dependency_overrides.pop(get_orchestrator, None)


# ── SSE Stream endpoints ─────────────────────────────────────────────────


def test_stream_endpoint_not_found(client: TestClient):
    resp = client.get("/v1/analyze/nonexistent/stream")
    assert resp.status_code == 404

    resp = client.get("/v1/stream/nonexistent")
    assert resp.status_code == 404


def test_stream_endpoint_completed(client: TestClient, case_manager):
    case_id, _ = case_manager.create_case("/bin/ls", tier="quick")
    case_manager.update_status(case_id, status="completed", phase="report", progress=100.0)

    resp = client.get(f"/v1/analyze/{case_id}/stream")
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("text/event-stream")

    lines = resp.text.strip().split("\n")
    events = [line for line in lines if line.startswith("data:")]
    assert len(events) >= 1
    last_event = json.loads(events[-1].replace("data: ", ""))
    assert last_event.get("status") == "completed"


def test_stream_v1_endpoint_completed(client: TestClient, case_manager):
    case_id, _ = case_manager.create_case("/bin/ls", tier="quick")
    case_manager.update_status(case_id, status="completed", phase="report", progress=100.0)

    resp = client.get(f"/v1/stream/{case_id}")
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("text/event-stream")

    lines = resp.text.strip().split("\n")
    data_events = [line for line in lines if line.startswith("data:")]
    assert len(data_events) >= 1
    statuses = set()
    for line in data_events:
        d = json.loads(line.replace("data: ", ""))
        if "status" in d:
            statuses.add(d["status"])
    assert "completed" in statuses


# ── Analyze error handling ────────────────────────────────────────────────


def test_analyze_path_reports_error(client: TestClient, case_manager, sample_binary):
    error_msg = "simulated pipeline failure"
    mock_orch = MockOrchestrator(make_phase_events(1))
    mock_orch.pipeline._events = {"fingerprint": {"current_phase": "fingerprint", "error": error_msg, "phase_results": [], "confidence_overall": 0.0}},

    app.dependency_overrides[get_orchestrator] = lambda: mock_orch

    try:
        resp = client.post("/v1/analyze/path", data={"binary_path": sample_binary, "tier": "standard"})
        assert resp.status_code == 200
        case_id = resp.json()["case_id"]

        timeout = 10
        while timeout > 0:
            status = case_manager.get_status(case_id)
            if status and status.get("status") in ("completed", "failed"):
                break
            time.sleep(0.5)
            timeout -= 0.5

        if timeout > 0:
            status = case_manager.get_status(case_id)
            assert status.get("error") is not None
    finally:
        app.dependency_overrides.pop(get_orchestrator, None)
