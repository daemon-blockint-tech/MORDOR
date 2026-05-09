from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sse_starlette.sse import EventSourceResponse

from api.auth import verify_api_key
from api.dependencies import CaseManager, get_case_manager, get_orchestrator
from api.models import AnalyzeResponse
from agents.gandalf import GandalfOrchestrator
from tools.safe_util import sanitize_path

_MAX_UPLOAD_SIZE = int(os.environ.get("MORDOR_MAX_UPLOAD_SIZE", "104857600"))  # 100MB default

router = APIRouter(prefix="/v1", tags=["analyze"])


def _run_pipeline(
    orchestrator: GandalfOrchestrator,
    case_manager: CaseManager,
    binary_path: str,
    case_id: str,
    tier: str,
    events: list[dict[str, Any]],
) -> None:
    try:
        safe_path = sanitize_path(binary_path)

        case_manager.update_status(case_id, status="running", phase="fingerprint")

        state = orchestrator._build_initial_state(safe_path, tier)
        state["case_dir"] = str(case_manager.cases_dir / case_id)
        os.makedirs(state["case_dir"], mode=0o750, exist_ok=True)

        phase_order = [
            "fingerprint", "filter", "hypothesize",
            "map_structure", "deep_analysis", "validate", "report",
        ]
        total = len(phase_order)
        config = {"configurable": {"thread_id": case_id}}
        all_completed: list[str] = []

        for event in orchestrator.pipeline.stream(state, config):
            if not isinstance(event, dict):
                continue

            for node_name, node_data in event.items():
                if isinstance(node_data, dict):
                    phase = node_data.get("current_phase") or node_name
                    error = node_data.get("error")
                    results = node_data.get("phase_results", [])
                    completed_here = [r["phase"] for r in results if r.get("status") == "done"]
                    for p in completed_here:
                        if p not in all_completed:
                            all_completed.append(p)
                    progress = min(100.0, (len(all_completed) / total) * 100)

                    case_manager.update_status(
                        case_id,
                        phase=phase,
                        progress=progress,
                        phases_completed=list(all_completed),
                        error=error,
                        confidence=node_data.get("confidence_overall", 0),
                    )

                    events.append({
                        "type": "phase_update",
                        "data": {
                            "case_id": case_id,
                            "phase": phase,
                            "progress": progress,
                            "error": error,
                            "confidence": node_data.get("confidence_overall", 0),
                            "phases_completed": list(all_completed),
                        },
                    })

        case_manager.update_status(case_id, status="completed", progress=100.0, phases_completed=list(all_completed))
        events.append({"type": "complete", "data": {"case_id": case_id, "status": "completed"}})

    except Exception as e:
        case_manager.update_status(case_id, status="failed", error=str(e))
        events.append({"type": "error", "data": {"case_id": case_id, "error": str(e)}})


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_binary(
    file: UploadFile = File(...),
    tier: str = Form("standard"),
    case_manager: CaseManager = Depends(get_case_manager),
    orchestrator: GandalfOrchestrator = Depends(get_orchestrator),
    _auth: str | None = Depends(verify_api_key),
) -> AnalyzeResponse:
    content = await file.read()
    if len(content) > _MAX_UPLOAD_SIZE:
        raise HTTPException(413, f"File exceeds maximum size of {_MAX_UPLOAD_SIZE // 1048576}MB")

    suffix = Path(file.filename or "sample").suffix or ".bin"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(content)
    tmp.close()

    case_id, _ = case_manager.create_case(tmp.name, tier)

    events: list[dict[str, Any]] = []
    t = threading.Thread(
        target=_run_pipeline,
        args=(orchestrator, case_manager, tmp.name, case_id, tier, events),
        daemon=True,
    )
    t.start()

    return AnalyzeResponse(case_id=case_id, status="running")


@router.post("/analyze/path")
async def analyze_path(
    binary_path: str = Form(...),
    tier: str = Form("standard"),
    case_manager: CaseManager = Depends(get_case_manager),
    orchestrator: GandalfOrchestrator = Depends(get_orchestrator),
    _auth: str | None = Depends(verify_api_key),
) -> AnalyzeResponse:
    safe_path = sanitize_path(binary_path)
    path = Path(safe_path)
    if not path.exists():
        raise HTTPException(404, f"Binary not found: {binary_path}")

    case_id, _ = case_manager.create_case(safe_path, tier)

    events: list[dict[str, Any]] = []
    t = threading.Thread(
        target=_run_pipeline,
        args=(orchestrator, case_manager, str(path.resolve()), case_id, tier, events),
        daemon=True,
    )
    t.start()

    return AnalyzeResponse(case_id=case_id, status="running")


@router.get("/analyze/{case_id}/stream")
async def stream_analysis(
    case_id: str,
    case_manager: CaseManager = Depends(get_case_manager),
    _auth: str | None = Depends(verify_api_key),
):
    status = case_manager.get_status(case_id)
    if not status:
        raise HTTPException(404, "Case not found")

    async def event_generator():
        while True:
            s = case_manager.get_status(case_id)
            if not s:
                break
            yield {
                "event": "phase",
                "data": json.dumps(s),
            }
            if s.get("status") in ("completed", "failed"):
                break
            await asyncio.sleep(0.5)

    return EventSourceResponse(event_generator())
