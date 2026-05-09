from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from sse_starlette.sse import EventSourceResponse

from api.dependencies import CaseManager, get_case_manager

router = APIRouter(prefix="/v1", tags=["stream"])


@router.get("/stream/{case_id}")
async def stream_case(
    case_id: str,
    case_manager: CaseManager = Depends(get_case_manager),
):
    status = case_manager.get_status(case_id)
    if not status:
        raise HTTPException(404, f"Case {case_id} not found")

    async def event_generator():
        last_phase = None
        while True:
            s = case_manager.get_status(case_id)
            if not s:
                break

            phase = s.get("phase")
            if phase != last_phase:
                last_phase = phase
                yield {
                    "event": "phase",
                    "data": json.dumps({"phase": phase, "progress": s.get("progress", 0)}),
                }

            if s.get("status") in ("completed", "failed"):
                yield {
                    "event": s["status"],
                    "data": json.dumps(s),
                }
                break

            await asyncio.sleep(0.5)

    return EventSourceResponse(event_generator())


@router.get("/health")
async def health():
    return {"status": "ok", "service": "mordor"}
