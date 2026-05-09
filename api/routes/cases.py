from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from api.dependencies import CaseManager, get_case_manager
from api.models import CaseStatus, CaseSummary

router = APIRouter(prefix="/v1", tags=["cases"])


@router.get("/cases", response_model=list[CaseSummary])
async def list_cases(
    case_manager: CaseManager = Depends(get_case_manager),
) -> list[CaseSummary]:
    return [CaseSummary(**c) for c in case_manager.list_cases()]


@router.get("/cases/{case_id}", response_model=CaseStatus)
async def get_case(
    case_id: str,
    case_manager: CaseManager = Depends(get_case_manager),
) -> CaseStatus:
    status = case_manager.get_status(case_id)
    if not status:
        raise HTTPException(404, f"Case {case_id} not found")
    return CaseStatus(**status)


@router.get("/cases/{case_id}/artifacts")
async def list_artifacts(
    case_id: str,
    case_manager: CaseManager = Depends(get_case_manager),
):
    artifacts = case_manager.list_artifacts(case_id)
    if not artifacts:
        raise HTTPException(404, f"Case {case_id} not found")
    return {"case_id": case_id, "artifacts": artifacts}


@router.get("/cases/{case_id}/artifacts/{name}")
async def get_artifact(
    case_id: str,
    name: str,
    case_manager: CaseManager = Depends(get_case_manager),
):
    content = case_manager.get_artifact(case_id, name)
    if content is None:
        raise HTTPException(404, f"Artifact {name} not found in case {case_id}")

    if name.endswith(".json"):
        from fastapi.responses import JSONResponse
        import json
        return JSONResponse(json.loads(content))
    return PlainTextResponse(content)


@router.get("/cases/{case_id}/report")
async def get_report(
    case_id: str,
    case_manager: CaseManager = Depends(get_case_manager),
):
    content = case_manager.get_artifact(case_id, "final_report.md")
    if content is None:
        raise HTTPException(404, f"No report for case {case_id}")
    return PlainTextResponse(content, media_type="text/markdown")


@router.get("/cases/{case_id}/timeline")
async def get_timeline(
    case_id: str,
    case_manager: CaseManager = Depends(get_case_manager),
):
    content = case_manager.get_artifact(case_id, "behavioral_timeline.json")
    if content is None:
        raise HTTPException(404, f"No timeline for case {case_id}")
    from fastapi.responses import JSONResponse
    import json
    return JSONResponse(json.loads(content))
