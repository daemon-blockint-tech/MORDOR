from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class AnalysisTier(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class AnalyzeRequest(BaseModel):
    tier: AnalysisTier = AnalysisTier.standard
    filename: str | None = None


class AnalyzeResponse(BaseModel):
    case_id: str
    status: str = "running"
    phase: str = "fingerprint"


class CaseStatus(BaseModel):
    case_id: str
    status: str
    phase: str
    progress: float = 0.0
    error: str | None = None
    error_count: int = 0
    confidence: float = 0.0
    phases_completed: list[str] = Field(default_factory=list)


class CaseSummary(BaseModel):
    case_id: str
    sha256: str
    file_type: str | None = None
    file_size: int | None = None
    status: str
    phase: str
    confidence: float = 0.0
    created_at: str | None = None


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
