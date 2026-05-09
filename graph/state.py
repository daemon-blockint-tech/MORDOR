from __future__ import annotations

from typing import Annotated, Any, Literal, Optional
from typing_extensions import TypedDict
import operator


PhaseName = Literal[
    "fingerprint",
    "filter",
    "hypothesize",
    "map_structure",
    "deep_analysis",
    "validate",
    "report",
    "done",
    "error",
]

ConfidenceLevel = Literal["critical", "suspicious", "info"]


class PhaseArtifacts(TypedDict, total=False):
    metadata: dict[str, Any]
    raw_strings: list[str]
    imports: list[dict[str, Any]]
    crypto_indicators: list[dict[str, Any]]
    filtered_signals: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    component_map: dict[str, Any]
    call_graph: str
    deep_analysis_plan: str
    frida_hooks_log: str
    decoded_payloads: list[dict[str, Any]]
    memory_dump: dict[str, Any]
    final_report: str
    ida_analysis: dict[str, Any]
    behavioral_timeline: dict[str, Any]


class Hypothesis(TypedDict, total=False):
    category: Literal["persistence", "c2", "injection", "collection", "exfiltration"]
    description: str
    confidence: float
    evidence: list[str]
    functions: list[str]
    risk_score: float


class IoC(TypedDict, total=False):
    value: str
    type: Literal["hash", "ip", "domain", "url", "registry", "file_path", "mutex"]
    source: str
    confidence: float
    tags: list[str]


class CaseState(TypedDict):
    sha256: str
    case_dir: str
    analysis_tier: str
    journal_path: str

    current_phase: PhaseName
    error: Optional[str]
    error_count: int

    phase_results: Annotated[list[dict[str, Any]], operator.add]
    hypotheses: Annotated[list[Hypothesis], operator.add]
    iocs: Annotated[list[IoC], operator.add]
    artifacts: Annotated[PhaseArtifacts, operator.or_]

    confidence_overall: float
    confidence_breakdown: dict[str, float]

    binary_path: str
    file_type: Optional[str]
    file_size: Optional[int]

    cost_entries: Annotated[list[dict], operator.add]
    cost_summary: dict
