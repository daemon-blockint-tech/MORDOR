from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


def load_system_prompt(name: str) -> str:
    prompt_path = Path(__file__).resolve().parent.parent / "prompts" / f"{name}_system_prompt.md"
    if prompt_path.exists():
        return prompt_path.read_text().strip()
    return ""


class AragornOSINTSchema(BaseModel):
    threat_intel: dict = Field(
        default_factory=dict,
        description="Threat intelligence summary including malicious flag and summary text",
    )
    hash_lookups: list[dict] = Field(
        default_factory=list,
        description="List of hash lookup results from threat intel sources",
    )
    tags: list[str] = Field(
        default_factory=list, description="List of threat tags/categories"
    )


class BoromirTriageSchema(BaseModel):
    filtered_signals: list[dict] = Field(
        default_factory=list,
        description="Filtered signals with confidence and category",
    )
    confidence_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Overall confidence score 0-100"
    )
    classification: str = Field(
        default="info",
        description="Classification: critical, suspicious, or info",
    )


class GollumReviewSchema(BaseModel):
    benign_explanations: list[dict] = Field(
        default_factory=list,
        description="List of findings with 3+ benign reasons each",
    )
    confirmed_flags: list[dict] = Field(
        default_factory=list,
        description="Flags confirmed as suspicious with severity",
    )
    dismissed_flags: list[str] = Field(
        default_factory=list,
        description="Findings dismissed as false positives",
    )


class LegolasAnnotationSchema(BaseModel):
    crypto_constants: list[str] = Field(
        default_factory=list,
        description="Detected cryptographic constants",
    )
    packer_hints: list[str] = Field(
        default_factory=list,
        description="Indicators of packers or obfuscation",
    )
    annotations: list[dict] = Field(
        default_factory=list,
        description="Annotated suspicious indicators with type and description",
    )


class MerryDependencySchema(BaseModel):
    dependencies: list[dict] = Field(
        default_factory=list,
        description="List of dependency findings with name, version, and risk level",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Recommended actions for dependency risks",
    )


class FrodoHookSchema(BaseModel):
    hooks: list[dict] = Field(
        default_factory=list,
        description="Hooks attached with function name and hook type",
    )
    results: list[dict] = Field(
        default_factory=list,
        description="Runtime hook results and observations",
    )
    status: str = Field(default="pending", description="Hook execution status")


class GimliTraceSchema(BaseModel):
    breakpoints: list[str] = Field(
        default_factory=list,
        description="Breakpoints set during debugging session",
    )
    trace_log: list[dict] = Field(
        default_factory=list,
        description="Execution trace log entries",
    )
    status: str = Field(default="pending", description="Trace execution status")


class PippinNetworkSchema(BaseModel):
    flows: list[dict] = Field(
        default_factory=list,
        description="Network flow records from pcap analysis",
    )
    dns_queries: list[dict] = Field(
        default_factory=list,
        description="DNS queries observed in network capture",
    )
    c2_indicators: list[dict] = Field(
        default_factory=list,
        description="Indicators of command-and-control communication",
    )
    status: str = Field(default="pending", description="Network analysis status")


class EowynMemorySchema(BaseModel):
    processes: list[dict] = Field(
        default_factory=list,
        description="Processes identified in memory dump",
    )
    network_connections: list[dict] = Field(
        default_factory=list,
        description="Network connections from memory analysis",
    )
    registry_keys: list[dict] = Field(
        default_factory=list,
        description="Registry keys identified in memory dump",
    )
    suspicious_indicators: list[str] = Field(
        default_factory=list,
        description="Suspicious indicators found in memory",
    )
    status: str = Field(default="pending", description="Memory analysis status")


class FaramirYARASchema(BaseModel):
    matches: list[dict] = Field(
        default_factory=list,
        description="YARA rule matches with rule name and offset",
    )
    rules_applied: int = Field(default=0, description="Number of YARA rules applied")
    status: str = Field(default="pending", description="YARA scan status")


class ArwenDecodeSchema(BaseModel):
    original: str = Field(default="", description="Original encoded payload")
    decoded: str = Field(default="", description="Decoded payload content")
    encoding_used: str = Field(default="auto", description="Encoding method detected")
    decoded_type: str = Field(
        default="unknown", description="Type of decoded content"
    )
    status: str = Field(default="pending", description="Decode status")


class TreebeardSandboxSchema(BaseModel):
    status: str = Field(default="pending", description="Sandbox execution status")
    results: dict = Field(
        default_factory=dict,
        description="Sandbox execution results including network, filesystem, process activity",
    )
    container_id: Optional[str] = Field(
        default=None, description="Docker container ID"
    )


class BilboSTIXSchema(BaseModel):
    type: str = Field(default="bundle", description="STIX object type")
    spec_version: str = Field(default="2.1", description="STIX specification version")
    objects: list[dict] = Field(
        default_factory=list,
        description="STIX indicator objects",
    )


class BilboYARARuleSchema(BaseModel):
    rule_name: str = Field(default="mordor_auto_ioc", description="YARA rule name")
    rule_text: str = Field(default="", description="Full YARA rule text")
    condition_count: int = Field(default=0, description="Number of conditions")


class BilboSigmaRuleSchema(BaseModel):
    title: str = Field(
        default="MORDOR Auto-Generated Sigma Rule",
        description="Sigma rule title",
    )
    logsource: dict = Field(
        default_factory=lambda: {"category": "process_creation"},
        description="Sigma rule log source configuration",
    )
    detection: dict = Field(
        default_factory=dict, description="Sigma rule detection logic"
    )


class ElrondCrossValidationSchema(BaseModel):
    agreement_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Cross-validation agreement score"
    )
    discrepancies: list[dict] = Field(
        default_factory=list,
        description="Discrepancies found between analysis tools",
    )
    confirmed_functions: list[dict] = Field(
        default_factory=list,
        description="Functions confirmed by multiple tools",
    )
    ghidra_only_count: int = Field(default=0, description="Items only in Ghidra")
    r2_only_count: int = Field(default=0, description="Items only in radare2")
    status: str = Field(default="ok", description="Validation status")


class GlorfindelDecompileSchema(BaseModel):
    status: str = Field(default="pending", description="Decompilation status")
    functions_decompiled: int = Field(default=0, description="Number of functions decompiled")
    signatures_matched: int = Field(default=0, description="Number of library signatures matched")
    decompiled_functions: list[dict] = Field(
        default_factory=list,
        description="List of decompiled functions with pseudocode and metadata",
    )
    signatures: list[dict] = Field(
        default_factory=list,
        description="FLIRT signature matches: library name and matched functions",
    )
    analysis_phases_completed: list[str] = Field(
        default_factory=list,
        description="Phases completed: signature, local, full",
    )
    ida_available: bool = Field(default=False, description="Whether IDA Pro was available")


class CelebornTimelineSchema(BaseModel):
    status: str = Field(default="pending", description="Timeline synthesis status")
    timeline: list[dict] = Field(
        default_factory=list,
        description="Chronological behavioral timeline of binary execution",
    )
    behavioral_groups: list[dict] = Field(
        default_factory=list,
        description="Grouped behaviors by category with confidence",
    )
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description="Analysis gaps or unanswered questions",
    )
    narrative: str = Field(
        default="", description="Executive narrative summary of binary behavior"
    )


class MultimodalAnalysisSchema(BaseModel):
    description: str = Field(
        default="", description="Textual description of the visual content"
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Suspicious indicators observed in the image",
    )
    text_extracted: list[str] = Field(
        default_factory=list,
        description="Text extracted from the image",
    )
    analysis_type: str = Field(
        default="screenshot",
        description="Type of content analyzed: screenshot, memory_dump, decompilation",
    )


class PayPaymentSchema(BaseModel):
    action: str = Field(
        default="health_check",
        description="Action to perform: health_check, balance_check, payment, topup, skills_update, skills_search",
    )
    recipient: Optional[str] = Field(
        default=None, description="Recipient address for payment",
    )
    amount: Optional[str] = Field(
        default=None, description="Payment amount in stablecoin units",
    )
    query: Optional[str] = Field(
        default=None, description="Search query for skills_search action",
    )
