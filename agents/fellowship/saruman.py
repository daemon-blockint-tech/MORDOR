"""Saruman - Advanced threat analysis using expert RE cognitive framework.

Based on USENIX RE-Mind research (272+ hours of expert RE observation) and
MITRE cognitive models. Implements hypothesis-driven investigation with
layered abstraction, pattern chunking, and kill chain reconstruction.
"""
from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from agents.gates import skip_llm

logger = logging.getLogger("mordor.saruman")


class ThreatHypothesis(BaseModel):
    """Structured threat hypothesis with confidence scoring."""
    
    category: str = Field(
        description="Threat category: persistence, c2, injection, collection, or exfiltration"
    )
    description: str = Field(
        description="Detailed description of the threat hypothesis"
    )
    confidence: float = Field(
        description="Confidence score from 0 to 100",
        ge=0.0,
        le=100.0
    )
    evidence: list[str] = Field(
        description="List of evidence supporting this hypothesis"
    )
    functions: list[str] = Field(
        description="Suspicious function names to investigate",
        default_factory=list
    )
    risk_score: float = Field(
        description="Risk score from 0 to 100",
        ge=0.0,
        le=100.0
    )
    mitre_tactics: list[str] = Field(
        description="MITRE ATT&CK tactics associated with this threat",
        default_factory=list
    )


class ThreatAnalysis(BaseModel):
    """Complete threat analysis with multiple hypotheses."""
    
    hypotheses: list[ThreatHypothesis] = Field(
        description="List of threat hypotheses"
    )
    overall_risk: float = Field(
        description="Overall risk assessment from 0 to 100",
        ge=0.0,
        le=100.0
    )
    recommended_actions: list[str] = Field(
        description="Recommended next steps for analysis"
    )


def analyze_with_structured_output(
    sha256: str,
    file_type: str,
    signals: list[dict[str, Any]],
    metadata: dict[str, Any],
    tier: str = "standard",
) -> ThreatAnalysis | None:
    """
    Perform expert-level threat analysis using cognitive RE framework.
    
    Implements USENIX RE-Mind mental models:
    1. Attacker Lens - Build intent hypothesis first
    2. Layered Abstraction - Work top-down (behavior → functional → structural)
    3. Pattern Chunking - Recognize known patterns instantly
    4. Hypothesis Loop - Predict → hunt → confirm/revise
    5. Negative Space - Note what's missing
    6. Second-Order Thinking - Chain implications
    7. Occam's Razor - Simplest explanation wins
    8. Kill Chain - Reconstruct temporal sequence
    
    Args:
        sha256: SHA256 hash of the binary.
        file_type: Detected file type.
        signals: Filtered signals from previous analysis.
        metadata: Binary metadata (imports, strings, etc.).
    
    Returns:
        ThreatAnalysis object with structured hypotheses, or None on error.
    """
    from tools.openrouter_client import chat_structured
    
    # Build expert RE system prompt with cognitive framework
    system_prompt = """You are SARUMAN, an expert reverse engineer using cognitive frameworks from USENIX RE-Mind research.

## Your Cognitive Operating System

### 1. ATTACKER LENS (Start Here)
Before analyzing, build attacker intent hypothesis:
- What's the economic goal? (ransomware / stealer / RAT / botnet)
- Who's the target? (enterprise / consumer / infrastructure)
- What's most valuable to steal/destroy?
- What delivery method makes sense?

### 2. LAYERED ABSTRACTION (Top-Down)
Work in 3 layers:
- Layer 3 (Behavioral): What it does - "This is a credential stealer"
- Layer 2 (Functional): How it does it - "Enumerate → Extract → Exfiltrate"
- Layer 1 (Structural): How it's built - "Uses DPAPI with XOR encoding"

### 3. PATTERN CHUNKING (Instant Recognition)
Recognize known patterns:
- VirtualAlloc + WriteProcessMemory + CreateRemoteThread = Process injection
- InternetOpen + HttpSendRequest = HTTP C2
- RegSetValue HKLM\\Run = Persistence

### 4. HYPOTHESIS LOOP (Predict → Hunt → Confirm)
For each hypothesis:
1. Predict what evidence should exist
2. Hunt for that specific evidence
3. Confirm or revise hypothesis

### 5. NEGATIVE SPACE (What's Missing)
Note absences:
- No anti-debug = Commodity malware
- No persistence = Dropper/loader
- No network = Local-only threat

### 6. SECOND-ORDER THINKING (Chain Implications)
For each finding, ask:
- What does this IMPLY?
- What came BEFORE?
- What comes AFTER?

### 7. OCCAM'S RAZOR (Simplest Explanation)
Test benign explanation first.
Only accept malicious when benign fails.

### 8. KILL CHAIN (Reconstruct Timeline)
Map to phases:
Execution → Persistence → Recon → Collection → C2 → Exfiltration → Cleanup"""
    
    # Build analysis prompt with expert framing
    prompt = f"""Analyze this binary using expert RE cognitive framework:

**Binary Information:**
- SHA256: {sha256}
- File Type: {file_type}
- Imports: {metadata.get('imports_count', 0)}
- Strings: {metadata.get('strings_count', 0)}
- Sections: {metadata.get('sections_count', 0)}
- Packer Hints: {metadata.get('packer_hints', [])}
- OSINT Malicious: {metadata.get('osint_malicious', False)}

**Filtered Signals ({len(signals)} total):**
{_format_signals(signals[:30])}

**Apply Expert RE Framework:**

1. **ATTACKER LENS**: What's the attacker's goal? Build intent hypothesis FIRST.

2. **PATTERN CHUNKING**: Recognize known patterns instantly:
   - Process injection patterns?
   - C2 communication patterns?
   - Persistence patterns?
   - Obfuscation patterns?

3. **NEGATIVE SPACE**: What's MISSING?
   - Anti-debug checks?
   - Persistence mechanisms?
   - Network code?
   - String encryption?

4. **HYPOTHESIS LOOP**: For each hypothesis:
   - Predict what evidence should exist
   - Confirm if evidence is present in signals
   - Assign confidence based on evidence strength

5. **SECOND-ORDER THINKING**: Chain implications:
   - If FindFirstFile → file enumeration → what's being searched?
   - If CryptUnprotectData → credential extraction → what credentials?

6. **OCCAM'S RAZOR**: Test benign explanations:
   - Could this be legitimate software?
   - What makes it suspicious?

7. **KILL CHAIN**: Map findings to phases:
   - Execution → Persistence → Recon → Collection → C2 → Exfil → Cleanup

**Generate structured threat hypotheses covering:**
- Persistence mechanisms
- Command & Control (C2)
- Code injection techniques
- Data collection
- Data exfiltration

For each hypothesis:
- Provide specific evidence from signals
- Apply Occam's Razor (test benign explanation)
- Assign confidence based on evidence strength
- Map to MITRE ATT&CK tactics
- Identify suspicious functions to investigate
- Note what's MISSING (negative space)

Also provide:
- Overall risk assessment (considering negative space)
- Kill chain reconstruction
- Recommended next steps"""
    
    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": prompt
        }
    ]
    
    if skip_llm(tier):
        return None

    try:
        # Use structured output with expert RE framework
        result = chat_structured(
            messages=messages,
            schema=ThreatAnalysis,
            model=None,  # Uses SARUMAN_MODEL from env
            temperature=0.2,  # Lower temperature for consistent expert reasoning
            max_tokens=4096,
        )
        
        if result:
            logger.info(
                "Saruman analysis complete: %d hypotheses, overall risk: %.1f (expert RE framework applied)",
                len(result.hypotheses),
                result.overall_risk
            )
        
        return result
    
    except Exception as exc:
        logger.error("Saruman analysis failed: %s", exc, exc_info=True)
        return None


def _format_signals(signals: list[dict[str, Any]]) -> str:
    """Format signals for prompt display."""
    lines = []
    for i, sig in enumerate(signals, 1):
        sig_type = sig.get("type", "unknown")
        sig_value = sig.get("value", "")
        lines.append(f"{i}. [{sig_type}] {sig_value}")
    return "\n".join(lines) if lines else "(no signals)"


def generate_mitre_mapping(hypotheses: list[dict[str, Any]], tier: str = "standard") -> dict[str, list[str]]:
    """
    Generate MITRE ATT&CK mapping from hypotheses.
    
    Args:
        hypotheses: List of hypothesis dicts.
    
    Returns:
        Dict mapping MITRE tactics to techniques.
    """
    from tools.openrouter_client import chat_json
    
    prompt = f"""Map these malware hypotheses to MITRE ATT&CK framework:

{_format_hypotheses(hypotheses)}

Return JSON object with this structure:
{{
  "tactics": {{
    "Persistence": ["T1547.001", "T1053.005"],
    "Command and Control": ["T1071.001"],
    ...
  }},
  "primary_tactics": ["Persistence", "Command and Control"],
  "threat_actor_profile": "APT-like / Commodity / Ransomware / etc"
}}
"""
    
    messages = [
        {
            "role": "system",
            "content": "You are a MITRE ATT&CK expert. Map malware behaviors to tactics and techniques."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]
    
    if skip_llm(tier):
        return {}
    result = chat_json(messages, temperature=0.1)
    return result or {}


def _format_hypotheses(hypotheses: list[dict[str, Any]]) -> str:
    """Format hypotheses for prompt display."""
    lines = []
    for i, h in enumerate(hypotheses, 1):
        lines.append(f"{i}. {h.get('category', 'unknown')}: {h.get('description', '')}")
        lines.append(f"   Confidence: {h.get('confidence', 0):.0f}%")
    return "\n".join(lines)
