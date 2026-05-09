# Implementing Cognitive Framework in MORDOR

## Quick Start: Integrate Framework into Existing Agents

### Step 1: Load System Prompts

```python
# In your agent file:
import os
from pathlib import Path

def load_system_prompt(agent_name: str) -> str:
    """Load cognitive framework system prompt for agent."""
    prompt_path = Path(__file__).parent.parent / "prompts" / f"{agent_name}_system_prompt.md"
    if prompt_path.exists():
        return prompt_path.read_text()
    return f"You are {agent_name.upper()}, a malware analysis agent."

# Usage:
GANDALF_PROMPT = load_system_prompt("gandalf")
LEGOLAS_PROMPT = load_system_prompt("legolas")
BOROMIR_PROMPT = load_system_prompt("boromir")
```

### Step 2: Update Agent Functions

#### Example: BOROMIR (Triage)

**Before:**
```python
def triage(signals: list[dict]) -> dict:
    from tools.openrouter_client import chat_json
    
    prompt = f"Triage these signals: {signals}"
    result = chat_json([
        {"role": "user", "content": prompt}
    ])
    return result or {}
```

**After (with Framework):**
```python
def triage(signals: list[dict]) -> dict:
    from tools.openrouter_client import chat_structured
    from pydantic import BaseModel, Field
    
    # Load cognitive framework prompt
    system_prompt = load_system_prompt("boromir")
    
    # Define structured output
    class TriageResult(BaseModel):
        filtered_signals: list[dict] = Field(description="Signals that passed triage")
        dismissed_signals: list[dict] = Field(description="Dismissed as noise")
        negative_space_findings: list[str] = Field(description="What's missing")
        confidence_score: float = Field(ge=0, le=100)
        priority: str = Field(description="CRITICAL/HIGH/MEDIUM/LOW")
        reasoning: str = Field(description="Triage reasoning")
    
    # Build prompt with framework guidance
    prompt = f"""Apply cognitive framework to triage these signals:

**Signals ({len(signals)} total):**
{format_signals(signals)}

**Apply Framework:**
1. NEGATIVE SPACE: What's MISSING? (anti-debug, persistence, network, obfuscation)
2. PATTERN CHUNKING: Recognize known patterns instantly
3. OCCAM'S RAZOR: Test benign explanation for each signal
4. CONFIDENCE SCORING: Quantify certainty

**Output structured triage result.**"""
    
    result = chat_structured(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        schema=TriageResult,
        model="openai/gpt-4o-mini",  # Fast model for triage
        temperature=0.2
    )
    
    return result.dict() if result else {}
```

### Step 3: Update GANDALF Orchestration

**In `graph/nodes.py`, update `phase_hypothesize`:**

```python
def phase_hypothesize(state: CaseState) -> Command[Literal["map_structure", "error"]]:
    from tools.openrouter_client import chat_structured
    from pydantic import BaseModel, Field
    
    # Load GANDALF cognitive framework
    system_prompt = load_system_prompt("gandalf")
    
    class Hypothesis(BaseModel):
        category: str = Field(description="Threat category")
        description: str = Field(description="Hypothesis description")
        confidence: float = Field(ge=0, le=100)
        evidence_predictions: list[str] = Field(description="What evidence should exist")
        functions_to_investigate: list[str] = Field(description="Suspicious functions")
        risk_score: float = Field(ge=0, le=100)
        kill_chain_phase: str = Field(description="Kill chain phase")
        negative_space_notes: list[str] = Field(description="What's missing")
    
    class HypothesisAnalysis(BaseModel):
        attacker_intent: str = Field(description="Attacker's goal (Attacker Lens)")
        hypotheses: list[Hypothesis]
        overall_confidence: float = Field(ge=0, le=100)
        kill_chain_gaps: list[str] = Field(description="Missing kill chain phases")
    
    filtered = state.get("artifacts", {}).get("filtered_signals", [])
    metadata = state.get("artifacts", {}).get("metadata", {})
    
    prompt = f"""Apply expert RE cognitive framework to build hypotheses:

**Binary Metadata:**
- SHA256: {state['sha256']}
- File Type: {metadata.get('file_type', 'unknown')}
- Imports: {metadata.get('imports_count', 0)}
- Strings: {metadata.get('strings_count', 0)}
- Packer Hints: {metadata.get('packer_hints', [])}

**Filtered Signals ({len(filtered)} total):**
{format_signals(filtered[:30])}

**Apply Cognitive Framework:**

1. **ATTACKER LENS** (Start Here):
   - What's the economic goal? (ransomware / stealer / RAT / botnet)
   - Who's the target? (enterprise / consumer / infrastructure)
   - What's valuable to steal/destroy?
   - What delivery method makes sense?

2. **PATTERN CHUNKING**:
   - Recognize known patterns instantly
   - Process injection? C2? Persistence? Obfuscation?

3. **NEGATIVE SPACE**:
   - What's MISSING? (anti-debug, persistence, network, obfuscation)
   - Absences inform classification

4. **HYPOTHESIS LOOP**:
   - For each hypothesis: PREDICT what evidence should exist
   - These predictions will guide LEGOLAS's evidence hunting

5. **KILL CHAIN**:
   - Map hypotheses to kill chain phases
   - Identify gaps (unknown functionality)

**Generate structured hypotheses with evidence predictions.**"""
    
    result = chat_structured(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        schema=HypothesisAnalysis,
        temperature=0.3
    )
    
    if result:
        hypotheses = [h.dict() for h in result.hypotheses]
        
        # Log framework application
        logger.info(
            "GANDALF: Attacker intent = %s, %d hypotheses, %d kill chain gaps",
            result.attacker_intent,
            len(result.hypotheses),
            len(result.kill_chain_gaps)
        )
        
        return Command(
            update={
                "current_phase": "hypothesize",
                "phase_results": [{
                    "phase": "hypothesize",
                    "status": "done",
                    "attacker_intent": result.attacker_intent,
                    "count": len(hypotheses),
                    "kill_chain_gaps": result.kill_chain_gaps
                }],
                "hypotheses": hypotheses,
                "confidence_overall": result.overall_confidence,
            },
            goto="map_structure",
        )
```

## Integration Patterns

### Pattern 1: Hypothesis-Driven Tool Calls

**Before:**
```python
# Blind enumeration
legolas_result = run_static_analysis(binary_path)
# Returns: ALL imports, ALL strings, ALL sections
```

**After:**
```python
# Hypothesis-driven
hypothesis = "Process injection capability"
predictions = [
    "VirtualAlloc + WriteProcessMemory + CreateRemoteThread",
    "Target process selection logic",
    "Payload blob in .data"
]

legolas_result = hunt_evidence(
    binary_path=binary_path,
    hypothesis=hypothesis,
    predictions=predictions
)
# Returns: ONLY evidence for this hypothesis
```

### Pattern 2: Negative Space Reporting

**Add to every analysis phase:**

```python
def analyze_with_negative_space(findings: dict) -> dict:
    """Explicitly check and report absences."""
    
    absences = {
        "anti_debug": check_anti_debug(findings),
        "anti_vm": check_anti_vm(findings),
        "persistence": check_persistence(findings),
        "network": check_network(findings),
        "obfuscation": check_obfuscation(findings)
    }
    
    negative_space_findings = []
    for feature, present in absences.items():
        if not present:
            negative_space_findings.append(
                f"No {feature} detected → {ABSENCE_IMPLICATIONS[feature]}"
            )
    
    findings["negative_space"] = negative_space_findings
    return findings

ABSENCE_IMPLICATIONS = {
    "anti_debug": "Commodity malware / low sophistication",
    "anti_vm": "Not designed to evade sandboxes",
    "persistence": "Dropper/loader (look for payload)",
    "network": "Local-only threat (ransomware/wiper)",
    "obfuscation": "Old malware / script kiddie"
}
```

### Pattern 3: Occam's Razor Filter

**Add before escalating findings:**

```python
def apply_occams_razor(finding: dict) -> dict:
    """Test benign explanation before accepting malicious."""
    
    # Test benign explanation
    benign_test = test_benign_explanation(finding)
    
    if benign_test["plausible"]:
        # Benign explanation exists - need corroboration
        if not has_corroborating_evidence(finding):
            finding["dismissed"] = True
            finding["reason"] = benign_test["explanation"]
            finding["confidence"] = max(finding["confidence"] - 30, 10)
    
    return finding

def test_benign_explanation(finding: dict) -> dict:
    """Test if finding could be benign."""
    
    BENIGN_PATTERNS = {
        "RegSetValue HKLM\\Run": {
            "explanation": "Legitimate auto-start",
            "differentiators": ["signed", "standard_path", "descriptive_name"]
        },
        "CreateRemoteThread": {
            "explanation": "Debugger/profiler",
            "differentiators": ["known_tool", "signed", "expected_functionality"]
        }
    }
    
    pattern = finding.get("pattern")
    if pattern in BENIGN_PATTERNS:
        benign = BENIGN_PATTERNS[pattern]
        # Check differentiators
        suspicious_count = sum(
            1 for diff in benign["differentiators"]
            if not finding.get(diff, False)
        )
        return {
            "plausible": suspicious_count < len(benign["differentiators"]) / 2,
            "explanation": benign["explanation"]
        }
    
    return {"plausible": False, "explanation": None}
```

### Pattern 4: Kill Chain Reconstruction

**Add to final report phase:**

```python
def reconstruct_kill_chain(state: CaseState) -> dict:
    """Reconstruct malware execution timeline."""
    
    kill_chain = {
        "execution": [],
        "persistence": [],
        "reconnaissance": [],
        "collection": [],
        "command_and_control": [],
        "exfiltration": [],
        "cleanup": []
    }
    
    # Map findings to phases
    for hypothesis in state.get("hypotheses", []):
        phase = hypothesis.get("kill_chain_phase", "unknown")
        if phase in kill_chain:
            kill_chain[phase].append({
                "category": hypothesis.get("category"),
                "description": hypothesis.get("description"),
                "confidence": hypothesis.get("confidence")
            })
    
    # Identify gaps
    gaps = [phase for phase, findings in kill_chain.items() if not findings]
    
    # Calculate completeness
    completeness = (len(kill_chain) - len(gaps)) / len(kill_chain) * 100
    
    return {
        "kill_chain": kill_chain,
        "gaps": gaps,
        "completeness": completeness,
        "analysis_complete": completeness >= 70
    }
```

## Testing Framework Integration

### Test 1: Hypothesis Quality

```python
def test_hypothesis_quality():
    """Test if hypotheses are specific and testable."""
    
    result = phase_hypothesize(test_state)
    hypotheses = result["hypotheses"]
    
    for h in hypotheses:
        # Check hypothesis has predictions
        assert "evidence_predictions" in h
        assert len(h["evidence_predictions"]) > 0
        
        # Check hypothesis is specific
        assert h["category"] in VALID_CATEGORIES
        assert len(h["description"]) > 20
        
        # Check hypothesis has confidence
        assert 0 <= h["confidence"] <= 100
```

### Test 2: Negative Space Reporting

```python
def test_negative_space():
    """Test if absences are explicitly reported."""
    
    result = triage(test_signals)
    
    # Should have negative space findings
    assert "negative_space_findings" in result
    assert len(result["negative_space_findings"]) > 0
    
    # Should note specific absences
    absences = result["negative_space_findings"]
    assert any("anti-debug" in a.lower() for a in absences)
```

### Test 3: Occam's Razor Application

```python
def test_occams_razor():
    """Test if benign explanations are tested."""
    
    # Finding with benign explanation
    finding = {
        "pattern": "RegSetValue HKLM\\Run",
        "signed": True,
        "standard_path": True
    }
    
    result = apply_occams_razor(finding)
    
    # Should be dismissed (benign explanation succeeds)
    assert result["dismissed"] == True
    assert "benign" in result["reason"].lower()
```

## Monitoring Framework Effectiveness

### Metrics to Track

```python
class FrameworkMetrics:
    """Track cognitive framework effectiveness."""
    
    def __init__(self):
        self.hypothesis_accuracy = []  # % of hypotheses confirmed
        self.evidence_targeting = []   # % of tool calls testing hypotheses
        self.fp_reduction = []         # % of findings dismissed by Occam's Razor
        self.kill_chain_completeness = []  # % of analyses with full timeline
        self.confidence_calibration = []   # Correlation: confidence vs accuracy
    
    def log_analysis(self, result: dict):
        """Log metrics for an analysis."""
        
        # Hypothesis accuracy
        confirmed = sum(1 for h in result["hypotheses"] if h["confirmed"])
        total = len(result["hypotheses"])
        self.hypothesis_accuracy.append(confirmed / total if total > 0 else 0)
        
        # Kill chain completeness
        gaps = len(result["kill_chain"]["gaps"])
        phases = len(result["kill_chain"])
        completeness = (phases - gaps) / phases
        self.kill_chain_completeness.append(completeness)
        
        # FP reduction
        dismissed = len(result.get("dismissed_findings", []))
        total_findings = len(result.get("all_findings", []))
        self.fp_reduction.append(dismissed / total_findings if total_findings > 0 else 0)
```

## Next Steps

1. **Load prompts**: Add `load_system_prompt()` to agents
2. **Update schemas**: Add Pydantic models with framework fields
3. **Modify nodes**: Update `graph/nodes.py` with framework patterns
4. **Test integration**: Run `test_openrouter.py` with framework
5. **Monitor metrics**: Track framework effectiveness

## Remember

The framework is not a one-time change. It's a **cognitive operating system** that should guide every decision:

1. What's the attacker trying to achieve?
2. What layer am I working on?
3. Is this a known pattern?
4. What's my hypothesis?
5. What's missing?
6. What does this imply?
7. What's the simplest explanation?
8. Where does this fit in the kill chain?

**Every agent, every analysis, every decision.**
