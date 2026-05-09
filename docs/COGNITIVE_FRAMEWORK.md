# MORDOR Cognitive Framework

## Foundation: Expert RE Thinking, Not Just Tools

This framework is based on **272+ hours of expert reverse engineer observation** from USENIX RE-Mind research (2022) and MITRE cognitive models. It encodes **how experts actually think**, not just what tools they use.

## The Problem with Traditional RE Systems

Traditional malware analysis systems work like this:

```
❌ WRONG APPROACH:
1. Run all tools
2. Collect all data
3. List all findings
4. Hope patterns emerge
```

This creates:
- **Information overload** - Too much data, no insight
- **False positives** - Everything looks suspicious
- **Missed threats** - Real malware hidden in noise
- **No understanding** - Lists of APIs, no intent

## The Expert RE Approach

Experts work fundamentally differently:

```
✅ EXPERT APPROACH:
1. Form hypothesis about attacker intent
2. Predict what evidence should exist
3. Hunt specifically for that evidence
4. Confirm or revise hypothesis
5. Reconstruct kill chain
```

This creates:
- **Targeted analysis** - Hunt evidence, don't enumerate
- **Low false positives** - Test benign explanations first
- **High detection** - Hypothesis-driven investigation
- **Deep understanding** - Reconstruct attacker's logic

## The 8 Mental Models

### 1. Attacker Lens (Inversion)

**Principle**: Don't ask "what does this code do?" Ask "if I wrote this malware, what would I need to implement?"

**Why it works**: Experts start with intent, not implementation. They build a mental model of the attacker's goals BEFORE touching any tools.

**Implementation**:
```python
# GANDALF starts every analysis with:
def build_attacker_hypothesis(metadata):
    """
    Before ANY tool execution:
    1. What's the economic goal? (ransomware / stealer / RAT)
    2. Who's the target? (enterprise / consumer)
    3. What's valuable to steal/destroy?
    4. What delivery method makes sense?
    
    THEN hunt for evidence of those components.
    """
```

**Example**:
```
Metadata: PE32, 2MB, high imports count, network strings

Expert thinking:
"If this is enterprise stealer (hypothesis):
 - Need: Browser credential extraction
 - Need: Network share enumeration
 - Need: Encrypted exfiltration
 - Need: Persistence for long-term access
 
 Now let me find EVIDENCE for each."

NOT: "Let me read all 500 functions and see what happens"
```

### 2. Layered Abstraction Navigation

**Principle**: Experts work in 3 layers simultaneously, moving top-down.

```
Layer 3 — BEHAVIORAL (What it does)
  "This is a credential stealer with HTTPS exfil"
  ↓
Layer 2 — FUNCTIONAL (How it does it)
  "Enumerate browsers → Extract creds → Encrypt → POST"
  ↓
Layer 1 — STRUCTURAL (How it's built)
  "Uses DPAPI CryptUnprotectData with XOR key 0x3F"
```

**Why it works**: Bottom-up analysis (assembly → behavior) gets lost in details. Top-down (behavior → evidence) stays focused.

**Implementation**:
```python
# LEGOLAS reports at appropriate layer:
{
  "layer": 2,  # Functional
  "finding": "Browser credential extraction pattern",
  "evidence": ["CryptUnprotectData", "browser paths in strings"],
  "implication": "Confirms stealer hypothesis (Layer 3)"
}
```

### 3. Chunking & Pattern Library

**Principle**: Experts recognize patterns instantly without deep analysis.

**Why it works**: After analyzing thousands of samples, experts build internal "chunk library" of known patterns. Recognition is instant.

**Implementation**:
```python
# LEGOLAS pattern library:
PATTERNS = {
    "process_injection": {
        "apis": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
        "confidence": 85,
        "instant_match": True
    },
    "http_c2": {
        "apis": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
        "confidence": 85,
        "instant_match": True
    }
}

# When pattern matches → report immediately, no deep analysis
```

**Example**:
```
Sees: VirtualAlloc + WriteProcessMemory + CreateRemoteThread

Expert: "Process injection. 85% confidence. Next."

NOT: "Let me analyze each API call, trace data flow, 
      understand memory allocation patterns..."
```

### 4. Hypothesis-Driven Investigation Loop

**Principle**: Always predict before hunting. Never enumerate blindly.

```
FORM hypothesis
  ↓
PREDICT what evidence should exist
  ↓
HUNT specifically for that evidence
  ↓
FOUND? → CONFIRM, escalate
NOT FOUND? → REVISE hypothesis, try alternative
```

**Why it works**: This is the core anti-FP mechanism. Blind enumeration flags everything. Hypothesis-driven investigation only flags what matters.

**Implementation**:
```python
# Every LEGOLAS call tests a hypothesis:
def hunt_evidence(hypothesis, predictions):
    """
    hypothesis: "This is a process injector"
    predictions: [
        "Should find VirtualAlloc + WriteProcessMemory",
        "Should find target process selection",
        "Should find payload blob"
    ]
    
    Hunt specifically for predictions.
    Report: CONFIRMED / REFUTED / INCONCLUSIVE
    """
```

### 5. Negative Space Analysis

**Principle**: What's MISSING is as informative as what's present.

**Why it works**: Absence patterns classify malware families as much as presence patterns.

**Implementation**:
```python
# BOROMIR explicitly checks absences:
negative_space = {
    "no_anti_debug": "Commodity malware / low sophistication",
    "no_persistence": "Dropper/loader (look for payload)",
    "no_network": "Ransomware / wiper / local-only",
    "no_obfuscation": "Old malware / script kiddie",
    "minimal_imports": "Packed (escalate to unpacking)"
}
```

**Example**:
```
Analysis finds:
✓ Process injection
✓ Network communication
✗ NO anti-debug
✗ NO anti-VM
✗ NO string encryption

Conclusion: Commodity malware, not targeted APT
Priority: MEDIUM (not CRITICAL)
```

### 6. Second-Order Thinking (Ripple Effects)

**Principle**: For every finding, ask "what does this IMPLY?"

**Why it works**: Experts don't just enumerate APIs. They chain implications to reconstruct intent.

**Implementation**:
```python
# LEGOLAS chains implications:
def second_order_analysis(finding):
    """
    Finding: FindFirstFile("*.doc")
    
    Second order: File enumeration loop exists
    Third order: Extension filter → targeting documents
    Fourth order: + encryption → ransomware
                  + exfiltration → stealer
    
    Chain implications to reconstruct intent.
    """
```

**Example**:
```
Found: CryptStringToBinary import

Implications:
→ There's encoded data somewhere (base64/hex)
→ Likely decode-then-execute pattern
→ Suggests payload delivery or config decoding

Predict next evidence:
→ Should find: Encoded blob in .data/.rsrc
→ Should find: VirtualAlloc after decode
→ Should find: Execution transfer to decoded buffer

Hunt for those predictions.
```

### 7. Occam's Razor for Malware

**Principle**: The simplest explanation that fits ALL evidence wins.

**Why it works**: This is the primary anti-FP mechanism. Test benign explanation FIRST. Only accept malicious when benign fails.

**Implementation**:
```python
# GOLLUM challenges every finding:
def challenge_finding(finding):
    """
    1. Is there a simpler, benign explanation?
    2. Is this a known legitimate pattern?
    3. Could this be a false positive?
    4. What additional evidence confirms malicious?
    
    Only accept malicious when benign fails.
    """
```

**Example**:
```
Finding: HTTP POST with encoded data

Hypothesis A: Custom encrypted C2 (complex)
Hypothesis B: Standard telemetry with base64 (simple)

Test B first:
- Known telemetry domain? NO
- Standard user-agent? NO
- Documented in privacy policy? NO

B fails → Accept A
```

### 8. Temporal Reasoning (Kill Chain Reconstruction)

**Principle**: Reconstruct the timeline, don't just list capabilities.

**Why it works**: Understanding the sequence reveals intent. A list of capabilities doesn't.

**Implementation**:
```python
# GANDALF reconstructs kill chain:
kill_chain = {
    "execution": ["Anti-sandbox check", "Unpack payload"],
    "persistence": ["Copy to %APPDATA%", "Add to Run key"],
    "recon": ["Enumerate drives", "List processes"],
    "collection": ["Search .doc/.pdf", "Copy to staging"],
    "c2": ["Beacon to C2", "Receive commands"],
    "exfiltration": ["Encrypt data", "HTTP POST"],
    "cleanup": ["Delete staging", "Clear logs"]
}

# Analysis complete when kill chain fully reconstructed
```

## How This Changes MORDOR

### Before (Tool-Centric)

```python
# Old approach:
def analyze(binary):
    # Run all tools
    osint = run_osint(binary)
    static = run_static(binary)
    dynamic = run_dynamic(binary)
    
    # List all findings
    findings = osint + static + dynamic
    
    # Hope patterns emerge
    return findings
```

**Problems**:
- Information overload
- No hypothesis
- High false positives
- No understanding

### After (Cognitive Framework)

```python
# New approach:
def analyze(binary):
    # 1. ATTACKER LENS: Build intent hypothesis
    hypothesis = build_attacker_hypothesis(metadata)
    # "This looks like enterprise stealer"
    
    # 2. PREDICT: What evidence should exist?
    predictions = predict_evidence(hypothesis)
    # ["Browser cred extraction", "Network exfil", "Persistence"]
    
    # 3. HUNT: Search specifically for predictions
    evidence = hunt_evidence(predictions)
    
    # 4. PATTERN CHUNK: Recognize known patterns
    patterns = recognize_patterns(evidence)
    
    # 5. NEGATIVE SPACE: Note absences
    absences = check_negative_space(evidence)
    
    # 6. OCCAM'S RAZOR: Test benign explanations
    confirmed = challenge_findings(evidence)
    
    # 7. KILL CHAIN: Reconstruct timeline
    kill_chain = reconstruct_timeline(confirmed)
    
    return {
        "hypothesis": hypothesis,
        "evidence": confirmed,
        "kill_chain": kill_chain,
        "confidence": calculate_confidence(evidence, absences)
    }
```

**Benefits**:
- Targeted analysis
- Hypothesis-driven
- Low false positives
- Deep understanding

## Encoding Framework into Agents

### GANDALF (Orchestrator)
- **Primary models**: All 8
- **Focus**: Attacker Lens, Layered Abstraction, Kill Chain
- **Role**: Build hypotheses, coordinate agents, reconstruct timeline

### LEGOLAS (Static Analysis)
- **Primary models**: Chunking, Hypothesis Loop, Second-Order
- **Focus**: Pattern recognition, evidence hunting
- **Role**: Hunt predicted evidence, recognize patterns, chain implications

### BOROMIR (Triage)
- **Primary models**: Negative Space, Occam's Razor, Chunking
- **Focus**: Filter noise, test benign explanations
- **Role**: Separate signal from noise, anti-FP mechanism

### GOLLUM (Adversarial Review)
- **Primary models**: Occam's Razor (primary)
- **Focus**: Challenge findings with benign explanations
- **Role**: Final anti-FP check, confidence calibration

### SARUMAN (Advanced Analysis)
- **Primary models**: All 8 (expert synthesis)
- **Focus**: Complete cognitive framework application
- **Role**: Deep analysis with full expert reasoning

## Measuring Success

### Traditional Metrics (Not Enough)
- Detection rate
- False positive rate
- Analysis time

### Cognitive Framework Metrics (Better)
- **Hypothesis quality**: How accurate are initial hypotheses?
- **Evidence targeting**: % of tool calls that test specific hypotheses
- **FP reduction**: % of findings dismissed by Occam's Razor
- **Kill chain completeness**: % of analyses with full timeline
- **Confidence calibration**: Correlation between confidence and accuracy

## Implementation Checklist

For each agent:
- [ ] System prompt includes relevant mental models
- [ ] Hypothesis-driven, not enumerate-driven
- [ ] Pattern library for instant recognition
- [ ] Negative space analysis explicit
- [ ] Occam's Razor applied to findings
- [ ] Second-order thinking for implications
- [ ] Kill chain phase mapping
- [ ] Confidence scoring with rubric

## References

- **USENIX RE-Mind (2022)**: 272+ hours of expert RE observation
- **MITRE Cognitive Models**: Formal models of expert RE thinking
- **CCDCOE**: Malware analysis best practices
- **FIRST**: Incident response cognitive frameworks

## Remember

This is not theory. This is **how real experts think**.

The framework is not about tools. It's about **encoding expert cognition** into the system.

Every agent must operate through this cognitive lens:
1. What's the attacker trying to achieve?
2. What layer am I working on?
3. Is this a known pattern?
4. What's my hypothesis?
5. What's missing?
6. What does this imply?
7. What's the simplest explanation?
8. Where does this fit in the kill chain?

**This is MORDOR's foundation. Not tools. Thinking.**
