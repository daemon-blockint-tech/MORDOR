# IronCurtain Insights for MORDOR

## 🎯 What is IronCurtain?

**IronCurtain** is a security-first AI agent framework by Niels Provos that solves the "ambient authority" problem - where AI agents have full access to everything the user has access to.

**Core Innovation**: Agents write TypeScript in V8 sandbox → Every tool call goes through policy engine → Human-in-the-loop for sensitive operations

## 🧠 Key Concepts Relevant to MORDOR

### 1. **Workflow as State Machine**

IronCurtain defines workflows as state machines with 4 types of states:

```yaml
agent:        # AI agent with role-specific prompt
human_gate:   # Pause for human review (approve/revise/abort)
deterministic: # Shell commands without LLM
terminal:     # End state (success/aborted)
```

**MORDOR Parallel**:
```python
# Our current pipeline is already a state machine:
fingerprint → filter → hypothesize → map_structure → 
deep_analysis → validate → report

# We can add human gates:
fingerprint → filter → hypothesize → [HUMAN_GATE] → 
map_structure → deep_analysis → [HUMAN_GATE] → validate → report
```

### 2. **Orchestrator Pattern**

IronCurtain's orchestrator:
- **Never reads source code**
- Reads the journal (history)
- Decides next state
- Writes scoped directive
- Every worker returns to it

**MORDOR's GANDALF is already this**:
```python
# GANDALF orchestrates without touching binaries directly:
def orchestrate(state):
    # Read journal (phase_results)
    history = state["phase_results"]
    
    # Decide next state
    next_phase = decide_next_phase(history)
    
    # Write directive
    directive = build_directive(next_phase, state)
    
    # Delegate to specialist
    result = delegate_to_agent(next_phase, directive)
    
    # Agent returns to GANDALF
    return result
```

### 3. **Hypothesis-Driven Harness Building**

IronCurtain's vulnerability discovery workflow:

```
1. analyze        → Structural analysis (facts only)
2. harness_design → Specify test harness
3. harness_build  → Implement harness
4. harness_validate → Run and verify
5. discover       → Drive harness with inputs
6. triage         → Validate findings
7. conclude       → Final report
```

**MORDOR Parallel** (Malware Analysis):

```
1. fingerprint    → Structural analysis (OSINT, static, deps)
2. filter         → Triage signals
3. hypothesize    → Build threat hypotheses
4. map_structure  → Component mapping
5. deep_analysis  → Test hypotheses
6. validate       → Confirm findings (sandbox, hooks, YARA)
7. report         → Final analysis
```

**Key Insight**: Both systems use **hypothesis → harness → test → validate** loop!

### 4. **Tiered Analysis Approach**

IronCurtain's harness tiers:

| Tier | Scope | Speed | Use Case |
|------|-------|-------|----------|
| T1 | Isolated function | Millions/sec | Single-function bugs |
| T2 | Multi-component | Moderate | Cross-function interactions |
| T3 | Full instrumented | Slow | Protocol framing, global state |

**MORDOR Should Adopt This**:

```python
class AnalysisTier:
    T1_QUICK = "quick"      # Static only, pattern matching
    T2_MEDIUM = "medium"    # Static + YARA + basic sandbox
    T3_DEEP = "deep"        # Full sandbox + dynamic + hooks
    T4_EXPERT = "expert"    # Manual RE + custom tools

def select_tier(hypothesis, confidence):
    """Select analysis tier based on hypothesis."""
    if confidence > 85 and hypothesis.category == "known_pattern":
        return AnalysisTier.T1_QUICK
    elif confidence > 70:
        return AnalysisTier.T2_MEDIUM
    elif confidence > 50:
        return AnalysisTier.T3_DEEP
    else:
        return AnalysisTier.T4_EXPERT
```

### 5. **Human Gates (Critical for MORDOR)**

IronCurtain pauses at 2 points:

1. **harness_review**: When design/validate loop stalls
   - Shows: analysis, design, reviewer notes, validation
   - Actions: approve, revise, abort

2. **report_review**: When investigation complete
   - Shows: final report, discoveries, triage, journal
   - Actions: approve, revise (re-investigate), abort

**MORDOR Should Add**:

```python
class HumanGate:
    """Human-in-the-loop decision point."""
    
    def __init__(self, gate_type: str, context: dict):
        self.gate_type = gate_type
        self.context = context
        self.decision = None
    
    def present_to_human(self):
        """Show context and wait for decision."""
        print(f"\n{'='*60}")
        print(f"HUMAN GATE: {self.gate_type}")
        print(f"{'='*60}")
        
        if self.gate_type == "hypothesis_review":
            print(f"Hypotheses: {len(self.context['hypotheses'])}")
            print(f"Confidence: {self.context['confidence']}%")
            print(f"Kill chain gaps: {self.context['gaps']}")
            print("\nProceed with deep analysis?")
        
        elif self.gate_type == "report_review":
            print(f"Analysis complete")
            print(f"Findings: {len(self.context['findings'])}")
            print(f"IOCs: {len(self.context['iocs'])}")
            print("\nApprove final report?")
        
        # Get decision
        decision = input("\n[A]pprove / [R]evise / [X]abort: ").upper()
        
        if decision == 'A':
            self.decision = "approve"
        elif decision == 'R':
            feedback = input("Revision feedback: ")
            self.decision = {"action": "revise", "feedback": feedback}
        else:
            self.decision = "abort"
        
        return self.decision

# In graph/nodes.py:
def phase_hypothesize(state: CaseState) -> Command:
    # ... build hypotheses ...
    
    # Add human gate
    gate = HumanGate("hypothesis_review", {
        "hypotheses": hypotheses,
        "confidence": confidence,
        "gaps": kill_chain_gaps
    })
    
    decision = gate.present_to_human()
    
    if decision == "abort":
        return Command(goto="error")
    elif isinstance(decision, dict) and decision["action"] == "revise":
        # Feed feedback back to LLM
        return revise_hypotheses(state, decision["feedback"])
    else:
        return Command(goto="map_structure")
```

### 6. **Journal-Driven Orchestration**

IronCurtain's orchestrator reads the **journal** (history of all actions) to decide next steps.

**MORDOR Should Implement**:

```python
class AnalysisJournal:
    """Complete history of analysis decisions."""
    
    def __init__(self, sha256: str):
        self.sha256 = sha256
        self.entries = []
    
    def log(self, phase: str, agent: str, action: str, result: dict):
        """Log an analysis action."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "agent": agent,
            "action": action,
            "result": result,
            "confidence": result.get("confidence", 0)
        }
        self.entries.append(entry)
    
    def get_context_for_phase(self, phase: str) -> str:
        """Get relevant journal context for a phase."""
        relevant = [e for e in self.entries if e["phase"] in RELATED_PHASES[phase]]
        return format_journal_entries(relevant)
    
    def detect_stall(self) -> bool:
        """Detect if analysis is stuck in a loop."""
        recent = self.entries[-5:]
        phases = [e["phase"] for e in recent]
        # If same phase repeated 3+ times, we're stalled
        return any(phases.count(p) >= 3 for p in set(phases))

# GANDALF uses journal to make decisions:
def orchestrate_with_journal(state: CaseState, journal: AnalysisJournal):
    """Orchestrate using journal context."""
    
    # Check for stall
    if journal.detect_stall():
        # Trigger human gate
        return human_gate_intervention(state, journal)
    
    # Get context for next phase
    context = journal.get_context_for_phase(state["current_phase"])
    
    # Make decision with full history
    decision = gandalf_decide(state, context)
    
    return decision
```

### 7. **Policy Engine (Security Layer)**

IronCurtain's policy engine evaluates every tool call:

```
allow      → Forward to MCP server
deny       → Block and return error
escalate   → Pause and ask human
```

**MORDOR Could Add** (for production deployment):

```python
class AnalysisPolicy:
    """Policy engine for malware analysis operations."""
    
    def __init__(self, constitution: str):
        self.rules = compile_policy(constitution)
    
    def evaluate(self, agent: str, action: str, args: dict) -> str:
        """Evaluate if action is allowed."""
        
        # Structural invariants (always enforced)
        if action == "execute_binary" and not args.get("sandbox"):
            return "deny"  # Never execute outside sandbox
        
        if action == "network_connect" and args.get("destination") == "internet":
            return "deny"  # No direct internet access
        
        # Check compiled rules
        for rule in self.rules:
            if rule.matches(agent, action, args):
                return rule.decision  # allow / deny / escalate
        
        # Default: escalate unknown actions
        return "escalate"

# Example constitution:
MORDOR_CONSTITUTION = """
The analysis system may:
- Read any file in the case directory
- Execute binaries only in isolated sandbox
- Make network requests only to known threat intel APIs
- Write results only to case directory

The analysis system may NOT:
- Execute binaries on host system
- Make arbitrary network connections
- Modify files outside case directory
- Access user's personal data

For any action not explicitly covered, ask the human.
"""
```

### 8. **Deterministic Commands (Non-LLM Steps)**

IronCurtain includes **deterministic** states for shell commands without LLM:

```yaml
- name: run_tests
  type: deterministic
  command: "pytest tests/"
```

**MORDOR Should Use This**:

```python
# Some operations don't need LLM:
def deterministic_yara_scan(binary_path: str) -> dict:
    """Run YARA without LLM - pure deterministic."""
    result = subprocess.run(
        ["yara", "-r", "rules/", binary_path],
        capture_output=True
    )
    return parse_yara_output(result.stdout)

def deterministic_hash_check(binary_path: str) -> dict:
    """Check hash against known malware DB - no LLM needed."""
    sha256 = hashlib.sha256(open(binary_path, "rb").read()).hexdigest()
    
    # Check VirusTotal, MalwareBazaar, etc.
    vt_result = check_virustotal(sha256)
    mb_result = check_malwarebazaar(sha256)
    
    return {
        "sha256": sha256,
        "known_malware": vt_result["malicious"] > 5,
        "family": mb_result.get("family"),
        "confidence": 100 if vt_result["malicious"] > 10 else 50
    }

# In pipeline:
def phase_fingerprint(state: CaseState):
    # Deterministic first (fast, cheap, no LLM)
    hash_result = deterministic_hash_check(state["binary_path"])
    
    if hash_result["known_malware"]:
        # Skip expensive analysis, we know what this is
        return Command(
            update={"known_malware": True, "family": hash_result["family"]},
            goto="report"
        )
    
    # Unknown sample, proceed with LLM-based analysis
    # ...
```

## 🔧 Actionable Improvements for MORDOR

### 1. Add Human Gates

```python
# In graph/pipeline.py:
def build_pipeline() -> StateGraph:
    builder = StateGraph(CaseState)
    
    # ... existing nodes ...
    
    # Add human gates
    builder.add_node("hypothesis_gate", human_gate_hypothesis)
    builder.add_node("report_gate", human_gate_report)
    
    # Insert gates in flow
    builder.add_edge("hypothesize", "hypothesis_gate")
    builder.add_conditional_edges(
        "hypothesis_gate",
        route_gate_decision,
        {
            "approve": "map_structure",
            "revise": "hypothesize",
            "abort": "error"
        }
    )
```

### 2. Implement Analysis Journal

```python
# Track complete history
journal = AnalysisJournal(sha256)

# Log every action
journal.log("fingerprint", "ARAGORN", "osint_lookup", osint_result)
journal.log("fingerprint", "LEGOLAS", "static_analysis", static_result)

# Use journal for decisions
if journal.detect_stall():
    trigger_human_intervention()

# Include journal in prompts
context = journal.get_context_for_phase("hypothesize")
prompt = f"Based on previous analysis:\n{context}\n\nBuild hypotheses..."
```

### 3. Add Tiered Analysis

```python
def select_analysis_tier(metadata: dict, osint: dict) -> str:
    """Select appropriate analysis depth."""
    
    # T1: Known malware (hash match)
    if osint.get("known_malware"):
        return "T1_QUICK"
    
    # T2: Suspicious but not confirmed
    if metadata.get("packer_hints") or osint.get("suspicious"):
        return "T2_MEDIUM"
    
    # T3: Unknown, needs deep analysis
    return "T3_DEEP"

# Execute tier-appropriate analysis
tier = select_analysis_tier(metadata, osint)

if tier == "T1_QUICK":
    # Pattern matching only
    result = quick_pattern_match(binary)
elif tier == "T2_MEDIUM":
    # Static + YARA + basic sandbox
    result = medium_analysis(binary)
else:
    # Full analysis with all agents
    result = deep_analysis(binary)
```

### 4. Separate Deterministic from LLM Steps

```python
# Phase 1: Deterministic (no LLM, fast, cheap)
def phase_fingerprint_deterministic(state):
    """Fast deterministic checks."""
    hash_check = check_known_hashes(state["binary_path"])
    yara_scan = run_yara_rules(state["binary_path"])
    
    if hash_check["known_malware"]:
        return skip_to_report(hash_check)
    
    return {"hash": hash_check, "yara": yara_scan}

# Phase 2: LLM-based (hypothesis building)
def phase_fingerprint_llm(state, deterministic_results):
    """LLM analyzes deterministic results."""
    # LLM only sees pre-processed data
    # Builds hypotheses from facts
    return build_hypotheses(deterministic_results)
```

## 📊 MORDOR + IronCurtain Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    GANDALF (Orchestrator)                │
│  - Reads journal (history)                              │
│  - Decides next state                                   │
│  - Never touches binaries directly                      │
└────────────┬────────────────────────────────────────────┘
             ↓
┌────────────────────────────────────────────────────────┐
│                   Analysis Journal                      │
│  - Complete history of all actions                     │
│  - Detects stalls and loops                            │
│  - Provides context for decisions                      │
└────────────┬───────────────────────────────────────────┘
             ↓
┌────────────────────────────────────────────────────────┐
│              Tiered Analysis Selection                  │
│  T1: Quick (pattern match, known malware)              │
│  T2: Medium (static + YARA + basic sandbox)            │
│  T3: Deep (full analysis with all agents)              │
└────────────┬───────────────────────────────────────────┘
             ↓
┌────────────────────────────────────────────────────────┐
│           Deterministic → LLM Pipeline                  │
│  1. Deterministic checks (fast, no LLM)                │
│  2. LLM hypothesis building (if needed)                │
│  3. Targeted evidence hunting                          │
└────────────┬───────────────────────────────────────────┘
             ↓
┌────────────────────────────────────────────────────────┐
│                   Human Gates                           │
│  - Hypothesis review (before deep analysis)            │
│  - Report review (before finalization)                 │
│  - Actions: approve / revise / abort                   │
└────────────────────────────────────────────────────────┘
```

## 🎯 Implementation Priority

### Phase 1: Core Improvements (Week 1)
1. ✅ Cognitive framework (DONE)
2. ✅ OpenRouter integration (DONE)
3. 📝 Add analysis journal
4. 📝 Implement tiered analysis

### Phase 2: Human-in-the-Loop (Week 2)
5. 📝 Add human gates
6. 📝 Implement gate UI (CLI or web)
7. 📝 Add revision feedback loop

### Phase 3: Optimization (Week 3)
8. 📝 Separate deterministic from LLM steps
9. 📝 Add stall detection
10. 📝 Implement policy engine (optional)

## 📚 Key Takeaways

1. **Orchestrator Pattern**: GANDALF should read journal, not binaries
2. **Human Gates**: Pause at critical decision points
3. **Tiered Analysis**: Match analysis depth to threat level
4. **Deterministic First**: Use LLM only when needed
5. **Journal-Driven**: Complete history informs decisions
6. **Hypothesis → Harness → Test**: Same pattern as IronCurtain

## 🔗 Resources

- **IronCurtain**: https://ironcurtain.dev/
- **GitHub**: https://github.com/provos/ironcurtain
- **Workflow YAML**: https://github.com/provos/ironcurtain/blob/master/src/workflow/workflows/vuln-discovery.yaml

---

**IronCurtain's workflow architecture is a perfect model for MORDOR's malware analysis pipeline.**
