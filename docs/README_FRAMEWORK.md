# MORDOR Cognitive Framework - Quick Reference

## 🧠 What Is This?

MORDOR doesn't just run tools. It **thinks like an expert reverse engineer**.

Based on **272+ hours of expert RE observation** (USENIX RE-Mind, 2022), we've encoded **how experts actually think** into system prompts.

## 🎯 The Core Insight

```
❌ Traditional: Run tools → Collect data → List findings → Hope
✅ Expert: Build hypothesis → Predict evidence → Hunt → Confirm
```

## 📚 The 8 Mental Models

### 1. 🎭 Attacker Lens
**"If I wrote this malware, what would I need?"**
- Build intent hypothesis FIRST
- Then hunt for evidence
- Not: "What does this code do?"

### 2. 📊 Layered Abstraction
**Work top-down, not bottom-up**
```
Behavioral (What) → Functional (How) → Structural (Details)
```

### 3. 🧩 Pattern Chunking
**Recognize instantly, don't analyze**
- `VirtualAlloc + WriteProcessMemory + CreateRemoteThread` = Process injection
- Report immediately, 85% confidence

### 4. 🔄 Hypothesis Loop
**Predict → Hunt → Confirm**
```
Form hypothesis → Predict evidence → Hunt specifically → Confirm/Revise
```

### 5. ⚫ Negative Space
**What's missing matters**
- No anti-debug = Commodity malware
- No persistence = Dropper/loader
- No network = Local-only threat

### 6. 🔗 Second-Order Thinking
**Chain implications**
```
FindFirstFile → Enumeration → Extension filter → Ransomware/Stealer
```

### 7. 🔪 Occam's Razor
**Simplest explanation wins**
- Test benign FIRST
- Only accept malicious when benign fails
- Primary anti-FP mechanism

### 8. ⏱️ Kill Chain
**Reconstruct timeline**
```
Execution → Persistence → Recon → Collection → C2 → Exfil → Cleanup
```

## 🤖 Agent Roles

| Agent | Primary Models | Role |
|-------|---------------|------|
| **GANDALF** | All 8 | Orchestrator - builds hypotheses, reconstructs kill chain |
| **LEGOLAS** | Chunking, Hypothesis Loop | Evidence hunter - recognizes patterns, hunts predictions |
| **BOROMIR** | Negative Space, Occam's Razor | Triage - filters noise, tests benign explanations |
| **GOLLUM** | Occam's Razor | Adversarial reviewer - challenges findings |
| **SARUMAN** | All 8 | Expert synthesis - deep analysis with full framework |

## 📖 System Prompts

All prompts are in `/prompts/`:
- `gandalf_system_prompt.md` - Master orchestrator
- `legolas_system_prompt.md` - Static analysis
- `boromir_system_prompt.md` - Triage specialist
- `gollum_system_prompt.md` - Adversarial reviewer

## 🔧 How to Use

### 1. Read the Framework
```bash
cat COGNITIVE_FRAMEWORK.md
```

### 2. Review Agent Prompts
```bash
ls prompts/
```

### 3. Update Your Agents
When creating/updating agents, include relevant mental models in system prompts.

### 4. Test with Framework
```python
from tools.openrouter_client import chat_structured

# Include framework in system prompt
system_prompt = open("prompts/gandalf_system_prompt.md").read()

result = chat_structured(
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Analyze..."}
    ],
    schema=YourSchema
)
```

## 💡 Key Principles

### ✅ DO:
- Build hypothesis before analysis
- Predict evidence, then hunt
- Recognize patterns instantly
- Note what's missing
- Test benign explanations first
- Reconstruct kill chain

### ❌ DON'T:
- Enumerate everything blindly
- Analyze without hypothesis
- Ignore absences
- Accept first explanation
- List capabilities without timeline

## 📊 Example: Before vs After

### Before (Tool-Centric)
```
1. Run static analysis
2. List all imports: CreateFile, RegSetValue, InternetOpen...
3. List all strings: http://..., HKLM\Run...
4. Flag everything suspicious
5. High false positives
```

### After (Cognitive Framework)
```
1. Hypothesis: "Enterprise stealer" (Attacker Lens)
2. Predict: Browser creds + network exfil + persistence
3. Hunt: Find DPAPI + HTTP POST + Run key (Hypothesis Loop)
4. Recognize: Known stealer pattern (Chunking)
5. Note: No anti-debug = commodity (Negative Space)
6. Test: Benign explanation fails (Occam's Razor)
7. Reconstruct: Collection → Exfil → Persistence (Kill Chain)
8. Confidence: 85% (evidence-based)
```

## 🎓 Learning Path

1. **Read**: `COGNITIVE_FRAMEWORK.md` - Full framework explanation
2. **Study**: `prompts/gandalf_system_prompt.md` - See framework encoded
3. **Compare**: `prompts/boromir_system_prompt.md` vs `prompts/legolas_system_prompt.md` - Different models for different roles
4. **Apply**: Update your agents with framework thinking
5. **Test**: Run analysis, observe hypothesis-driven behavior

## 📚 Resources

- **USENIX RE-Mind (2022)**: Original research paper
- **MITRE Cognitive Models**: Formal RE thinking models
- **CCDCOE**: Malware analysis best practices
- **FIRST**: Incident response frameworks

## 🔑 Remember

> "This is not about tools. This is about **encoding expert cognition**."

Every agent must think through:
1. What's the attacker trying to achieve? (Attacker Lens)
2. What layer am I on? (Layered Abstraction)
3. Is this a known pattern? (Chunking)
4. What's my hypothesis? (Hypothesis Loop)
5. What's missing? (Negative Space)
6. What does this imply? (Second-Order)
7. What's the simplest explanation? (Occam's Razor)
8. Where in the kill chain? (Temporal Reasoning)

**This is MORDOR's foundation.**
