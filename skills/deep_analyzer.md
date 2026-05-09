# MORDOR Skill: Deep Analyzer

Phase 5 of the MORDOR pipeline. Rank all flagged functions by risk score, then activate SARUMAN (Claude Opus) exclusively for CRITICAL paths. This is the most expensive phase — be surgical.

## Risk Scoring

Score every function from `component_map.json` on three dimensions:

### 1. API Risk (0–40 points)

| API Category | Points | Examples |
|--------------|--------|----------|
| Process injection | 40 | `CreateRemoteThread`, `QueueUserAPC`, `NtUnmapViewOfSection` |
| Persistence | 30 | `RegSetValue`, `CreateService`, `SCHRegSetPath` |
| Anti-debug | 25 | `IsDebuggerPresent`, `NtQueryInformationProcess`, `NtSetInformationThread` |
| Cryptography | 20 | `CryptEncrypt`, `BCryptEncrypt`, custom crypto constants |
| Network | 15 | `socket`, `send`, `WSASocket`, `WinHttpOpen` |
| File I/O | 10 | `CreateFile`, `WriteFile`, `FindFirstFile` |

Score = points of highest API category + 5 for each additional category present.

### 2. Complexity Risk (0–30 points)

| Metric | Points | Threshold |
|--------|--------|-----------|
| Cyclomatic complexity | +10 | > 20 branches |
| Function size | +10 | > 500 bytes |
| Nested calls | +10 | > 5 call depth |
| Obfuscated control flow | +15 | Opaque predicates detected |
| Stack strings | +10 | Character-by-character string construction |

### 3. Hypothesis Alignment (0–30 points)

- **+15** if function directly matches a Phase 3 hypothesis
- **+10** if function is in the XREF chain of a CRITICAL hypothesis
- **+5** if function connects two separate hypothesis categories
- **−15** if XREF chain is incomplete (no caller)

### Final Score

```
risk_score = api_risk + complexity_risk + hypothesis_alignment
```

| Score | Label | Action |
|-------|-------|--------|
| ≥ 85 | CRITICAL | Activate SARUMAN for full decompilation |
| 50–84 | SUSPICIOUS | GANDALF-level analysis, queue for human review |
| < 50 | INFO | Log only — no action |

## SARUMAN Activation

SARUMAN (Claude Opus) is called ONLY for functions scoring ≥ 85.

### SARUMAN Prompt Template

```
You are SARUMAN, deep analyzer of the MORDOR pipeline.
Analyze the following decompiled function from {sample_name}.

Context:
- Hypothesis: {hypothesis_id} ({hypothesis_category})
- Risk Score: {risk_score}/100
- API Risk: {api_risk}/40
- Complexity Risk: {complexity_risk}/30
- Hypothesis Alignment: {hypothesis_alignment}/30
- XREF Chain: {xref_chain}

Decompiled Code:
```c
{decompiled_function}
```

Instructions:
1. Identify the function's true purpose in 1-2 sentences
2. Map any obfuscation / anti-analysis techniques present
3. Trace data flow: where does input come from, where does output go?
4. Identify decryption/decode loops and their algorithm
5. State with confidence: is this malicious or benign?
```

### SARUMAN Output Format

```markdown
## SARUMAN Analysis: FUN_00401234 (inj_main)

**Purpose**: Process injection launcher — allocates memory in
  target process, writes shellcode, executes via CreateRemoteThread.

**Obfuscation**: 
- API hash resolution (dynamically resolves CreateRemoteThread)
- Call to dec_string() at 0x401100 decrypts "ntdll.dll" at runtime

**Data Flow**:
  str_00402000 (encrypted shellcode) 
    → dec_loop at 0x401180 (XOR with 0xAB key) 
    → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread

**Algorithm**: Single-byte XOR (0xAB) on a 272-byte shellcode buffer.
  Key verified: 0xAB appears as immediate in dec_loop.

**Verdict**: MALICIOUS — CRITICAL (98% confidence)
  Process injection with runtime-decrypted shellcode.
```

## Data Flow Analysis

For each CRITICAL function, trace:

1. **Input origin**: Function parameter? Global buffer? Registry? Network?
2. **Data transformation**: Encrypted → decrypt → plaintext? Encoded → decode?
3. **Output destination**: Write to process? Write to disk? Send over socket?

Use taint tracking markers:

```python
taint = TaintTracker()
taint.mark_source(0x401100, "dec_string_output")
taint.propagate(0x401200, "VirtualAllocEx", arg=1)  # size
taint.propagate(0x401250, "WriteProcessMemory", arg=2)  # buffer
taint.propagate(0x401300, "CreateRemoteThread", arg=1)  # start address
```

## When NOT to Activate SARUMAN

- Function scores < 85
- Function is a library function misidentified by Ghidra (check function ID)
- Function has no data flow path from input to output (dead code)
- GOLLUM adversarial review produced a convincing benign explanation
- ELROND disagrees with LEGOLAS on the function boundary
