# MORDOR Skill: Component Mapper

Phase 4 of the MORDOR pipeline. Decompile the binary with Ghidra, independently cross-validate with radare2, then produce a structured component map and call graph. **LEGOLAS and ELROND must agree before anything is flagged.**

## Ghidra Decompilation (LEGOLAS)

### Pre-Flight Configuration

Run these before every Ghidra session. Failure to do so will produce false positives.

```
Disable Aggressive Instruction Finder
  → Analysis → Auto Analysis → Uncheck "Aggressive Instruction Finder"
  
Disable Stack Analysis for Packed Binaries
  → Analysis → Auto Analysis → Uncheck "Stack Analysis"
  → Reason: Packed binaries have synthetic/virtual stacks that confuse the analyzer

Enable:
  ✓ Data Reference
  ✓ Function ID
  ✓ Decompiler Parameter ID
  ✓ Call Convention Analysis
```

### Function Categorization

After auto-analysis, manually categorize every function. Use LEGOLAS's naming convention:

- `FUN_<offset>` — unknown/non-critical helper
- `enc_<name>` — encryption/decryption routine (confirmed via crypto constants)
- `net_<name>` — network operation
- `inj_<name>` — process injection
- `pers_<name>` — persistence mechanism
- `anti_<name>` — anti-analysis / anti-debug
- `str_<name>` — string decryption / deobfuscation at runtime

### XREF Graphing

For every function flagged in Phase 3 hypotheses:
1. List all XREFs to the function
2. List all XREFs from the function (calls out)
3. Identify calling depth — root functions call depth-1 which call depth-2, etc.

```bash
# Ghidra script equivalent via LEGOLAS
legolas.xref_to("VirtualAllocEx")   # → [FUN_00401234, FUN_00405678]
legolas.xref_from("FUN_00401234")   # → [VirtualAllocEx, WriteProcessMemory, CreateRemoteThread]
```

Rule: If a flagged import has **no XREF (no caller)**, it is NOT a signal. Downgrade to INFO.

### Call Graph Generation

Generate a DOT-format call graph focused on suspicious functions:

```dot
digraph callgraph {
  rankdir=TB;
  node [shape=box, style=rounded];
  
  "FUN_00401234" [color=red, label="inj_main\n(0x401234)"];
  "VirtualAllocEx" [color=orange];
  "WriteProcessMemory" [color=orange];
  "CreateRemoteThread" [color=orange];
  
  "FUN_00401234" -> "VirtualAllocEx";
  "FUN_00401234" -> "WriteProcessMemory";
  "FUN_00401234" -> "CreateRemoteThread";
}
```

Save to `call_graph.dot`. Include only functions with XREF connections to Phase 3 hypotheses.

## Radare2 Cross-Validation (ELROND)

Run independently after Ghidra. Compare results.

```bash
r2 -A sample.bin
[0x00400000]> afl              # list all functions
[0x00400000]> axt sym.VirtualAllocEx  # XREFs TO
[0x00400000]> axf sym.VirtualAllocEx  # XREFs FROM
[0x00400000]> s sym.entry0
[0x00400000]> pdd              # decompile (r2ghidra plugin)
```

### Agreement Rules

| Scenario | Action |
|----------|--------|
| Ghidra + radare2 agree on function boundary and XREF | ACCEPT — flag with confidence |
| Ghidra says caller, radare2 says no XREF | RECOMPUTE — run both again |
| Ghidra says no XREF, radare2 confirms no XREF | DOWNGRADE — signal is dead |
| Tools disagree on decompiled output | SARUMAN arbitration (Phase 5) |

**Anti-False-Positive Gate**: No function may be flagged without both Ghidra and radare2 independently confirming its XREF chain.

## Output Artifacts

### component_map.json

```json
{
  "functions": {
    "FUN_00401234": {
      "name": "inj_main",
      "offset": "0x401234",
      "size": 248,
      "xrefs_to": 1,
      "xrefs_from": 7,
      "calls": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
      "hypothesis": "INJ-001",
      "ghidra_analysis": "confirmed",
      "radare2_analysis": "confirmed"
    }
  },
  "total_functions": 142,
  "flagged_functions": 3,
  "ghidra_radare2_agreement": 1.0
}
```

### call_graph.dot

Full directed graph of flagged functions and their callees.

## Verification Checklist

- [ ] Aggressive Instruction Finder disabled
- [ ] Stack Analysis disabled (if packed)
- [ ] Every Phase 3 hypothesis has at least one corresponding function entry
- [ ] Every flagged function has XREFs confirmed by BOTH tools
- [ ] `component_map.json` written and valid JSON
- [ ] `call_graph.dot` renders without errors (`dot -Tsvg call_graph.dot -o call_graph.svg`)
