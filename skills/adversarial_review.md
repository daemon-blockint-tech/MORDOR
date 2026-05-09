# MORDOR Skill: Adversarial Review (GOLLUM)

Mandatory anti-false-positive gate. Before any signal or function is flagged as malicious, GOLLUM must argue for its innocence. This is not optional — it is the last gate before a finding becomes real.

## Core Rule: Three Benign Reasons

Before writing any finding, produce exactly three distinct reasons the observed behavior COULD be legitimate.

```
BAD:  "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread = injection"
GOOD: "This could be benign because:
       1. Legitimate software updaters use WriteProcessMemory 
          for patch application
       2. CreateRemoteThread is used by EDR tools for injection
          of monitoring DLLs
       3. The target process (svchost.exe) suggests a Windows 
          service patching flow"
```

If you cannot produce three plausible benign reasons, that itself is suspicious — but still record the three best attempts.

## XREF Verification Checklist

Run this for EVERY flagged function:

- [ ] Function has at least one caller (XREF TO exists)
- [ ] Caller is not dead code (reachable from entry point)
- [ ] The XREF is in a code section, not data
- [ ] LEGOLAS and ELROND agree on the XREF count
- [ ] No thunk/wrapper confusion (e.g., import thunk vs. actual implementation)

**If any check fails**, downgrade confidence by one full tier (CRITICAL → SUSPICIOUS → INFO).

## False Positive Patterns to Recognize

### Pattern 1: Compiler-Generated Helper
Functions named `__security_init_cookie`, `__chkstk`, `_except_handler4` are compiler intrinsics. Never flag them.

### Pattern 2: Legitimate Crypto Libraries
OpenSSL, Crypto++, BCrypt, CNG — these ship with thousands of binaries. The presence of AES constants does not mean the binary is malicious. Check:
- Is crypto linked statically (many functions) or implemented ad-hoc (few)?
- Is there application-specific code calling the crypto?

### Pattern 3: Legitimate Anti-Debug
Many legitimate applications check for debuggers:
- `IsDebuggerPresent` is called by Chrome, Firefox, and most DRM
- `NtQueryInformationProcess` is used by task managers and system monitors

Check: Is the anti-debug call connected to malicious behavior (e.g., abort if debugger found), or is it a standard compatibility check?

### Pattern 4: Legitimate Persistence
Not all persistence is malware:
- `RegSetValue` for `HKCU\...\Run` is used by Discord, Spotify, Teams
- `CreateService` is used by legitimate drivers and server software

Check: Is the binary signed? Does it have a known publisher? Is the persistence path in a standard, documented location?

### Pattern 5: Legitimate Injection
Some legitimate software uses process injection:
- EDR/AV agents inject into all processes for monitoring
- Screen readers inject into applications for accessibility
- Game overlays (Discord, Steam) inject into game processes

Check: Is the injected content shellcode or a signed DLL? What is the target process?

## Confidence Adjustment Rules

Apply these in order, top to bottom:

| Condition | Adjustment |
|-----------|------------|
| 3+ benign reasons are strong (no stretch) | −15 points |
| At least 1 benign reason is weak/stretching | No adjustment |
| Zero benign reasons found | +10 points (suspicious silence) |
| Function has no caller (dead code) | Reset to INFO (0–10 points) |
| LEGOLAS + ELROND disagree | Cap at SUSPICIOUS (max 75 points) |
| Function is compiler-generated (Pattern 1) | Reset to INFO |
| Function uses well-known OSS crypto (Pattern 2) | −20 points |
| Function is signed by known vendor | −25 points |
| ARAGORN confirms prior malware family | +30 points |

## The Anti-FP Review Record

Write every review to `anti_fp_review.md`:

```markdown
## Anti-FP Review: FUN_00401234 (inj_main)

**Hypothesis**: INJ-001 — Process Injection
**Current Confidence**: 82% (SUSPICIOUS)

### Three Benign Reasons
1. EDR injection agents use identical API pattern
   Strength: WEAK — no EDR signature in binary strings
2. Could be a legitimate installer performing DLL injection
   Strength: WEAK — no installer resources found
3. Target process explorer.exe could be for shell extension
   Strength: WEAK — no shell extension COM registration

### XREF Check: PASS
- Caller: FUN_00401000 → confirmed by both Ghidra and radare2
- Reachable from entry: YES (entry → 0x401000 → 0x401234)
- Code section: YES (.text)

### Pattern Check
- Compiler helper? NO
- OSS Crypto? NO
- Signed? SIGNED by "Example Corp" — WOULD CHECK

### Adjustment Applied
-15 (signed by known vendor)

### Final Confidence: 67% (SUSPICIOUS — queue for human review)

### Verdict: SUSPICIOUS — ESCALATE
```

## When to Escalate vs. Suppress

| Outcome | Action |
|---------|--------|
| Confidence > 85% after adjustment | ESCALATE to SARUMAN |
| Confidence > 50% after adjustment | Queue for human review |
| Confidence < 50% after adjustment | LOG ONLY — no further action |
| All benign reasons are strong AND XREF negative | SUPPRESS — false positive |

## Rules

1. GOLLUM review is **mandatory** for every function that would be flagged
2. GOLLUM review is **not skippable** even for "obviously" malicious findings
3. If GOLLUM downgraded a finding and human review overturns it, log the lesson learned
4. Never let confidence exceed 95% — there is always uncertainty in static analysis
5. The anti-FP review must be committed to `anti_fp_review.md` before any flag is raised
