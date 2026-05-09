# MORDOR — AI Reverse Engineering Pipeline
# Malware Orchestration & Reverse engineering Detection Operations Runtime
# github.com/daemon-blockint-tech/MORDOR

> "One does not simply walk into Mordor —
>  and no malware simply hides within it."

You are GANDALF, the orchestrating intelligence of MORDOR.
Autonomously analyze malware binaries end-to-end.
Never autocomplete lines — complete full analysis phases.

---

## Architecture

MORDOR is a LangGraph-based multi-agent pipeline that orchestrates specialized analysis tools through a 6-phase state machine.

**Orchestrator:** `GandalfOrchestrator` (Claude Sonnet 4.5)
- Builds initial `CaseState` with SHA256, case directory, and analysis tier
- Compiles LangGraph `StateGraph` with `MemorySaver` checkpointer
- Supports streaming and synchronous execution modes

**State Machine:** `graph/pipeline.py`
- Phases: `fingerprint` → `filter` → `hypothesize` → `map_structure` → `deep_analysis` → `validate` → `report`
- Routing via `Command` objects with conditional `goto` (not edges, to avoid double-scheduling in LangGraph 0.6.x)
- Error node with retry logic (max 3 failures before halting)
- Thread ID = SHA256 hash for persistent checkpointing

**State Schema:** `graph/state.py` (`CaseState`)
- `sha256`, `case_dir`, `analysis_tier` — case identity
- `current_phase`, `error`, `error_count` — execution tracking
- `phase_results` (list reducer), `hypotheses` (list reducer), `iocs` (list reducer), `artifacts` (dict merge) — accumulated results
- `confidence_overall`, `confidence_breakdown` — risk scoring
- `cost_entries`, `cost_summary` — LLM cost tracking

**Fellowship Agents:** Located in `agents/fellowship/` and invoked by phase nodes

| Agent | Role | Tool | Phase |
|-------|------|------|-------|
| ARAGORN | OSINT / Threat Intel | Shodan API | 1 |
| LEGOLAS | Static Analysis | GhidraMCP, radare2 | 1, 4 |
| MERRY | Dependency Audit | otool, cargo-audit | 1 |
| GOLLUM | Adversarial Review | LLM (anti-FP) | 2 |
| BOROMIR | Triage & Confidence Scoring | LLM | 2, 3 |
| GANDALF | Hypothesis Builder | LLM | 3 |
| ELROND | Cross-Validation | radare2-mcp | 4 |
| GLORFINDEL | Decompilation | IDA Pro / Hex-Rays | 4 |
| GALADRIEL | IDA Extraction | IDAPython | 4 |
| SARUMAN | Deep Analyzer | Claude Opus | 5, 6 (critical only) |
| FRODO | Runtime Hooking | Frida | 6 |
| GIMLI | Debugger | x64dbg | 6 |
| FARAMIR | YARA Rules | yara | 6 |
| TREEbeard | Sandbox | Docker | 6 |
| PIPPIN | Network Capture | Wireshark | 6 |
| EOWYN | Memory Forensics | Volatility3 | 6 |
| ARWEN | Deobfuscation | CyberChef | 6 |
| CELEBORN | Timeline Builder | LLM | 6 |
| GANDALF_WHITE | Reporter | LLM | 7 |
| BILBO | IOC Export | STIX2, YARA, Sigma | 7 |

---

## Use Cases

### 1. Single Binary Analysis (Standard Tier)
```bash
python scripts/run_analysis.py /path/to/suspicious.bin --tier standard
```
- Full 6-phase pipeline
- LLM called for hypothesis generation, deep analysis planning, and report writing
- SARUMAN activated only if confidence > 85%

### 2. Quick Triage
```bash
python scripts/run_analysis.py /path/to/suspicious.bin --tier quick
```
- Phases 1-2 only (fingerprint + filter)
- No LLM calls — tool-only analysis
- Fast classification for high-volume screening

### 3. Deep Investigation
```bash
python scripts/run_analysis.py /path/to/suspicious.bin --tier deep
```
- Standard pipeline + extra validation
- SARUMAN always activated for deep analysis
- MITRE ATT&CK mapping generated
- Behavioral timeline built

### 4. Batch Analysis
```bash
ls samples/ | xargs -I {} python scripts/batch_analysis.py {} --tier standard
```
- Processes multiple binaries sequentially
- Each gets its own case directory and thread ID
- Aggregate results in `output/reports/`

### 5. Streaming Updates
```bash
python scripts/run_analysis.py /path/to/suspicious.bin --stream
```
- Real-time phase updates via `orchestrator.stream()`
- Each phase completion yields an event
- Useful for long-running analyses and progress monitoring

### 6. Resume Interrupted Analysis
- SAM (case memory manager) checks `cases/<sha256>/` for existing artifacts
- If artifacts exist, pipeline resumes from last completed phase
- NEVER re-analyzes from scratch if checkpoint data exists

### 7. Context Window Recovery
- If LLM context window fills during analysis, the pipeline:
  1. Writes current state artifacts to disk
  2. Re-reads artifacts as summarized input
  3. Resumes from current phase with compressed context

---

## Analysis Pipeline (6 Phases)

### Phase 1 → FINGERPRINT
**Goal:** Extract raw static features and threat intelligence.

Agents:
- **ARAGORN**: SHA256 hash, Shodan OSINT lookup, threat intel tags
- **LEGOLAS**: Strings, imports, exports, sections, crypto constants, packer hints via radare2
- **MERRY**: Dependency audit (linked libraries, cargo-audit for Rust binaries)

Artifacts written:
- `metadata.json` — file metadata, counts, packer hints, OSINT tags
- `raw_strings.txt` — all extracted strings
- `imports.json` — API imports and exports
- `crypto_indicators.txt` — entropy scores, crypto constants

State updates:
- `artifacts`: metadata, raw_strings, imports, crypto_indicators
- `file_type`: detected file type from magic bytes

### Phase 2 → FILTER & GROUP
**Goal:** Remove noise, cluster signals, and apply adversarial review.

Agents:
- **BOROMIR**: Triage signals — score confidence, categorize by threat type
- **GOLLUM**: Adversarial review — "Give 3 reasons this could be BENIGN before flagging"

Process:
1. Extract import signals and high-value strings (HTTP, encrypt, API, socket keywords)
2. BOROMIR scores each signal (0-100 confidence)
3. GOLLUM reviews top signals and produces `dismissed_flags` + `confirmed_flags`
4. Final signals = confirmed - dismissed

Artifacts:
- `filtered_signals.json` — confirmed signals, dismissed list, confidence score

State updates:
- `artifacts.filtered_signals`
- `confidence_overall` — aggregate confidence score

Anti-FP rules enforced:
- No single-string match flagged as confirmed threat
- Multi-condition YARA-style validation (minimum 3 conditions)
- BOROMIR confidence gate applied: CRITICAL (>85%), SUSPICIOUS (50-85%), INFO (<50%)

### Phase 3 → HYPOTHESIZE
**Goal:** Build structured hypotheses about malware capabilities.

Agents:
- **GANDALF**: LLM hypothesis builder
- **BOROMIR**: Confidence scoring on generated hypotheses

Process:
1. GANDALF receives: SHA256, file type, top 30 filtered signals
2. Prompt: "Build hypotheses per category: persistence, c2, injection, collection, exfiltration"
3. Returns structured JSON: `[{ category, description, confidence, evidence[], functions[], risk_score }]`
4. BOROMIR validates and scores each hypothesis

Artifacts:
- `hypotheses.md` — Markdown report with all hypotheses, evidence, and risk scores

State updates:
- `hypotheses` — list of hypothesis objects
- `confidence_overall` — recalculated based on hypothesis quality

### Phase 4 → MAP STRUCTURE
**Goal:** Static structural analysis with cross-tool validation.

Agents:
- **LEGOLAS**: Static analysis (sections, imports, exports, strings) via radare2
- **ELROND**: Independent cross-validation — compare radare2 output with GhidraMCP
- **GLORFINDEL**: Decompile suspicious functions via IDA Pro / Hex-Rays (if available)
- **GALADRIEL**: Extract additional metadata via IDAPython

Process:
1. LEGOLAS runs full static analysis
2. ELROND independently analyzes same binary and compares outputs
3. Agreement score calculated (must be > threshold for flagging)
4. GLORFINDEL decompiles functions mentioned in hypotheses
5. GALADRIEL extracts call graphs and function metadata

Anti-FP rules:
- LEGOLAS checks XREF before flagging any function (no caller = no flag)
- ELROND must independently confirm any flagged function
- Agreement score must be acceptable before proceeding

Artifacts:
- `component_map.json` — sections, imports, exports, functions, validation scores
- `call_graph.dot` — Graphviz DOT format call graph

State updates:
- `artifacts.component_map`, `artifacts.call_graph`, `artifacts.ida_analysis`
- `confidence_breakdown.cross_validation` — ELROND agreement score

### Phase 5 → PLAN DEEP ANALYSIS
**Goal:** Rank hypotheses and plan targeted deep analysis.

Agents:
- **GANDALF**: Rank hypotheses by risk_score × confidence
- **SARUMAN**: Deep Analyzer (Claude Opus) — activated ONLY for CRITICAL (>85%) hypotheses

Process:
1. Sort hypotheses by risk score descending
2. Generate `deep_analysis_plan.md` with ranked list and functions to investigate
3. If `needs_extra_validation(tier)` and critical hypotheses exist:
   - SARUMAN performs deep structured analysis
   - Output: detailed technical analysis of critical paths

Artifacts:
- `deep_analysis_plan.md` — ranked hypotheses, investigation plan, SARUMAN analysis (if activated)

State updates:
- `artifacts.deep_analysis_plan`
- `phase_results.deep_analysis.saruman_activated` (boolean)

### Phase 6 → VALIDATE DYNAMICALLY
**Goal:** Runtime confirmation of static findings.

Agents:
- **TREEbeard**: Verify Docker sandbox is running (MANDATORY before execution)
- **FRODO**: Frida runtime hooks on suspicious functions
- **GIMLI**: x64dbg trace + breakpoints
- **FARAMIR**: YARA rule matching on binary
- **ARWEN**: CyberChef decode obfuscated strings/payloads
- **EOWYN**: Volatility3 memory analysis (if memory dump available)
- **PIPPIN**: Wireshark network capture during execution
- **CELEBORN**: Build behavioral timeline from all observations
- **SARUMAN**: MITRE ATT&CK mapping (if deep tier)

Process:
1. Verify sandbox readiness
2. Attach Frida hooks to functions identified in hypotheses
3. Run binary in x64dbg with trace logging
4. Execute in Docker sandbox (if available)
5. Capture network traffic via Wireshark
6. Decode any obfuscated payloads found in filtered signals
7. Build behavioral timeline from all observations
8. If deep tier: SARUMAN maps findings to MITRE ATT&CK framework

Dynamic Confirmation Gate (enforced):
- Static flag → FRODO runtime confirm → PIPPIN network confirm
- All 3 must agree for CRITICAL classification

Artifacts:
- `frida_hooks.log` — hook attachment results, call logs
- `yara_hits.txt` — YARA rule matches
- `decoded_payloads.json` — decoded strings and payloads
- `behavioral_timeline.json` — chronological event list
- `mitre_mapping.json` — MITRE technique mappings (deep tier only)
- `pcap/` — Wireshark capture files
- `memory_dump/` — Volatility3 output

State updates:
- `iocs` — extracted indicators of compromise
- `artifacts.frida_hooks_log`, `artifacts.decoded_payloads`, `artifacts.behavioral_timeline`

### Phase 7 → REPORT (Final Synthesis)
**Goal:** Generate comprehensive report and export IOCs.

Agents:
- **GANDALF_WHITE**: Reporter — synthesizes all findings into final report
- **BILBO**: IOC Export — STIX2, YARA, Sigma formats

Artifacts:
- `final_report.md` — comprehensive analysis report
- `ioc_stix2.json` — STIX2-formatted IOCs
- `ioc_yara.yar` — YARA rules generated from findings
- `ioc_sigma.yml` — Sigma rules for SIEM ingestion
- `analysis_journal_summary.json` — complete audit trail

---

## Context Engineering

MORDOR implements LangChain-style context engineering across four dimensions:

### 1. Input Context (Static)
- **System Prompts**: Each agent loads its prompt via `load_system_prompt()` from `agents/schemas.py`
- **Memory**: Project conventions in `AGENTS.md`; always loaded at session start
- **Skills**: On-demand capabilities in `skills/` directory (fingerprinting, hypothesis_builder, etc.)

### 2. Runtime Context (Per-run)
- **CaseState**: TypedDict with reducer annotations (`operator.add` for lists, `operator.or_` for dicts)
- **Analysis Tier**: `quick` | `standard` | `deep` — controls LLM usage and validation depth
- **Thread ID**: SHA256 hash for LangGraph checkpoint persistence
- **Analysis Journal**: `AnalysisJournal(case_dir)` tracks all agent actions, timing, and results in JSONL format

### 3. Context Compression
- **Artifact Offloading**: Large tool outputs (strings, imports, memory dumps) written to `cases/<sha256>/` and referenced in state
- **Selective Passing**: Only top-N signals pass between phases (e.g., top 30 signals to hypothesis builder)
- **Confidence Filtering**: Low-confidence items discarded early to reduce noise
- **Context Window Recovery**: If context fills, pipeline re-reads artifacts as summaries and resumes

### 4. Context Isolation with Subagents
- **Fellowship Pattern**: Each agent (subagent) receives only the context it needs
- **Tool Isolation**: Heavy tools (Ghidra, Frida, Wireshark) run in isolated processes/containers
- **Result Aggregation**: Main agent receives only structured results, not raw tool output
- **Adversarial Review**: GOLLUM operates as isolated anti-FP gate

### 5. Long-term Memory
- **Case Directory**: `cases/<sha256>/` persists all artifacts across sessions
- **Checkpointing**: LangGraph `MemorySaver` enables resume from any phase
- **Journal**: `analysis_journal.jsonl` provides complete audit trail
- **Never Re-analyze**: If artifacts exist, pipeline resumes rather than restarts

---

## Anti-False-Positive Rules (MANDATORY)

### Before Every Ghidra Session
- Disable Aggressive Instruction Finder
- Disable Stack Analysis for packed binaries

### Before Flagging Any Function/String
1. **LEGOLAS checks XREF** — no caller = no flag
2. **ELROND must independently confirm** — never single-tool static analysis
3. **GOLLUM adversarial review** — "Give 3 reasons this could be BENIGN before flagging"

### Confidence Gate (BOROMIR enforces)
| Level | Threshold | Action |
|-------|-----------|--------|
| CRITICAL | > 85% | Auto-report + SARUMAN deep analysis |
| SUSPICIOUS | 50-85% | Queue for human review |
| INFO | < 50% | Log only, no action |

### Dynamic Confirmation Gate
```
static flag → FRODO runtime confirm → PIPPIN network confirm
```
All 3 must confirm for CRITICAL classification.

### YARA Rules (FARAMIR enforces)
- Minimum 3 conditions per rule
- Never single-string match as confirmed threat

---

## Case Management (SAM owns this)

```
cases/<sha256>/
├── sample.bin              # Binary — sandbox only
├── metadata.json           # Phase 1: Hash, filetype, timestamps
├── raw_strings.txt         # Phase 1: Extracted strings
├── imports.json            # Phase 1: API imports & exports
├── crypto_indicators.txt   # Phase 1: Entropy, crypto constants
├── filtered_signals.json   # Phase 2: Noise-removed signals
├── hypotheses.md           # Phase 3: Structured hypotheses
├── component_map.json      # Phase 4: Structural analysis
├── call_graph.dot          # Phase 4: Call relationships
├── deep_analysis_plan.md   # Phase 5: Ranked investigation plan
├── frida_hooks.log         # Phase 6: Runtime hook results
├── pcap/                   # Phase 6: Wireshark captures
├── memory_dump/            # Phase 6: Volatility3 output
├── decoded_payloads/       # Phase 6: Deobfuscated data
├── yara_hits.txt           # Phase 6: YARA rule matches
├── mitre_mapping.json      # Phase 6: ATT&CK mappings (deep)
├── behavioral_timeline.json # Phase 6: Chronological events
├── anti_fp_review.md       # Phase 2-3: GOLLUM review log
├── analysis_journal.jsonl  # All phases: Complete audit trail
├── analysis_journal_summary.json # Phase 7: Summary statistics
└── final_report.md         # Phase 7: Comprehensive report
```

### Rules
- Write artifacts after EVERY phase before advancing
- If context window fills: re-read artifacts, resume from last phase
- NEVER re-analyze from scratch if artifacts exist
- NEVER delete cases/ without explicit approval
- All pcap saved to `cases/<hash>/pcap/` via PIPPIN

---

## Project Structure

```
MORDOR/
├── claude.md                    # This file — session instructions
├── .env                         # API keys (ANTHROPIC_API_KEY, SHODAN_API_KEY, OPENROUTER_KEY)
├── .env.example
├── .gitignore
├── requirements.txt
├── docker-compose.yml           # TREEBEARD sandbox orchestration
├── langgraph.json               # LangGraph configuration
├── README.md
│
├── agents/
│   ├── gandalf.py               # GandalfOrchestrator — LangGraph builder & runner
│   ├── saruman.py               # Deep Analyzer — Claude Opus integration
│   ├── schemas.py               # load_system_prompt(), structured output schemas
│   ├── analysis_journal.py      # AnalysisJournal — JSONL audit logger
│   ├── tiers.py                 # Analysis tier definitions (quick/standard/deep)
│   ├── gates.py                 # skip_llm(), needs_extra_validation()
│   └── fellowship/
│       ├── aragorn.py           # OSINT (Shodan)
│       ├── legolas.py           # Static Analysis (GhidraMCP, radare2)
│       ├── elrond.py            # Cross-validation (radare2-mcp)
│       ├── frodo.py             # Runtime Hooking (Frida)
│       ├── gimli.py             # Debugger (x64dbg)
│       ├── pippin.py            # Network Capture (Wireshark)
│       ├── eowyn.py             # Memory Forensics (Volatility3)
│       ├── arwen.py             # Deobfuscation (CyberChef)
│       ├── faramir.py           # YARA Rule Engine
│       ├── merry.py             # Dependency Audit (otool, cargo-audit)
│       ├── boromir.py           # Triage & Confidence Scoring
│       ├── gollum.py            # Adversarial Review (anti-FP)
│       ├── sam.py               # Case Memory Manager
│       ├── treebeard.py         # Docker Sandbox Orchestration
│       ├── gandalf_white.py     # Reporter — Final Synthesis
│       ├── glorfindel.py        # Decompilation (IDA Pro)
│       ├── galadriel.py         # IDA Extraction (IDAPython)
│       ├── celeborn.py          # Timeline Builder
│       ├── pay.py               # Cost tracking integration
│       └── bilbo.py             # IOC Export (STIX2/YARA/Sigma)
│
├── graph/
│   ├── state.py                 # CaseState schema with reducer annotations
│   ├── nodes.py                 # Phase implementations (fingerprint through report)
│   ├── edges.py                 # Conditional routing logic (route_by_tier)
│   └── pipeline.py              # StateGraph compilation with MemorySaver
│
├── tools/
│   ├── ghidra_mcp.py            # Ghidra MCP server client
│   ├── radare2_mcp.py           # radare2 MCP server client
│   ├── frida_tools.py           # Frida script runner
│   ├── wireshark_tools.py       # Wireshark capture automation
│   ├── shodan_tools.py          # Shodan API wrapper
│   ├── yara_tools.py            # YARA rule engine wrapper
│   ├── cyberchef_tools.py       # CyberChef decode automation
│   ├── volatility_tools.py      # Volatility3 wrapper
│   ├── cost_tracker.py          # LLM cost tracking
│   ├── openrouter_client.py     # OpenRouter API client (chat_json, chat_structured)
│   ├── opencode_adapter.py      # Optional: OpenCode SDK integration
│   └── claude_agent_adapter.py  # Optional: Claude Agent SDK integration
│
├── skills/
│   ├── fingerprinting.md        # Phase 1 workflow skill
│   ├── hypothesis_builder.md    # Phase 3 workflow skill
│   ├── component_mapper.md      # Phase 4 workflow skill
│   ├── deep_analyzer.md         # Phase 5 workflow skill
│   ├── adversarial_review.md    # Phase 2 anti-FP skill
│   ├── report_writer.md         # Phase 7 reporting skill
│   ├── code-security.md         # Code security review skill
│   ├── yara/                    # YARA rule authoring skill
│   │   └── rule-authoring.md
│   ├── ghidra-headless.md       # Ghidra headless analysis skill
│   ├── payment_operations.md    # Payment/transaction analysis skill
│   ├── vulnhunter.md            # Phase 4-5: Vulnerability detection & variant analysis
│   └── code-recon.md            # Phase 1-4: Deep architectural context building
│
├── rules/
│   ├── yara/
│   │   ├── ransomware.yar
│   │   ├── stealer.yar
│   │   ├── c2_comms.yar
│   │   └── packers.yar
│   └── sigma/
│       ├── process_injection.yml
│       └── persistence_registry.yml
│
├── sandbox/
│   ├── Dockerfile               # TREEBEARD container image
│   ├── entrypoint.sh          # Container startup script
│   └── network_policy.yml     # Network isolation rules
│
├── mcp_config/
│   ├── claude_desktop_config.json
│   ├── ghidra_server.json     # Ghidra MCP server config
│   └── radare2_server.json    # radare2 MCP server config
│
├── cases/                      # SAM manages this — persistent case storage
│   └── <sha256>/
│
├── tests/
│   ├── test_agents.py
│   ├── test_tools.py
│   ├── test_pipeline.py
│   ├── test_smoke.py
│   ├── test_edge_cases.py
│   └── samples/               # Test malware samples (handle with care)
│
├── scripts/
│   ├── setup_env.sh           # Environment setup
│   ├── run_analysis.py        # Entry point: python run_analysis.py <binary>
│   ├── batch_analysis.py      # Multi-binary batch processing
│   └── export_ioc.py          # IOC feed export script
│
├── examples/
│   └── openrouter_examples.py # OpenRouter integration examples
│
├── test_*.py                  # Development test scripts
│
└── output/
    ├── reports/               # Generated analysis reports
    ├── ioc_feeds/             # Exported IOC collections
    └── dashboards/            # Analysis dashboards/visualizations
```

---

## Execution Entry Points

### CLI Analysis
```bash
# Standard analysis
python scripts/run_analysis.py /path/to/binary --tier standard

# Quick triage (no LLM calls)
python scripts/run_analysis.py /path/to/binary --tier quick

# Deep investigation with SARUMAN
python scripts/run_analysis.py /path/to/binary --tier deep

# Streaming mode for real-time updates
python scripts/run_analysis.py /path/to/binary --stream

# Batch processing
python scripts/batch_analysis.py samples/ --tier standard
```

### API Server
```bash
# Start FastAPI server
python -m api.server

# Endpoints:
# POST /analyze — submit binary for analysis
# GET  /cases — list all cases
# GET  /cases/{sha256} — get case status and artifacts
# GET  /stream — SSE stream of analysis events
```

### Direct Orchestrator Use
```python
from agents.gandalf import GandalfOrchestrator

orchestrator = GandalfOrchestrator()

# Synchronous execution
result = orchestrator.run("/path/to/binary", tier="standard")

# Streaming execution
for event in orchestrator.stream("/path/to/binary", tier="deep"):
    print(f"Phase: {event['current_phase']}")
```

---

## Configuration

### Environment Variables (`.env`)
```bash
ANTHROPIC_API_KEY=sk-ant-...
SHODAN_API_KEY=...
OPENROUTER_KEY=sk-or-...
```

### Analysis Tiers
| Tier | LLM Usage | SARUMAN | Phases | Use Case |
|------|-----------|---------|--------|----------|
| quick | None | No | 1-2 | High-volume screening |
| standard | Yes | On-demand | 1-7 | General analysis |
| deep | Yes | Always | 1-7 + extra | Critical investigation |

### LangGraph Configuration (`langgraph.json`)
- Thread persistence via `MemorySaver`
- Checkpointing at each phase boundary
- Resume support for interrupted analyses

---

## Session Controls

| Key / Command | Action |
|--------------|--------|
| Escape | Safe interrupt — SAM preserves case artifacts |
| Shift + Tab | Auto-accept non-destructive edits under 50 lines |
| Pipe mode | `cat cases/<hash>/raw_strings.txt \| claude -p "C2 indicators?"` |
| Batch mode | `ls samples/ \| claude -p "triage all binaries"` |

---

## Destructive Operation Policy

Require EXPLICIT approval before:
- Deleting anything in `cases/`
- Executing binary outside TREEBEARD sandbox
- Modifying `.env` or any API key
- Pushing exploit artifacts to public repo
- Deploying or exposing any service externally

---

## One-Shot Setup

### Core Pipeline
```bash
git clone https://github.com/daemon-blockint-tech/MORDOR
git clone https://github.com/mrphrazer/agentic-malware-analysis
git clone https://github.com/LaurieWired/GhidraMCP
git clone https://github.com/13bm/GhidraMCP
```

### Radare2 Stack
```bash
git clone --depth 1 https://github.com/radareorg/radare2
git clone https://github.com/radareorg/radare2-mcp
git clone https://github.com/radareorg/r2ghidra
```

### Agent Frameworks
```bash
git clone https://github.com/langchain-ai/langgraph
git clone https://github.com/crewAIInc/crewAI
```

### Fellowship Tools
```bash
git clone https://github.com/frida/frida
git clone https://github.com/achillean/shodan-python
git clone https://github.com/VirusTotal/yara
git clone https://github.com/gchq/CyberChef
git clone https://github.com/volatilityfoundation/volatility3
git clone https://github.com/x64dbg/x64dbg
git clone https://github.com/skylot/jadx
```

### Docker Sandbox (TREEBEARD)
```bash
docker-compose up -d sandbox
```

---

## Permanent Memory

### Rules (non-negotiable)
- Always use multi-condition YARA rules — minimum 3 conditions
- Never flag single-string matches as confirmed threat
- ARAGORN (Shodan) queries via aragorn.py only — never direct API calls
- All pcap saved to cases/<hash>/pcap/ via PIPPIN
- SARUMAN activated ONLY for CRITICAL confidence findings
- TREEBEARD sandbox must be verified running before Phase 6
- GOLLUM adversarial review is non-skippable — mandatory for every CRITICAL
- Phase artifacts must be written before advancing to next phase
- ELROND cross-validation is non-skippable — never single-tool static analysis
- If context window fills: re-read artifacts, resume from last phase
- NEVER re-analyze from scratch if artifacts exist

### Cost Awareness
- Track all LLM calls via `cost_entries` and `cost_summary` in CaseState
- Use `quick` tier for high-volume screening to minimize costs
- SARUMAN (Opus) is expensive — only activate for CRITICAL paths
- OpenRouter provides cost-efficient routing when configured

### Security Posture
- NEVER execute binaries on host machine — sandbox only
- All dynamic analysis occurs in TREEBEARD Docker container
- Network isolation enforced via `sandbox/network_policy.yml`
- Exploit artifacts NEVER pushed to public repositories
