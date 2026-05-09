<p align="center">
  <img src="mordor-logo-white.png" alt="MORDOR" width="400"/>
</p>

<p align="center">
  <strong>Malware Orchestration & Reverse engineering Detection Operations Runtime</strong>
  <br>
  <em>"One does not simply walk into Mordor — and no malware simply hides within it."</em>
  <br>
  <a href="https://github.com/daemon-blockint-tech/MORDOR">github.com/daemon-blockint-tech/MORDOR</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12-blue?logo=python" alt="Python 3.12"/>
  <img src="https://img.shields.io/badge/langgraph-orchestrated-green" alt="LangGraph"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"/>
</p>

---

## What is MORDOR?

MORDOR is an **AI-driven reverse engineering pipeline** that autonomously analyzes malware binaries end-to-end. It orchestrates a fellowship of specialized agents — each wielding industry-standard tools — through a 6-phase analysis pipeline, from fingerprinting through dynamic validation, all coordinated by **GANDALF** (the orchestrator) running on LangGraph.

Built for malware analysts, reverse engineers, and security researchers who want to scale their analysis without sacrificing depth or accuracy.

---

## Architecture

### The Fellowship

| Agent | Identity | Tool |
|-------|----------|------|
| **GANDALF** | Orchestrator + Planner | Claude Sonnet 4.5 |
| **SARUMAN** | Deep Analyzer (on-demand) | Claude Opus |
| **LEGOLAS** | Static Analysis | GhidraMCP |
| **ELROND** | Cross-validation | radare2-mcp |
| **FRODO** | Runtime Hooking | Frida |
| **GIMLI** | Debugger | x64dbg |
| **PIPPIN** | Network Behavior | Wireshark |
| **ARAGORN** | OSINT / Recon | Shodan |
| **FARAMIR** | IoC Matching | YARA |
| **ARWEN** | Deobfuscation | CyberChef |
| **EOWYN** | Memory Forensics | Volatility3 |
| **TREEBEARD** | Sandbox Isolation | Docker |
| **SAM** | Case Memory | filesystem |
| **BOROMIR** | Triage / Confidence | LLM |
| **GOLLUM** | Adversarial Review | LLM |
| **MERRY** | Dependency Scan | cargo-audit/geiger |
| **GANDALF⬜** | Reporter | LLM |
| **BILBO** | IOC Export | STIX2/YARA/Sigma |

### Pipeline

```
Binary ──► Phase 1: FINGERPRINT ──► Phase 2: FILTER & GROUP ──► Phase 3: HYPOTHESIZE
              │                          │                            │
              ▼                          ▼                            ▼
         metadata.json             filtered_signals.json         hypotheses.md
              │                          │                            │
              ▼                          ▼                            ▼
         Phase 4: MAP STRUCTURE ──► Phase 5: PLAN DEEP ANALYSIS ──► Phase 6: VALIDATE DYNAMICALLY
              │                          │                            │
              ▼                          ▼                            ▼
      component_map.json          deep_analysis_plan.md        frida + pcap + memdump
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- Docker (for TREEBEARD sandbox)
- API keys in `.env`:
  - `ANTHROPIC_API_KEY` — required (Claude models)
  - `SHODAN_API_KEY` — optional (OSINT enrichment)

### Setup

```bash
git clone https://github.com/daemon-blockint-tech/MORDOR
cd MORDOR
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your API keys
```

### Run

```bash
# Standard analysis
python scripts/run_analysis.py /path/to/malware.exe

# With real-time streaming
python scripts/run_analysis.py /path/to/malware.exe --stream

# Quick tier (tool-only, skips deep analysis)
python scripts/run_analysis.py /path/to/malware.exe --tier quick

# Deep tier (full pipeline + extra validation)
python scripts/run_analysis.py /path/to/malware.exe --tier deep
```

---

## Analysis Pipeline (6 Phases)

### Phase 1 — FINGERPRINT
- **ARAGORN**: hash computation, OSINT lookups, threat intel correlation
- **LEGOLAS**: string extraction, import table analysis, crypto constant detection, packer heuristics
- **Artifacts**: `metadata.json`, `raw_strings.txt`, `imports.json`, `crypto_indicators.txt`

### Phase 2 — FILTER & GROUP
- **GANDALF**: removes noise, clusters signals by category
- **GOLLUM**: first adversarial pass — "is this signal or noise, precious?"
- **Artifacts**: `filtered_signals.json`

### Phase 3 — HYPOTHESIZE
- **GANDALF + BOROMIR**: builds hypotheses per category (persistence, C2, injection, collection, exfiltration)
- **Artifacts**: `hypotheses.md`

### Phase 4 — MAP STRUCTURE
- **LEGOLAS**: Ghidra decompilation, XREF mapping, function renaming
- **ELROND**: Radare2 independent cross-validation
- **Artifacts**: `component_map.json`, `call_graph.dot`

### Phase 5 — PLAN DEEP ANALYSIS
- **GANDALF**: ranks top-N suspicious functions by risk score
- **SARUMAN**: activated only for CRITICAL hypothesis paths
- **Artifacts**: `deep_analysis_plan.md`

### Phase 6 — VALIDATE DYNAMICALLY
- **FRODO**: Frida runtime hooks on suspicious calls
- **GIMLI**: x64dbg trace + breakpoints
- **PIPPIN**: Wireshark C2/DNS/exfiltration capture
- **EOWYN**: Volatility3 memory dump analysis
- **ARWEN**: CyberChef payload deobfuscation
- **Artifacts**: `frida_hooks.log`, `pcap/`, `memory_dump/`, `decoded_payloads/`

---

## Project Structure

```
MORDOR/
├── agents/              # Fellowship agents (one per capability)
│   ├── gandalf.py        # Orchestrator
│   ├── saruman.py        # Deep analyzer
│   └── fellowship/       # Individual agent implementations
├── graph/               # LangGraph pipeline definition
│   ├── state.py          # CaseState schema
│   ├── nodes.py          # Phase node implementations
│   ├── edges.py          # Conditional routing
│   └── pipeline.py       # Compiled LangGraph graph
├── tools/               # MCP and SDK adapters
├── skills/              # Agent skill prompts
├── rules/               # YARA + Sigma detection rules
│   ├── yara/            # ransomware, stealer, C2, packer rules
│   └── sigma/           # process injection, persistence rules
├── sandbox/             # Docker sandbox configuration
├── mcp_config/          # MCP server configs (Ghidra, radare2)
├── cases/               # Case artifacts per SHA256
├── scripts/             # Entry points and utilities
├── tests/               # Test suite
├── output/              # Reports, IOC feeds, dashboards
├── claude.md            # Operational instructions for AI orchestration
└── langgraph.json       # LangGraph project config
```

---

## Anti-False-Positive Rules

MORDOR enforces strict gates to minimize false positives:

- **XREF requirement**: every flagged function must have a caller (LEGOLAS checks)
- **Dual-tool confirmation**: LEGOLAS + ELROND must agree before flagging
- **Adversarial review**: GOLLUM must give 3 benign explanations before any CRITICAL classification
- **Confidence gate**: CRITICAL (>85%), SUSPICIOUS (50-85%), INFO (<50%)
- **Triple confirmation**: static + dynamic (FRODO/GIMLI) + network (PIPPIN) must all agree for CRITICAL
- **Minimum 3 YARA conditions**: never a single-string match

---

## Configuration

| File | Purpose |
|------|---------|
| `.env` | API keys and runtime configuration |
| `langgraph.json` | LangGraph pipeline & checkpointer config |
| `docker-compose.yml` | Sandbox + Ghidra server services |
| `sandbox/Dockerfile` | Isolated analysis environment |

### Environment Variables

Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Claude model access (orchestration + deep analysis) |
| `OPENROUTER_API_KEY` | No | Alternative LLM routing via OpenRouter |
| `SHODAN_API_KEY` | No | OSINT / threat intel enrichment |
| `IDA_API_KEY` | No | IDA Pro binary analysis |
| `GANDALF_MODEL` | No | LLM for orchestrator (default: `openai/gpt-4o-mini`) |
| `SARUMAN_MODEL` | No | LLM for deep analysis (default: `anthropic/claude-opus-4`) |
| `OPENCODE_ENABLED` | No | Enable OpenCode SDK integration (`false`) |
| `CLAUDE_AGENT_ENABLED` | No | Enable Claude Agent SDK integration (`false`) |
| `PAY_BIN_PATH` | No | Pay CLI programmable money toolchain |

---

## LangGraph Integration

The pipeline is defined as a compiled LangGraph state graph:

```bash
langgraph dev    # Launch LangGraph Studio for visual debugging
```

The graph compiles in `graph/pipeline.py` with a `MemorySaver` checkpointer for state persistence across phases.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Commit format: `<type>(mordor): <short description>`
- Types: `feat`, `fix`, `analysis`, `rules`, `agent`, `docs`

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 daemon
