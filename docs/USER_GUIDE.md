# MORDOR User Guide

> Malware Orchestration & Reverse engineering Detection Operations Runtime

For security analysts, malware researchers, and incident responders who want to analyze suspicious binaries at scale.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Quick Start](#2-quick-start)
3. [Installation & Setup](#3-installation--setup)
4. [Analysis Tiers](#4-analysis-tiers)
5. [CLI Usage](#5-cli-usage)
6. [Terminal UI (TUI)](#6-terminal-ui-tui)
7. [API Server](#7-api-server)
8. [Pipeline Phases](#8-pipeline-phases)
9. [Understanding Results](#9-understanding-results)
10. [IOC Export](#10-ioc-export)
11. [Batch Analysis](#11-batch-analysis)
12. [Resuming Interrupted Analyses](#12-resuming-interrupted-analyses)
13. [Sandbox Setup](#13-sandbox-setup)
14. [Configuration Reference](#14-configuration-reference)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Overview

MORDOR is an **AI-driven reverse engineering pipeline** that autonomously analyzes malware binaries through 7 phases — from fingerprinting through dynamic validation to a final report. It coordinates a fellowship of specialized agents (each backed by industry tools like radare2, YARA, Frida, and LLMs) via a LangGraph state machine.

**What MORDOR does for you:**

- Extracts static features (strings, imports, sections, crypto constants, packer hints)
- Correlates OSINT threat intelligence via Shodan
- Filters noise and scores signals with false-positive review
- Generates structured hypotheses about malware capabilities
- Maps binary structure with cross-validation
- Runs deep analysis on critical paths
- Validates findings dynamically via Frida hooks, YARA, and sandbox execution
- Produces a comprehensive final report with STIX 2.1 / YARA / Sigma IOC exports

**Tiers:** Quick (no LLM, fast triage) → Standard (full pipeline) → Deep (extra validation for critical samples)

---

## 2. Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/daemon-blockint-tech/MORDOR
cd MORDOR
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 2. Run a standard analysis
python3 scripts/run_analysis.py /path/to/suspicious.bin

# 3. View the report
cat cases/<sha256>/final_report.md
```

---

## 3. Installation & Setup

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | Required |
| Docker | Latest | Required for sandbox (Phase 6) |
| API key (Anthropic) | — | Required for standard/deep tiers |
| radare2 | 6.x | Used for static analysis |
| YARA | 4.x | Used for rule matching |

### Step-by-Step

```bash
# 1. Clone the repository
git clone https://github.com/daemon-blockint-tech/MORDOR
cd MORDOR

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
# Or install in editable mode for the `mordor` CLI:
pip install -e .

# 4. Configure environment
cp .env.example .env
```

### Environment Variables

Edit `.env` with your API keys:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...     # Claude model access

# Optional — enables additional features
SHODAN_API_KEY=...               # OSINT enrichment
IDA_API_KEY=...                  # IDA Pro integration
OPENROUTER_API_KEY=sk-or-...     # Alternative LLM routing

# Optional — model selection (defaults are sensible)
GANDALF_MODEL=openai/gpt-4o-mini
SARUMAN_MODEL=anthropic/claude-opus-4
```

### Verify Installation

```bash
# Run the smoke tests
python3 -m pytest tests/test_pipeline_smoke.py -v

# Expected: 3 passed
```

---

## 4. Analysis Tiers

Choosing the right tier balances speed against depth:

| Tier | Command Flag | LLM Usage | Phases Run | SARUMAN | Best For |
|------|-------------|-----------|------------|---------|----------|
| **Quick** | `--tier quick` | None | 1–2 (fingerprint + filter) | Never | High-volume screening, initial triage |
| **Standard** | `--tier standard` (default) | Full | 1–7 | Only if confidence > 85% | General analysis |
| **Deep** | `--tier deep` | Full | 1–7 + extra validation | Always | Critical samples, formal investigations |

**Guidelines:**

- **Quick:** Use for bulk triage — checks file metadata, strings, imports, OSINT hits, and produces a confidence score with no LLM cost.
- **Standard:** Default for most analysis. Generates hypotheses, maps structure, validates dynamically, and produces a full report.
- **Deep:** Use when you need maximum rigor — forces SARUMAN (Claude Opus) deep analysis on all critical paths, generates MITRE ATT&CK mappings.

---

## 5. CLI Usage

MORDOR has two CLI entry points.

### 5a. Legacy Script (`scripts/run_analysis.py`)

```bash
python3 scripts/run_analysis.py <binary> [options]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `<binary>` | Yes | Path to the binary to analyze |
| `--tier` | No | `quick`, `standard` (default), or `deep` |
| `--stream` | No | Show real-time phase updates |

**Examples:**

```bash
# Standard analysis (default)
python3 scripts/run_analysis.py samples/suspicious.exe

# Quick triage — no LLM calls, fast
python3 scripts/run_analysis.py samples/suspicious.exe --tier quick

# Deep investigation with SARUMAN
python3 scripts/run_analysis.py samples/suspicious.exe --tier deep

# Real-time streaming output
python3 scripts/run_analysis.py samples/suspicious.exe --stream
```

### 5b. Typer CLI (`mordor`)

After `pip install -e .`, the `mordor` command is available:

```bash
mordor <command> [options]
```

| Command | Description |
|---------|-------------|
| `analyze` | Run analysis on a binary (local or remote) |
| `upload` | Upload a binary to a running server |
| `cases` | List all cases on a server |
| `status` | Check case status |
| `report` | Get the final report |
| `artifacts` | List/download case artifacts |
| `tui` | Launch the Textual terminal UI |
| `serve` | Start the API server |

#### `mordor analyze`

```bash
# Local analysis (default)
mordor analyze /path/to/suspicious.bin --tier deep

# Remote analysis via API server
mordor analyze /path/to/suspicious.bin --tier standard --server http://10.0.0.5:8765
```

#### `mordor status`

```bash
mordor status <case_id>
mordor status <case_id> --server http://10.0.0.5:8765
```

#### `mordor report`

```bash
mordor report <case_id>
mordor report <case_id> --server http://10.0.0.5:8765
```

#### `mordor artifacts`

```bash
mordor artifacts <case_id>
```

#### `mordor serve`

```bash
mordor serve --port 8765 --host 0.0.0.0
```

---

## 6. Terminal UI (TUI)

The Textual-based terminal UI provides a live dashboard for analysis progress.

```bash
# Launch TUI with direct local analysis
mordor tui /path/to/suspicious.bin --tier deep

# Launch TUI case manager (requires a running API server)
mordor tui --server http://127.0.0.1:8765
```

The TUI shows:
- Real-time phase progress bars
- Live event log from each agent
- Current confidence score
- Case selector for browsing past analyses

---

## 7. API Server

Run MORDOR as a service for team access or remote analysis.

### Starting the Server

```bash
# Via the mordor CLI
mordor serve --port 8765 --host 0.0.0.0

# Via Docker
docker compose up -d mordor

# Via uvicorn directly
uvicorn api.server:app --host 0.0.0.0 --port 8765
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Service info |
| `GET` | `/v1/health` | Health check |
| `POST` | `/v1/analyze` | Upload binary (multipart form) and start analysis |
| `POST` | `/v1/analyze/path` | Analyze binary already on the server |
| `GET` | `/v1/analyze/{case_id}/stream` | SSE stream of analysis events |
| `GET` | `/v1/cases` | List all cases |
| `GET` | `/v1/cases/{case_id}` | Get case status and summary |
| `GET` | `/v1/cases/{case_id}/artifacts` | List available artifacts |
| `GET` | `/v1/cases/{case_id}/artifacts/{name}` | Download a specific artifact |
| `GET` | `/v1/cases/{case_id}/report` | Get the final report (Markdown) |
| `GET` | `/v1/cases/{case_id}/timeline` | Get the behavioral timeline |
| `GET` | `/v1/stream/{case_id}` | SSE stream of phase changes |

### Using the API with curl

```bash
# Submit a binary for analysis
curl -X POST http://localhost:8765/v1/analyze \
  -F "file=@suspicious.exe" \
  -F "tier=standard"

# Check case status
curl http://localhost:8765/v1/cases/<case_id>

# Get the final report
curl http://localhost:8765/v1/cases/<case_id>/report

# Stream events (real-time)
curl -N http://localhost:8765/v1/stream/<case_id>
```

### Using the Python Client

```python
from cli.client import MordorClient

client = MordorClient("http://127.0.0.1:8765")

# Submit a binary
result = client.analyze("suspicious.exe", tier="standard")
case_id = result["case_id"]
print(f"Case ID: {case_id}")

# Poll for status
status = client.get_case(case_id)
print(f"Phase: {status['current_phase']}")

# Stream live events
for event in client.stream_events(case_id):
    print(f"[{event['phase']}] {event.get('message', '')}")

# Get the final report
report = client.get_report(case_id)
print(report)

# List and download artifacts
artifacts = client.list_artifacts(case_id)
for name in artifacts:
    content = client.get_artifact(case_id, name)
```

---

## 8. Pipeline Phases

Understanding what happens in each phase helps you interpret results.

### Phase 1 — FINGERPRINT

**Goal:** Extract raw static features and threat intelligence.

**Agents involved:**
- **ARAGORN** — Computes SHA256 hash, queries Shodan OSINT for known associations
- **LEGOLAS** — Runs radare2 static analysis: strings, imports, exports, sections, crypto constants, packer hints
- **MERRY** — Dependency audit (linked libraries)

**Artifacts produced:**
| File | Description |
|------|-------------|
| `metadata.json` | File metadata, hashes, OSINT tags, packer hints |
| `raw_strings.txt` | All extracted strings from the binary |
| `imports.json` | API imports and exports |
| `crypto_indicators.txt` | Entropy scores, crypto constants found |

**What to look for:** Unknown imports, suspicious string patterns (URLs, registry keys, API function names), high-entropy sections (packed code).

### Phase 2 — FILTER & GROUP

**Goal:** Remove noise, cluster signals, apply adversarial review to prevent false positives.

**Agents involved:**
- **BOROMIR** — Scores each signal (0–100 confidence), categorizes by threat type
- **GOLLUM** — Adversarial review: "Give 3 reasons this could be BENIGN before flagging"

**Artifacts produced:**
| File | Description |
|------|-------------|
| `filtered_signals.json` | Confirmed signals, dismissed flags, aggregate confidence score |
| `anti_fp_review.md` | GOLLUM's adversarial review log |

**Confidence gate:**
| Level | Score | Action |
|-------|-------|--------|
| CRITICAL | > 85% | Auto-report + SARUMAN deep analysis |
| SUSPICIOUS | 50–85% | Queued for human review |
| INFO | < 50% | Logged only, no action |

**What to look for:** The `confidence_overall` value. If CRITICAL, the pipeline will auto-escalate. Review `dismissed_flags` to see what GOLLUM filtered out.

### Phase 3 — HYPOTHESIZE

**Goal:** Build structured hypotheses about what the malware can do.

**Agents involved:**
- **GANDALF** (LLM) — Receives SHA256, file type, top 30 filtered signals; generates hypotheses
- **BOROMIR** — Scores each hypothesis for confidence

**Categories analyzed:** Persistence, C2 communication, injection, data collection, exfiltration

**Artifacts produced:**
| File | Description |
|------|-------------|
| `hypotheses.md` | Structured hypotheses with evidence, confidence, and risk scores |

**What to look for:** Each hypothesis includes `category`, `description`, `confidence` (0–100), `evidence` (list of supporting signals), `functions` (relevant binary functions), and `risk_score` (0–100). Focus on high-confidence, high-risk hypotheses.

### Phase 4 — MAP STRUCTURE

**Goal:** Deep structural analysis with cross-tool validation.

**Agents involved:**
- **LEGOLAS** — Full radare2 static analysis
- **ELROND** — Independent cross-validation (compares radare2 with GhidraMCP)
- **GLORFINDEL** — IDA Pro / Hex-Rays decompilation of suspicious functions (if available)
- **GALADRIEL** — IDAPython metadata extraction (if available)

**Validation rules:**
- Every flagged function must have a caller (XREF check) — no caller = no flag
- ELROND must independently confirm every flagged function
- Agreement score must be > 80% before proceeding

**Artifacts produced:**
| File | Description |
|------|-------------|
| `component_map.json` | Sections, imports, exports, functions, validation scores |
| `call_graph.dot` | Graphviz DOT-format call graph |

**What to look for:** The `confidence_breakdown.cross_validation` score tells you how well the two tools agreed. Low agreement may indicate obfuscation or packing.

### Phase 5 — DEEP ANALYSIS

**Goal:** Rank hypotheses and plan targeted investigation.

**Agents involved:**
- **GANDALF** — Ranks hypotheses by `risk_score × confidence`
- **SARUMAN** — Claude Opus deep analysis (activated only for CRITICAL hypotheses or DEEP tier)

**Framework:** SARUMAN uses the USENIX RE-Mind cognitive framework: Attacker Lens, Layered Abstraction, Pattern Chunking, Hypothesis Loop, Negative Space, Second-Order Thinking, Occam's Razor.

**Artifacts produced:**
| File | Description |
|------|-------------|
| `deep_analysis_plan.md` | Ranked hypotheses, investigation plan, SARUMAN analysis |

### Phase 6 — VALIDATE DYNAMICALLY

**Goal:** Confirm static findings with runtime evidence.

**Agents involved:**

| Agent | Tool | Role |
|-------|------|------|
| TREEBEARD | Docker | Verifies sandbox is ready (mandatory) |
| FRODO | Frida | Runtime hooks on suspicious functions |
| GIMLI | x64dbg/LLDB | Debugger trace with breakpoints |
| FARAMIR | YARA | Rule matching on the binary |
| ARWEN | CyberChef | Decode obfuscated payloads |
| EOWYN | Volatility3 | Memory analysis (if dump available) |
| PIPPIN | Wireshark/tShark | Network capture analysis |
| CELEBORN | LLM | Build behavioral timeline |
| SARUMAN | Claude Opus | MITRE ATT&CK mapping (DEEP tier only) |

**Triple confirmation gate (for CRITICAL classification):**
1. Static analysis flags the behavior ✓
2. FRODO runtime hook confirms ✓
3. PIPPIN network capture confirms ✓

All three must confirm for CRITICAL classification.

**Artifacts produced:**
| File | Description |
|------|-------------|
| `frida_hooks.log` | Hook attachment results and call logs |
| `yara_hits.txt` | YARA rule matches |
| `decoded_payloads.json` | Decoded strings and payloads |
| `behavioral_timeline.json` | Chronological event list |
| `mitre_mapping.json` | MITRE ATT&CK technique mappings (DEEP tier) |
| `pcap/` | Network capture files |
| `memory_dump/` | Volatility3 output |

### Phase 7 — REPORT

**Goal:** Generate comprehensive report and export IOCs.

**Agents involved:**
- **GANDALF_WHITE** — Synthesizes all findings into final report
- **BILBO** — Exports IOCs in STIX 2.1, YARA, and Sigma formats

**Artifacts produced:**
| File | Description |
|------|-------------|
| `final_report.md` | Comprehensive analysis report |
| `ioc_stix2.json` | STIX 2.1 formatted IOCs |
| `ioc_yara.yar` | YARA rules for detection |
| `ioc_sigma.yml` | Sigma rules for SIEM ingestion |
| `analysis_journal_summary.json` | Summary statistics and audit trail |

---

## 9. Understanding Results

### Case Directory Structure

Every analysis creates a case directory at `cases/<sha256>/` containing all artifacts:

```
cases/<sha256>/
├── metadata.json              ← File info, hashes, OSINT (Phase 1)
├── raw_strings.txt            ← Extracted strings (Phase 1)
├── imports.json               ← API imports (Phase 1)
├── crypto_indicators.txt      ← Entropy, crypto constants (Phase 1)
├── filtered_signals.json      ← Cleaned signals + confidence (Phase 2)
├── anti_fp_review.md          ← Adversarial review log (Phase 2)
├── hypotheses.md              ← Structured hypotheses (Phase 3)
├── component_map.json         ← Structural map (Phase 4)
├── call_graph.dot             ← Call graph (Phase 4)
├── deep_analysis_plan.md      ← Investigation plan (Phase 5)
├── frida_hooks.log            ← Runtime hooks (Phase 6)
├── yara_hits.txt              ← YARA matches (Phase 6)
├── decoded_payloads.json      ← Deobfuscated data (Phase 6)
├── behavioral_timeline.json   ← Event timeline (Phase 6)
├── mitre_mapping.json         ← ATT&CK mappings (Phase 6, DEEP only)
├── pcap/                      ← Network captures (Phase 6)
├── memory_dump/               ← Memory forensics (Phase 6)
├── analysis_journal.jsonl     ← Full audit trail
├── analysis_journal_summary.json ← Summary statistics
├── final_report.md            ← Final comprehensive report (Phase 7)
├── ioc_stix2.json             ← STIX 2.1 IOCs (Phase 7)
├── ioc_yara.yar               ← YARA rules (Phase 7)
└── ioc_sigma.yml              ← Sigma rules (Phase 7)
```

### How to Read a Case

1. **Start with `final_report.md`** — The synthesized executive summary and technical findings
2. **Check `confidence_overall`** in `filtered_signals.json` — Is this likely malicious?
3. **Review `hypotheses.md`** — What capabilities are suspected? What's the evidence?
4. **Inspect `filtered_signals.json`** — Which signals drove the classification? What was dismissed?
5. **Verify with `analysis_journal.jsonl`** — Every agent action is logged with timing
6. **Deep-dive artifacts** — Strings, imports, call graph, behavioral timeline as needed

### Confidence Scores

Confidence is calculated across the pipeline:
- **Phase 2:** Aggregate signal confidence
- **Phase 3:** Recalculated based on hypothesis quality
- **Phase 4:** Cross-validation agreement score added
- **Phase 6:** Dynamic confirmation updates the score

The final `confidence_overall` and `confidence_breakdown` in the case state provide the full picture.

---

## 10. IOC Export

After the report phase, IOCs are automatically exported in three formats:

### STIX 2.1 (`ioc_stix2.json`)
Standardized format for threat intelligence platforms (MISP, OpenCTI, etc.).

### YARA Rules (`ioc_yara.yar`)
Detection rules for scanning other binaries:
```bash
# Use the generated rules
yara cases/<sha256>/ioc_yara.yar /path/to/suspicious.bin
```

### Sigma Rules (`ioc_sigma.yml`)
SIEM detection rules for identifying behavior in event logs.

### Re-exporting IOCs

```bash
# Re-export IOCs from a completed case
python3 scripts/export_ioc.py cases/<sha256> --format all --output /path/to/output

# Export specific formats
python3 scripts/export_ioc.py cases/<sha256> --format stix2
python3 scripts/export_ioc.py cases/<sha256> --format yara
python3 scripts/export_ioc.py cases/<sha256> --format sigma
```

---

## 11. Batch Analysis

Process multiple binaries in sequence:

```bash
# Using the batch script
python3 scripts/batch_analysis.py sample1.exe sample2.exe sample3.dll --tier standard

# Using xargs with the run script
ls samples/ | xargs -I {} python3 scripts/run_analysis.py samples/{} --tier quick

# Using the CLI
mordor analyze sample1.exe --tier quick
mordor analyze sample2.exe --tier quick
```

Each binary gets its own case directory and thread ID.

---

## 12. Resuming Interrupted Analyses

If an analysis is interrupted (network issue, crash, Ctrl+C), MORDOR can resume from where it left off:

1. SAM (case manager) checks the `cases/<sha256>/` directory for existing artifacts
2. LangGraph `MemorySaver` checkpointer stores the last completed phase
3. Re-running the same binary automatically resumes from the last completed phase

```bash
# If interrupted, just re-run:
python3 scripts/run_analysis.py /path/to/suspicious.bin
# Output: "Resuming from phase: <phase_name>"
```

**MORDOR never re-analyzes from scratch if artifacts exist.**

---

## 13. Sandbox Setup

The TREEBEARD sandbox provides an isolated Docker environment for dynamic analysis.

### Starting the Sandbox

```bash
# Start all services
docker compose up -d sandbox

# Start with Ghidra server (optional)
docker compose up -d sandbox ghidra-server

# Verify it's running
docker compose ps
```

### Sandbox Architecture

The sandbox runs on Ubuntu 24.04 with:
- Network isolation (DNS-only egress by default, optional simulated C2 range)
- Tools: Python, curl, tcpdump, strace, gdb, ltrace, binutils, iptables
- Runs as the `analyst` user (non-root)
- Binary is injected without host execution

### Network Policy

Default: **DROP all egress** except DNS (port 53). For C2 simulation, the policy allows traffic to `198.51.100.0/24` (TEST-NET-2 range).

---

## 14. Configuration Reference

### `.env` File

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Claude model access for orchestrator + deep analysis |
| `SHODAN_API_KEY` | No | — | OSINT threat intelligence enrichment |
| `IDA_API_KEY` | No | — | IDA Pro binary analysis |
| `OPENROUTER_API_KEY` | No | — | Alternative LLM routing via OpenRouter |
| `GANDALF_MODEL` | No | `openai/gpt-4o-mini` | Orchestrator LLM model ID |
| `SARUMAN_MODEL` | No | `anthropic/claude-opus-4` | Deep analysis LLM model ID |
| `OPENCODE_ENABLED` | No | `false` | Enable OpenCode SDK integration |
| `CLAUDE_AGENT_ENABLED` | No | `false` | Enable Claude Agent SDK integration |
| `PAY_BIN_PATH` | No | `pay` | Pay CLI binary path |
| `IDA_PATH` | No | `/Applications/IDA Free 9.3.app/...` | IDA Pro/Free binary path |

### Model Router

MORDOR maps agents to model complexity tiers:

| Tier | Default Model | Cost/1k in | Cost/1k out | Used By |
|------|--------------|------------|-------------|---------|
| SIMPLE | `openai/gpt-4o-mini` | $0.00015 | $0.0006 | BOROMIR, BILBO |
| MEDIUM | `moonshotai/kimi-k2.6` | $0.002 | $0.008 | ARAGORN, GOLLUM, LEGOLAS |
| COMPLEX | `anthropic/claude-sonnet-4.5` | $0.003 | $0.015 | GANDALF, GANDALF_WHITE |
| CRITICAL | `anthropic/claude-opus-4` | $0.015 | $0.075 | SARUMAN |

### Cost Limits

- Maximum cost per case: **$50** (raises an error if exceeded)
- Tracked via `cost_entries` and `cost_summary` in case state
- Use `quick` tier for high-volume screening to minimize LLM costs

---

## 15. Troubleshooting

### Common Issues

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `ANTHROPIC_API_KEY not set` | Missing API key in `.env` | Add a valid Anthropic API key |
| `OPENROUTER_API_KEY not set` | Missing OpenRouter key | Add key or switch to Anthropic-only |
| `Binary not found` | Wrong path to binary | Check the file path and try again |
| `IDA not found` | IDA Pro not installed | Non-fatal; pipeline continues without it |
| Frida timeout | Sample can't be spawned | Confirm sandbox is running (`docker compose ps`) |
| `No endpoints found that support tool use` | OpenRouter provider limitation | Non-fatal; circuit breaker falls back |
| `Multi-turn conversations not supported` | Morph/Kimi model limitation | Non-fatal; client auto-collapses prompts |
| Sandbox unavailable | Docker not running | Start Docker: `docker compose up -d sandbox` |

### Checking Pipeline Health

```bash
# Verify Docker services
docker compose ps

# Run smoke tests
python3 -m pytest tests/test_pipeline_smoke.py -v

# Check LangGraph configuration
langgraph dev
```

### Getting Help

- **Pipeline ordering or routing:** Check `graph/pipeline.py` and `graph/nodes.py`
- **LLM errors or model routing:** Check `tools/openrouter_client.py`
- **Static analysis issues:** Check `agents/fellowship/legolas.py`
- **Sandbox problems:** Check `agents/fellowship/treebeard.py` and `docker-compose.yml`
- **IOC exports:** Check `agents/fellowship/bilbo.py`

---

## Safety Rules

These are enforced automatically by the pipeline, but you should be aware of them:

1. **No host execution** — Binaries are never executed on the host machine. All dynamic analysis happens in the Docker sandbox.
2. **Cross-validation required** — Every flagged function must be independently confirmed by two tools (LEGOLAS + ELROND).
3. **Adversarial review mandatory** — GOLLUM must provide 3 benign explanations before any CRITICAL classification.
4. **Triple confirmation for CRITICAL** — Static flag + runtime hook + network evidence must all agree.
5. **Minimum 3 YARA conditions** — No single-string match is ever treated as a confirmed threat.
6. **Phase artifacts written before advancing** — Every phase writes its results before the next phase begins.
