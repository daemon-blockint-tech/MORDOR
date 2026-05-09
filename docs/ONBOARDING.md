# Developer Onboarding Guide

## Who This Is For

This guide is for developers and analysts who need to run, debug, or extend MORDOR locally.

If you only need to run one sample, start with `ANALYSIS_RUNBOOK.md`.

## Local Setup

### 1. Create Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The `pyproject.toml` declares all dependencies. Install in editable mode to get the `mordor` Typer CLI entry point.

The repository's `langgraph.json` targets Python 3.12 for LangGraph deployment. Local development has also been run with system `python3`, but use a modern Python where possible.

### 2. Configure environment

```bash
cp .env.example .env
```

Set:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
GANDALF_MODEL=openai/gpt-4o-mini
SARUMAN_MODEL=anthropic/claude-opus-4
```

Optional keys:

```bash
SHODAN_API_KEY=...
IDA_API_KEY=...
```

Do not commit `.env`.

### 3. Start sandbox services

```bash
docker compose up -d sandbox ghidra-server
```

The Ghidra MCP service is exposed on host port `13100` and container port `8080`.

### 4. Run tests

```bash
python3 -m pytest tests/test_pipeline_smoke.py -v
```

The smoke test uses `tests/samples/test_malware.x64` and validates radare2 analysis, cross-validation, and full pipeline phase order.

## Repository Map

| Path | Purpose |
| --- | --- |
| `scripts/` | User-facing CLIs such as `run_analysis.py`. |
| `agents/` | Orchestrator, schemas, journal, gates, and fellowship agents. |
| `agents/fellowship/` | Role-specific agents such as LEGOLAS, BOROMIR, FRODO, and BILBO. |
| `graph/` | LangGraph state, phase nodes, routing helpers, and graph compilation. |
| `tools/` | Integrations for OpenRouter, radare2, Ghidra, Frida, YARA, Shodan, CyberChef, and Volatility. |
| `rules/` | YARA and Sigma detection rules. |
| `sandbox/` | Docker sandbox and Ghidra container definitions. |
| `tests/` | Smoke tests and sample binaries. |
| `cases/` | Per-sample persistent artifacts. Do not delete without approval. |
| `docs/` | Project documentation. |

## Key Concepts

### Agents

MORDOR uses themed agents to isolate responsibility:

| Agent | Role |
| --- | --- |
| GANDALF | Orchestration and final synthesis. |
| SARUMAN | Strategic Director — delegates to sub-agents per phase. |
| GANDALF_WHITE | Second-stage Director / Reporter. |
| BOROMIR | Binary analyst — triage, confidence scoring. |
| FARAMIR | Second-seat analyst — YARA, signal validation. |
| GOLLUM | Adversarial false-positive review. |
| ELROND | Pattern analyst — cross-validation. |
| GALADRIEL | Insight synthesizer. |
| CELEBORN | Cross-reference analyst. |
| GLORFINDEL | Light analysis — fast filtering. |
| ARWEN | Evenstar refiner — deobfuscation. |
| ARAGORN | Pathfinder — OSINT and threat intelligence. |
| LEGOLAS | Precision scanner — static analysis. |
| GIMLI | Deep miner — debugger trace planning. |
| TREEBEARD | Data steward — Docker sandbox. |
| BILBO | Chronicler — IOC export (STIX2/YARA/Sigma). |
| FRODO | Focus agent — Frida runtime hooks. |
| SAM | Support agent — case artifact memory. |
| MERRY | Lateral agent — dependency audit. |
| PIPPIN | Curiosity agent — network capture. |
| EOWYN | Shield analyst — memory forensics. |
| PAY | Payment handler — cost tracking. |

### Analysis tiers

| Tier | Intended use |
| --- | --- |
| `quick` | Fast local triage, minimal/skip LLM use where gates allow. |
| `standard` | Normal analysis with LLM-assisted reasoning and validation. |
| `deep` | Extended analysis with extra validation where implemented. |

### Case artifacts

Every run writes to:

```text
cases/<sha256>/
```

The case directory is the source of truth for resuming, auditing, and reporting.

## Common Tasks

### Run one sample

```bash
python3 scripts/run_analysis.py tests/samples/test_malware.x64 --tier standard
```

### Run with phase streaming

```bash
python3 scripts/run_analysis.py tests/samples/test_malware.x64 --tier standard --stream
```

### Add a new phase artifact

1. Add the artifact field to `PhaseArtifacts` in `graph/state.py`.
2. Write the file through `write_case_artifact()` from `graph/nodes.py` or `write_artifact()` from `agents/fellowship/sam.py`.
3. Include it in the phase update's `artifacts` dict.
4. Document it in `ARCHITECTURE.md` and `ANALYSIS_RUNBOOK.md`.
5. Update smoke tests if phase output expectations change.

### Add a new agent fallback

1. Define a Pydantic schema in `agents/schemas.py`.
2. Call `chat_structured()` with `agent_name` and `phase` set.
3. Make tool-first behavior explicit: try the local tool, then LLM fallback.
4. Return plain dictionaries from agent functions so graph nodes stay simple.

### Change graph routing

Routing is controlled by `Command(goto=...)` returned from phase nodes. Do not add duplicate normal edges for those transitions in `graph/pipeline.py`; doing so can double-schedule nodes.

Terminal edges only:

```python
builder.add_edge("report", END)
builder.add_edge("error", END)
```

## Testing Expectations

Run smoke tests after changes to:

- `graph/`
- `agents/`
- `tools/openrouter_client.py`
- `scripts/run_analysis.py`
- YARA rules used by default scans

Command:

```bash
python3 -m pytest tests/test_pipeline_smoke.py -v
```

Smoke test success criteria:

- radare2 static analysis returns enough functions/imports/sections.
- ELROND cross-validation returns at least 80% agreement.
- Full pipeline phase order is exactly fingerprint, filter, hypothesize, map_structure, deep_analysis, validate, report.

## Known Local Environment Notes

- `IDA not found` is non-fatal unless you are testing IDA-specific behavior.
- OpenRouter provider support varies by model. Some providers do not support tool calling.
- Morph-routed models may require single-message prompts; `openrouter_client.py` handles known Morph/Moonshot/Kimi model names.
- urllib3 may warn about LibreSSL on macOS system Python. Treat as non-blocking unless network calls fail.

## Who To Ask For What

Use these ownership areas when routing questions:

| Topic | Start With |
| --- | --- |
| Pipeline ordering or state | `graph/pipeline.py`, `graph/nodes.py`, `graph/state.py` |
| LLM routing or model errors | `tools/openrouter_client.py`, `docs/OPENROUTER_SETUP.md` |
| Static analysis | `agents/fellowship/legolas.py`, `tools/radare2_mcp.py` |
| Cross-validation | `agents/fellowship/elrond.py` |
| Sandbox behavior | `agents/fellowship/treebeard.py`, `docker-compose.yml` |
| YARA/Sigma/IOC output | `agents/fellowship/faramir.py`, `agents/fellowship/bilbo.py`, `rules/` |
| Final reports | `agents/fellowship/gandalf_white.py` |
