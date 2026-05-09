# MORDOR Documentation

MORDOR is an AI-assisted reverse engineering pipeline for malware triage and analysis. It coordinates static analysis, cross-validation, hypothesis generation, dynamic validation, YARA/IOC export, and final reporting through a LangGraph workflow.

Use this directory as the operational entry point for the project documentation.

## Start Here

If you are new to the project, read these in order:

1. `ONBOARDING.md` - local setup, key systems, and common tasks.
2. `CLI_API_REFERENCE.md` - how to run analysis from the CLI or Python.
3. `ARCHITECTURE.md` - how the pipeline, agents, tools, and artifacts fit together.
4. `ANALYSIS_RUNBOOK.md` - step-by-step procedure for running a safe analysis.

Existing focused docs:

- `OPENROUTER_SETUP.md` - historical OpenRouter setup notes and examples.
- `README_OPENROUTER.md` - OpenRouter quick reference.
- `README_FRAMEWORK.md` - cognitive framework quick reference.
- `COGNITIVE_FRAMEWORK.md` - expert reverse engineering mental model.
- `AGENT_MIGRATION_GUIDE.md` - migration notes for agent changes.
- `FRAMEWORK_IMPLEMENTATION.md` - implementation detail for framework adoption.
- `IRONCURTAIN_INSIGHTS.md` - design insights from IRONCURTAIN work.
- `MIGRATION_COMPLETE.md` - migration completion notes.

## Quick Start

This gets you to a local smoke test and one analysis run.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
GANDALF_MODEL=openai/gpt-4o-mini
SARUMAN_MODEL=anthropic/claude-sonnet-4.5
```

Run smoke tests:

```bash
python3 -m pytest tests/test_pipeline_smoke.py -v
```

Run the sample analysis (legacy CLI):

```bash
python3 scripts/run_analysis.py tests/samples/test_malware.x64 --tier standard
```

Or with the Typer CLI (requires API server):

```bash
mordor serve &
mordor analyze tests/samples/test_malware.x64 --tier standard
```

Outputs are written to `cases/<sha256>/`.

## Safety Rules

MORDOR handles suspicious binaries. Follow these rules every time:

- Never execute a sample on the host machine.
- Use TREEBEARD/Docker sandbox paths for any runtime execution.
- Do not delete `cases/` without explicit approval.
- Do not commit `.env`, API keys, private samples, or exploit artifacts.
- Treat static-only conclusions as hypotheses until cross-validated and dynamically confirmed.

## Main Commands

```bash
# Legacy CLI (direct pipeline, no server needed)
python3 scripts/run_analysis.py path/to/sample.bin --tier standard
python3 scripts/run_analysis.py path/to/sample.bin --tier quick
python3 scripts/run_analysis.py path/to/sample.bin --tier standard --stream

# Typer CLI (requires API server)
mordor analyze path/to/sample.bin --tier deep
mordor tui                    # Textual terminal UI
mordor serve                  # Start API server
mordor cases                  # List past cases
mordor status <case_id>       # Check case status

# Start sandbox services
docker compose up -d sandbox ghidra-server
```

## What Success Looks Like

A successful run should:

- Create `cases/<sha256>/`.
- Write phase artifacts such as `metadata.json`, `filtered_signals.json`, `hypotheses.md`, `component_map.json`, `deep_analysis_plan.md`, `behavioral_timeline.json`, and `final_report.md`.
- End with `Analysis finished at phase: report`.
- Preserve an audit trail in `analysis_journal.jsonl`.

## Contributing

Before changing behavior:

1. Read `ARCHITECTURE.md` and the relevant agent file.
2. Keep changes minimal and phase-local.
3. Add or update smoke coverage when pipeline behavior changes.
4. Run `python3 -m pytest tests/test_pipeline_smoke.py -v`.
5. Update docs when commands, artifacts, phases, or safety behavior change.
