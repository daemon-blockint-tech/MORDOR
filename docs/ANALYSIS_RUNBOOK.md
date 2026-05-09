# Malware Analysis Runbook

## When To Use This Runbook

Use this runbook when you need to analyze a suspicious binary with MORDOR from a local workstation or controlled analysis environment.

Use a different procedure if:

- You need production incident response coordination.
- You need to detonate a sample against a real network target.
- You do not have authorization to analyze the sample.

## Safety First

Do not execute the binary on the host machine.

Allowed on host:

- Hashing
- File metadata reads
- Static analysis tools such as radare2/rabin2
- Artifact generation under `cases/<sha256>/`

Not allowed on host:

- Running the sample directly
- Opening the sample with tools that auto-execute payloads
- Exposing sandbox services externally
- Committing private samples or `.env`

## Prerequisites

Access needed:

- Local checkout of this repository.
- Python environment with dependencies installed.
- OpenRouter API key for standard/deep LLM tiers.
- Docker for sandbox validation.
- Optional: YARA, Frida, Volatility3, IDA, Ghidra container, Shodan key.

Install baseline dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install langchain-openai
```

Configure `.env` from `.env.example`:

```bash
cp .env.example .env
```

Required for LLM-backed tiers:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
GANDALF_MODEL=openai/gpt-4o-mini
SARUMAN_MODEL=anthropic/claude-opus-4
```

Start sandbox services when dynamic validation is needed:

```bash
docker compose up -d sandbox ghidra-server
```

Confirm Docker is available:

```bash
docker info
```

## Procedure

### 1. Place the sample safely

Put the sample in a non-executable working directory. Do not double-click it or run it.

Example:

```bash
mkdir -p samples-local
cp /path/to/suspicious.bin samples-local/suspicious.bin
```

### 2. Run a smoke test first

```bash
python3 -m pytest tests/test_pipeline_smoke.py -v
```

Expected result:

```text
3 passed
```

Warnings from urllib3/LibreSSL or LangChain/Pydantic structured output may appear. Treat them as non-blocking unless tests fail.

### 3. Choose analysis tier

| Tier | Use When | Behavior |
| --- | --- | --- |
| `quick` | You need fast tool-only triage | LLM calls should be skipped by tier gates. |
| `standard` | Normal analysis | Runs static, LLM-assisted, validation, and report phases. |
| `deep` | High-risk sample or formal review | Enables extra validation paths where implemented. |

### 4. Run analysis

```bash
python3 scripts/run_analysis.py samples-local/suspicious.bin --tier standard
```

To stream phase updates:

```bash
python3 scripts/run_analysis.py samples-local/suspicious.bin --tier standard --stream
```

### 5. Locate the case directory

The orchestrator computes SHA256 and writes artifacts under:

```text
cases/<sha256>/
```

Expected files include:

```text
metadata.json
raw_strings.txt
imports.json
filtered_signals.json
hypotheses.md
component_map.json
call_graph.dot
deep_analysis_plan.md
frida_hooks.log
yara_hits.txt
decoded_payloads.json
behavioral_timeline.json
final_report.md
analysis_journal.jsonl
analysis_journal_summary.json
```

### 6. Review the final report

Start with:

```text
cases/<sha256>/final_report.md
```

Then inspect supporting evidence:

```text
cases/<sha256>/analysis_journal.jsonl
cases/<sha256>/filtered_signals.json
cases/<sha256>/hypotheses.md
cases/<sha256>/behavioral_timeline.json
```

### 7. Export and hand off IoCs

If IoCs exist, BILBO writes:

```text
ioc_stix2.json
ioc_yara.yar
ioc_sigma.yml
```

Before sharing, check that exported values do not include private paths, secrets, or customer-only identifiers.

## Rollback And Cleanup

If a run used the wrong sample or wrong tier:

1. Stop any running containers if needed:

```bash
docker compose stop sandbox ghidra-server
```

2. Preserve the generated `cases/<sha256>/` directory unless the project owner explicitly approves deletion.

3. Re-run with the correct sample or tier:

```bash
python3 scripts/run_analysis.py samples-local/suspicious.bin --tier quick
```

If you need a clean comparison, create a new sample path or archive the old case directory outside the repository. Do not delete `cases/` casually.

## Troubleshooting

### `OPENROUTER_API_KEY not set`

Fix `.env`:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
```

### `No endpoints found that support tool use`

This is expected for some OpenRouter providers. The circuit breaker should skip `function_calling` after the first failure and fall back to other structured-output modes.

### `Multi-turn conversations are not supported`

Morph-routed models may reject multiple messages. Current `openrouter_client.py` collapses system+user prompts for model names containing `morph`, `moonshot`, or `kimi`.

### `IDA not found`

IDA is optional. The pipeline should continue with available static analysis and LLM fallback. Install/configure IDA only if decompilation is required.

### Frida timeout

Frida can time out if the sample cannot be spawned or attached in the current environment. Confirm sandbox availability and avoid host execution.

### Sandbox unavailable

Run:

```bash
docker info
docker compose up -d sandbox
```

If Docker is unavailable, TREEBEARD returns a degraded result or LLM fallback depending on tier.

## Optional Coding-Agent Integrations

MORDOR supports two optional coding-agent integrations that can assist with autonomous code analysis:

| Integration | Gate | Requirements |
|---|---|---|
| OpenCode | `OPENCODE_ENABLED=true` | Running OpenCode server at `OPENCODE_URL` |
| Claude Agent SDK | `CLAUDE_AGENT_ENABLED=true` | `pip install anthropic-agent-sdk` |

Both default to disabled. When enabled and available, they can be used via `tools.opencode_adapter.coding_query()` or `tools.claude_agent_adapter.coding_query()` respectively. Both fall back to the standard LLM pipeline when unavailable.

## Escalation Path

Escalate when:

- Static and dynamic evidence disagree.
- A sample appears destructive or self-propagating.
- A finding would be classified as critical but lacks runtime confirmation.
- Sandbox isolation is uncertain.
- The analysis involves customer, legal, or law-enforcement commitments.

Escalate with:

- SHA256
- `final_report.md`
- `analysis_journal.jsonl`
- Relevant phase artifacts
- Commands run and environment notes
