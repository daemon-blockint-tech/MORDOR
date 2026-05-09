# CLI And Python API Reference

## CLI

Two entry points are available:

### Legacy CLI (`scripts/run_analysis.py`)

```bash
python3 scripts/run_analysis.py <binary> [--tier quick|standard|deep] [--stream]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<binary>` | Yes | Path to the binary to analyze. The file must exist. |
| `--tier` | No | Analysis depth. Defaults to `standard`. Choices: `quick`, `standard`, `deep`. |
| `--stream` | No | Streams phase updates from the orchestrator. |

Examples:

```bash
python3 scripts/run_analysis.py tests/samples/test_malware.x64 --tier standard
python3 scripts/run_analysis.py tests/samples/test_malware.x64 --tier quick
python3 scripts/run_analysis.py tests/samples/test_malware.x64 --tier standard --stream
```

If the pipeline completes, the CLI logs `Analysis finished at phase: report`.

### Typer CLI (`mordor`)

Installed via `pip install -e .` or `poetry install`:

```bash
mordor analyze <binary> [--tier quick|standard|deep] [--server URL]
mordor upload <binary> [--tier standard] [--server URL]
mordor cases [--server URL]
mordor status <case_id> [--server URL]
mordor report <case_id> [--server URL]
mordor artifacts <case_id> [--server URL]
mordor tui [<binary>] [--tier standard] [--server URL]
mordor serve [--host 0.0.0.0] [--port 8765]
```

#### `mordor analyze`

Default mode: runs directly via `GandalfOrchestrator` with live Rich progress bar.
No server needed. Use `--server` to submit to a remote MORDOR API instead:

```bash
# Direct local analysis (default, no server needed)
mordor analyze samples/malware.exe --tier deep

# Remote analysis via API server
mordor analyze samples/malware.exe --tier standard --server http://10.0.0.5:8765
```

On completion, prints a summary panel with the final report and confidence score.

#### `mordor tui`

Launches the Textual Terminal UI. With a binary path, runs analysis directly
via `GandalfOrchestrator` with a live dashboard. Without a binary, opens the
case manager (requires a running API server):

```bash
# Direct local analysis with Textual dashboard (no server needed)
mordor tui samples/malware.exe --tier deep

# Server-based case manager
mordor tui --server http://127.0.0.1:8765
```

#### `mordor serve`

Starts the FastAPI server (default `http://0.0.0.0:8765`):

```bash
mordor serve --port 8765
```

## Python Orchestrator API

Use `GandalfOrchestrator` when embedding MORDOR in another Python workflow.

```python
from agents.gandalf import GandalfOrchestrator

orchestrator = GandalfOrchestrator()
result = orchestrator.run("tests/samples/test_malware.x64", tier="standard")

print(result["sha256"])
print(result["current_phase"])
print(result["artifacts"].keys())
```

### `GandalfOrchestrator.run()`

```python
run(binary_path: str, tier: str = "standard", config: dict | None = None) -> dict
```

| Parameter | Description |
| --- | --- |
| `binary_path` | Path to the binary. The orchestrator hashes this file and creates `cases/<sha256>/`. |
| `tier` | `quick`, `standard`, or `deep`. |
| `config` | Optional LangGraph configurable values. `thread_id` defaults to SHA256. |

Returns final `CaseState` dictionary.

### `GandalfOrchestrator.stream()`

```python
for event in orchestrator.stream("tests/samples/test_malware.x64", tier="standard"):
    print(event)
```

## MordorClient API

The `MordorClient` (`cli/client.py`) communicates with the running API server:

```python
from cli.client import MordorClient

client = MordorClient("http://127.0.0.1:8765")

# Submit a binary
result = client.analyze("malware.exe", tier="standard")
case_id = result["case_id"]

# Poll for status
status = client.get_case(case_id)

# Get final report
report = client.get_report(case_id)

# List artifacts
artifacts = client.list_artifacts(case_id)

# Stream live events
for event in client.stream_events(case_id):
    print(event["phase"], event["progress"])
```

## OpenRouter Client API

Path: `tools/openrouter_client.py`

### `chat()`

```python
from tools.openrouter_client import chat

response = chat(
    [
        {"role": "system", "content": "You are a malware analyst."},
        {"role": "user", "content": "Summarize these imports: CreateFile, RegSetValue"},
    ],
    model="openai/gpt-4o-mini",
    temperature=0.2,
    max_tokens=1024,
)
```

Returns a string response or `None` on failure.

### `chat_json()`

```python
from tools.openrouter_client import chat_json

data = chat_json([
    {"role": "user", "content": "Return JSON: {\"risk\": \"low\"}"}
])
```

Returns a parsed `dict` or `list`, or `None` if parsing fails.

### `chat_structured()`

```python
from pydantic import BaseModel, Field
from tools.openrouter_client import chat_structured

class Assessment(BaseModel):
    classification: str = Field(description="benign, suspicious, or malicious")
    confidence: float = Field(description="0-100 confidence")

result = chat_structured(
    messages=[{"role": "user", "content": "Assess imports: socket, connect, send"}],
    schema=Assessment,
    temperature=0.2,
    agent_name="example",
    phase="triage",
)
```

Structured-output behavior:

1. Tries `function_calling`.
2. Tries `json_schema`.
3. Falls back to plain chat, extracts JSON, and validates with Pydantic.

Provider-level failures trip a circuit breaker so later calls skip known-broken structured-output methods.

### `reset_circuit_breaker()`

```python
from tools.openrouter_client import reset_circuit_breaker

reset_circuit_breaker()
```

Use after changing models in a long-running process or in tests that need a clean structured-output attempt order.

## Case Artifacts API

Path: `agents/fellowship/sam.py`

### `write_artifact()`

```python
from agents.fellowship.sam import write_artifact

write_artifact("cases/<sha256>", "metadata.json", {"sha256": "..."})
```

Writes dict/list values as pretty JSON and strings as plain text.

### `list_artifacts()`

```python
from agents.fellowship.sam import list_artifacts

print(list_artifacts("cases/<sha256>"))
```

Returns relative file paths under a case directory.

## Common Error Codes And Failures

| Error | Meaning | Action |
| --- | --- | --- |
| `OPENROUTER_API_KEY not set` | `.env` is missing API credentials. | Set `OPENROUTER_API_KEY`. |
| OpenRouter `404` for tool use | Provider does not support structured tool calls. | Circuit breaker should fall back automatically. |
| OpenRouter `400` multi-turn | Provider rejects multiple messages. | Use a non-Morph model or rely on current message-collapse workaround. |
| `Binary not found` | CLI path does not exist. | Correct the path and rerun. |
| `IDA not found` | Optional IDA integration unavailable. | Install IDA or accept degraded analysis. |
| Frida timeout | Runtime hook attach/spawn failed. | Validate sandbox and sample behavior. |

## Rate Limits And Cost

OpenRouter model rate limits and token costs vary by provider and account. MORDOR mitigates runaway calls by:

- Setting `DEFAULT_REQUEST_TIMEOUT = 30` seconds.
- Using a process-local circuit breaker for unsupported structured-output methods.
- Recording usage metadata when providers return it.

For large samples, prefer `quick` first, then run `standard` or `deep` only when initial evidence warrants it.
