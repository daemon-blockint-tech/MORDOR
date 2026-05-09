# OpenRouter Integration for MORDOR

## ✅ Installation Complete

The MORDOR project now uses **OpenRouter** with **LangChain** for LLM integration.

## What Was Done

### 1. **Installed Dependencies**
- `langchain-openrouter>=0.2.0` - OpenRouter integration for LangChain
- `langchain-core>=0.3.0` - Core LangChain functionality

### 2. **Created OpenRouter Client** (`tools/openrouter_client.py`)
A new client that provides:
- **`chat()`** - Basic chat completions
- **`chat_json()`** - JSON-formatted responses
- **`chat_structured()`** - Structured output using Pydantic schemas
- **`get_model()`** - Model configuration helper

### 3. **Updated Graph Nodes**
- Changed `graph/nodes.py` to use `openrouter_client` instead of `daemon_client`
- All existing functionality preserved, now using OpenRouter

### 4. **Created Saruman Agent** (`agents/fellowship/saruman.py`)
Advanced threat analysis agent demonstrating:
- **Structured output** with Pydantic models
- **Type-safe responses** (no JSON parsing errors)
- **MITRE ATT&CK mapping**
- **Evidence-based threat hypotheses**

### 5. **Environment Configuration**
Updated `.env` and `.env.example` with:
```bash
OPENROUTER_API_KEY=sk-or-v1-...
GANDALF_MODEL=moonshotai/kimi-k2.6
SARUMAN_MODEL=anthropic/claude-opus-4.7
```

## Test Results

✅ **Basic Chat Completion** - Working
✅ **Structured Output (Pydantic)** - Working  
✅ **Model Selection** - Working (tested GPT-4o-mini, Claude Sonnet 4.5, Gemini 2.5 Flash)
⚠️ **JSON Response** - Needs improvement (model returned markdown-wrapped JSON)

## Available Models via OpenRouter

Your current configuration uses:
- **GANDALF_MODEL**: `moonshotai/kimi-k2.6` (default for general tasks)
- **SARUMAN_MODEL**: `anthropic/claude-opus-4.7` (for advanced analysis)

You can use any model from [OpenRouter's catalog](https://openrouter.ai/models):
- `openai/gpt-4o-mini` - Fast, cost-effective
- `openai/gpt-4o` - Most capable OpenAI model
- `anthropic/claude-sonnet-4.5` - Balanced Claude model
- `anthropic/claude-opus-4` - Most capable Claude model
- `google/gemini-2.5-flash` - Fast Google model
- `google/gemini-2.5-pro` - Most capable Google model
- `meta-llama/llama-4-maverick` - Open source option

## Usage Examples

### Basic Chat
```python
from tools.openrouter_client import chat

messages = [
    {"role": "system", "content": "You are a malware analyst."},
    {"role": "user", "content": "Analyze this binary..."}
]

response = chat(messages, model="openai/gpt-4o-mini", temperature=0.3)
```

### Structured Output (Recommended)
```python
from pydantic import BaseModel, Field
from tools.openrouter_client import chat_structured

class ThreatAssessment(BaseModel):
    threat_type: str = Field(description="Type of threat")
    severity: str = Field(description="Severity level")
    confidence: float = Field(description="Confidence 0-100", ge=0, le=100)

result = chat_structured(
    messages=[{"role": "user", "content": "Analyze..."}],
    schema=ThreatAssessment,
    model="anthropic/claude-sonnet-4.5"
)

print(f"Threat: {result.threat_type}, Severity: {result.severity}")
```

### Using Saruman Agent
```python
from agents.fellowship.saruman import analyze_with_structured_output

result = analyze_with_structured_output(
    sha256="abc123...",
    file_type="PE32 executable",
    signals=[...],
    metadata={...}
)

for hypothesis in result.hypotheses:
    print(f"{hypothesis.category}: {hypothesis.confidence}% confidence")
```

## Advanced Features

### 1. **Provider Routing**
Control which providers handle your requests:
```python
from langchain_openrouter import ChatOpenRouter

model = ChatOpenRouter(
    model="anthropic/claude-sonnet-4.5",
    openrouter_provider={
        "order": ["Anthropic", "Google"],
        "allow_fallbacks": True,
        "data_collection": "deny",  # Don't allow training on your data
    }
)
```

### 2. **Multi-Model Routing**
Use multiple models with automatic fallback:
```python
model = ChatOpenRouter(
    model="openai/gpt-4o",
    models=["openai/gpt-4o", "anthropic/claude-sonnet-4.5"],
    route="fallback"
)
```

### 3. **Token Usage Tracking**
```python
response = model.invoke(messages)
print(response.usage_metadata)
# {'input_tokens': 12, 'output_tokens': 25, 'total_tokens': 37}
```

### 4. **Multimodal Input** (Images, PDFs, Audio, Video)
```python
from langchain_core.messages import HumanMessage

message = HumanMessage(content=[
    {"type": "text", "text": "Analyze this screenshot"},
    {"type": "image", "url": "https://example.com/malware-screenshot.png"}
])

response = model.invoke([message])
```

## Migration from Daemon Client

The old `daemon_client.py` is still available but no longer used. All nodes now use `openrouter_client.py`.

**Key differences:**
- ✅ More models available (50+ providers)
- ✅ Structured output with Pydantic
- ✅ Better error handling
- ✅ Token usage tracking
- ✅ Provider routing and fallbacks
- ✅ Multimodal support

## Testing

Run the test suite:
```bash
source .venv/bin/activate
python test_openrouter.py
```

## Cost Optimization

OpenRouter charges per token. To optimize costs:

1. **Use smaller models for simple tasks**:
   - `openai/gpt-4o-mini` for filtering/triage
   - `anthropic/claude-sonnet-4.5` for analysis
   - `anthropic/claude-opus-4` only for complex reasoning

2. **Set appropriate `max_tokens`**:
   ```python
   chat(messages, max_tokens=512)  # Limit response length
   ```

3. **Use lower temperature for deterministic tasks**:
   ```python
   chat(messages, temperature=0.1)  # More focused, less creative
   ```

4. **Enable prompt caching** (for repeated prompts):
   ```python
   # Add cache_control to system messages
   messages = [
       ("system", [{
           "type": "text",
           "text": long_system_prompt,
           "cache_control": {"type": "ephemeral"}
       }]),
       ("user", "Analyze this...")
   ]
   ```

## Troubleshooting

### "OPENROUTER_API_KEY not set"
Make sure your `.env` file has:
```bash
OPENROUTER_API_KEY=sk-or-v1-...
```

### Model not found
Check available models at https://openrouter.ai/models

### Rate limiting
OpenRouter has rate limits. Add retry logic:
```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def call_with_retry():
    return chat(messages)
```

### JSON parsing errors
Use `chat_structured()` instead of `chat_json()` for reliable structured output.

## Next Steps

1. **Update other agents** to use structured output
2. **Add multimodal analysis** for screenshots/memory dumps
3. **Implement cost tracking** per analysis
4. **Add model selection logic** based on task complexity
5. **Create agent-specific Pydantic schemas** for each fellowship member

## Documentation

- [OpenRouter Docs](https://openrouter.ai/docs)
- [LangChain OpenRouter Integration](https://docs.langchain.com/oss/python/integrations/chat/openrouter)
- [OpenRouter Models](https://openrouter.ai/models)
- [OpenRouter API Reference](https://reference.langchain.com/python/integrations/langchain_openrouter)
