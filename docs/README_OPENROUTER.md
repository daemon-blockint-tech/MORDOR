# MORDOR + OpenRouter Integration

## 🎯 Quick Start

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Install dependencies (already done)
pip install -r requirements.txt

# 3. Set your OpenRouter API key in .env
OPENROUTER_API_KEY=sk-or-v1-your-key-here

# 4. Run tests
python test_openrouter.py

# 5. Run MORDOR analysis
python main.py /path/to/binary
```

## 📦 What's New

### New Files
- `tools/openrouter_client.py` - OpenRouter LLM client with LangChain
- `agents/fellowship/saruman.py` - Advanced analysis with structured output
- `test_openrouter.py` - Integration tests
- `OPENROUTER_SETUP.md` - Detailed setup guide
- `AGENT_MIGRATION_GUIDE.md` - Guide for updating agents

### Updated Files
- `requirements.txt` - Added langchain-openrouter
- `graph/nodes.py` - Now uses openrouter_client
- `.env` - Added OPENROUTER_API_KEY
- `.env.example` - Updated with OpenRouter config

## 🚀 Key Features

### 1. Multiple Model Support
Access 50+ models from different providers:
```python
from tools.openrouter_client import chat

# Use GPT-4o-mini for fast tasks
response = chat(messages, model="openai/gpt-4o-mini")

# Use Claude Opus for complex reasoning
response = chat(messages, model="anthropic/claude-opus-4")

# Use Gemini for multimodal
response = chat(messages, model="google/gemini-2.5-pro")
```

### 2. Structured Output (Type-Safe)
No more JSON parsing errors:
```python
from pydantic import BaseModel, Field
from tools.openrouter_client import chat_structured

class ThreatAnalysis(BaseModel):
    threat_type: str
    severity: str
    confidence: float = Field(ge=0, le=100)

result = chat_structured(
    messages=[{"role": "user", "content": "Analyze..."}],
    schema=ThreatAnalysis
)

# result is guaranteed to be a ThreatAnalysis object
print(f"Threat: {result.threat_type}")  # Type-safe!
```

### 3. Cost Optimization
Choose the right model for each task:
- **Triage/Filtering**: `openai/gpt-4o-mini` ($0.15/1M tokens)
- **Analysis**: `anthropic/claude-sonnet-4.5` ($3/1M tokens)
- **Complex Reasoning**: `anthropic/claude-opus-4` ($15/1M tokens)

### 4. Provider Routing
Control which providers handle your requests:
```python
from langchain_openrouter import ChatOpenRouter

model = ChatOpenRouter(
    model="anthropic/claude-sonnet-4.5",
    openrouter_provider={
        "order": ["Anthropic", "Google"],  # Try Anthropic first
        "data_collection": "deny",         # Don't train on my data
    }
)
```

## 📊 Current Configuration

Your `.env` is configured with:
```bash
OPENROUTER_API_KEY=sk-or-v1-...
GANDALF_MODEL=moonshotai/kimi-k2.6      # Default model
SARUMAN_MODEL=anthropic/claude-opus-4.7  # Advanced analysis
```

## 🧪 Test Results

Run `python test_openrouter.py` to verify:

✅ Basic Chat Completion
✅ Structured Output (Pydantic)
✅ Model Selection (GPT-4o-mini, Claude, Gemini)
⚠️ JSON Response (use structured output instead)
✅ Saruman Agent

## 🔄 Migration Status

### ✅ Migrated
- `graph/nodes.py` - Uses openrouter_client
- All LLM calls in pipeline now use OpenRouter

### 📝 To Migrate
Individual fellowship agents can be updated to use structured output:
- `boromir.py` - Triage
- `gollum.py` - Adversarial review
- `elrond.py` - Cross-validation
- `eowyn.py` - Export functions
- etc.

See `AGENT_MIGRATION_GUIDE.md` for patterns.

## 💡 Usage Examples

### Basic Analysis
```python
from tools.openrouter_client import chat

messages = [
    {"role": "system", "content": "You are a malware analyst"},
    {"role": "user", "content": "What does CreateRemoteThread indicate?"}
]

response = chat(messages, temperature=0.3)
print(response)
```

### Structured Analysis
```python
from agents.fellowship.saruman import analyze_with_structured_output

result = analyze_with_structured_output(
    sha256="abc123...",
    file_type="PE32",
    signals=[...],
    metadata={...}
)

for hypothesis in result.hypotheses:
    print(f"{hypothesis.category}: {hypothesis.confidence}%")
```

### Custom Model Selection
```python
from tools.openrouter_client import chat

# Fast model for simple tasks
response = chat(messages, model="openai/gpt-4o-mini")

# Powerful model for complex reasoning
response = chat(messages, model="anthropic/claude-opus-4")

# Your configured default
response = chat(messages)  # Uses GANDALF_MODEL
```

## 🔧 Configuration

### Environment Variables
```bash
# Required
OPENROUTER_API_KEY=sk-or-v1-...

# Optional (with defaults)
GANDALF_MODEL=openai/gpt-4o-mini
SARUMAN_MODEL=anthropic/claude-sonnet-4.5
```

### Model Selection Guide
| Task | Recommended Model | Cost | Speed |
|------|------------------|------|-------|
| Triage | `openai/gpt-4o-mini` | $ | ⚡⚡⚡ |
| Filtering | `openai/gpt-4o-mini` | $ | ⚡⚡⚡ |
| Analysis | `anthropic/claude-sonnet-4.5` | $$ | ⚡⚡ |
| Reasoning | `anthropic/claude-opus-4` | $$$ | ⚡ |
| Multimodal | `google/gemini-2.5-pro` | $$ | ⚡⚡ |

## 📚 Documentation

- **Setup Guide**: `OPENROUTER_SETUP.md`
- **Migration Guide**: `AGENT_MIGRATION_GUIDE.md`
- **OpenRouter Docs**: https://openrouter.ai/docs
- **LangChain Integration**: https://docs.langchain.com/oss/python/integrations/chat/openrouter
- **Available Models**: https://openrouter.ai/models

## 🐛 Troubleshooting

### "OPENROUTER_API_KEY not set"
Check your `.env` file has:
```bash
OPENROUTER_API_KEY=sk-or-v1-...
```

### Import errors
Make sure you're using the virtual environment:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Model not found
Check available models at https://openrouter.ai/models

### Rate limiting
OpenRouter has rate limits. The client will log errors if you hit them.

### JSON parsing errors
Use `chat_structured()` instead of `chat_json()` for reliable structured output.

## 🎓 Next Steps

1. **Run the tests**: `python test_openrouter.py`
2. **Try Saruman agent**: See examples in `test_openrouter.py`
3. **Migrate other agents**: Follow `AGENT_MIGRATION_GUIDE.md`
4. **Optimize costs**: Use appropriate models for each task
5. **Add multimodal**: Analyze screenshots, memory dumps, etc.

## 💰 Cost Tracking

To track costs per analysis:
```python
from tools.openrouter_client import get_model

model = get_model()
response = model.invoke(messages)

# Check token usage
usage = response.usage_metadata
print(f"Tokens: {usage['total_tokens']}")
print(f"Input: {usage['input_tokens']}")
print(f"Output: {usage['output_tokens']}")
```

## 🔐 Security Notes

- OpenRouter API keys start with `sk-or-v1-`
- Keys are stored in `.env` (not committed to git)
- Set `data_collection: "deny"` to prevent training on your data
- Use provider routing to control which providers see your data

## 📞 Support

- **OpenRouter Issues**: https://openrouter.ai/docs
- **LangChain Issues**: https://github.com/langchain-ai/langchain
- **MORDOR Issues**: Check your project's issue tracker

---

**Status**: ✅ OpenRouter integration complete and tested
**Version**: 1.0.0
**Last Updated**: 2026-05-09
