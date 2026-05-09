# Agent Migration Guide: Daemon → OpenRouter

Quick guide for updating your fellowship agents to use OpenRouter with structured output.

## Pattern 1: Simple Function (No LLM calls)

**No changes needed** for agents that don't make LLM calls:
- `frodo.py` - Frida hooks
- `gimli.py` - Binary tracing
- `legolas.py` - Static analysis
- `aragorn.py` - OSINT
- etc.

## Pattern 2: Basic Chat → Structured Output

### Before (daemon_client)
```python
from tools.daemon_client import chat_json

def analyze_something(data):
    prompt = f"Analyze this: {data}"
    result = chat_json([
        {"role": "system", "content": "You are an analyst"},
        {"role": "user", "content": prompt}
    ])
    return result  # Hope it's valid JSON!
```

### After (openrouter_client with Pydantic)
```python
from pydantic import BaseModel, Field
from tools.openrouter_client import chat_structured

class AnalysisResult(BaseModel):
    """Structured analysis result."""
    category: str = Field(description="Analysis category")
    confidence: float = Field(description="Confidence 0-100", ge=0, le=100)
    findings: list[str] = Field(description="Key findings")

def analyze_something(data):
    prompt = f"Analyze this: {data}"
    result = chat_structured(
        messages=[
            {"role": "system", "content": "You are an analyst"},
            {"role": "user", "content": prompt}
        ],
        schema=AnalysisResult,
        temperature=0.3
    )
    return result  # Guaranteed to match schema!
```

## Pattern 3: Agent-Specific Schemas

Create Pydantic models for each agent's output:

### Boromir (Triage)
```python
from pydantic import BaseModel, Field

class TriageResult(BaseModel):
    """Boromir's triage assessment."""
    filtered_signals: list[dict] = Field(description="Signals that passed triage")
    dismissed_signals: list[dict] = Field(description="Signals dismissed as noise")
    confidence_score: float = Field(description="Overall confidence", ge=0, le=100)
    priority: str = Field(description="Priority: critical, high, medium, low")
    reasoning: str = Field(description="Triage reasoning")

def triage(signals: list[dict]) -> TriageResult:
    from tools.openrouter_client import chat_structured
    
    prompt = f"Triage these {len(signals)} signals..."
    
    return chat_structured(
        messages=[
            {"role": "system", "content": "You are Boromir, a triage specialist"},
            {"role": "user", "content": prompt}
        ],
        schema=TriageResult,
        model="openai/gpt-4o-mini",  # Fast model for triage
        temperature=0.2
    )
```

### Gollum (Adversarial Review)
```python
class AdversarialReview(BaseModel):
    """Gollum's adversarial review."""
    confirmed_flags: list[str] = Field(description="Confirmed suspicious flags")
    dismissed_flags: list[str] = Field(description="False positives")
    confidence_adjustments: dict[str, float] = Field(
        description="Confidence adjustments per flag"
    )
    alternative_explanations: list[str] = Field(
        description="Benign explanations for suspicious behavior"
    )

def adversarial_review(signals: list[dict]) -> AdversarialReview:
    from tools.openrouter_client import chat_structured
    
    prompt = "Challenge these findings with alternative explanations..."
    
    return chat_structured(
        messages=[
            {"role": "system", "content": "You are Gollum, a skeptical reviewer"},
            {"role": "user", "content": prompt}
        ],
        schema=AdversarialReview,
        temperature=0.4  # Higher temp for creative alternatives
    )
```

### Elrond (Cross-Validation)
```python
class ValidationResult(BaseModel):
    """Elrond's cross-validation result."""
    agreement_score: float = Field(description="Agreement score 0-100", ge=0, le=100)
    conflicts: list[dict] = Field(description="Conflicting findings")
    consensus: dict = Field(description="Consensus findings")
    recommendations: list[str] = Field(description="Recommendations")

def cross_validate(analysis_results: dict) -> ValidationResult:
    from tools.openrouter_client import chat_structured
    
    return chat_structured(
        messages=[
            {"role": "system", "content": "You are Elrond, a wise validator"},
            {"role": "user", "content": f"Cross-validate: {analysis_results}"}
        ],
        schema=ValidationResult,
        model="anthropic/claude-sonnet-4.5",  # Better reasoning
        temperature=0.1
    )
```

## Pattern 4: Multi-Step Analysis

For complex agents that need multiple LLM calls:

```python
from pydantic import BaseModel, Field
from tools.openrouter_client import chat_structured

class InitialAssessment(BaseModel):
    threat_level: str
    key_indicators: list[str]

class DetailedAnalysis(BaseModel):
    techniques: list[str]
    mitre_tactics: list[str]
    confidence: float

def complex_analysis(data):
    # Step 1: Quick assessment with fast model
    initial = chat_structured(
        messages=[{"role": "user", "content": f"Quick assessment: {data}"}],
        schema=InitialAssessment,
        model="openai/gpt-4o-mini",
        temperature=0.2
    )
    
    # Step 2: Detailed analysis only if needed
    if initial.threat_level in ["high", "critical"]:
        detailed = chat_structured(
            messages=[{
                "role": "user",
                "content": f"Deep analysis of {initial.key_indicators}"
            }],
            schema=DetailedAnalysis,
            model="anthropic/claude-opus-4",  # Use powerful model
            temperature=0.1
        )
        return detailed
    
    return initial
```

## Pattern 5: Model Selection by Task

Choose models based on task complexity:

```python
def get_model_for_task(task_type: str) -> str:
    """Select appropriate model for task."""
    models = {
        "triage": "openai/gpt-4o-mini",           # Fast, cheap
        "filter": "openai/gpt-4o-mini",           # Fast, cheap
        "analysis": "anthropic/claude-sonnet-4.5", # Balanced
        "reasoning": "anthropic/claude-opus-4",    # Most capable
        "validation": "anthropic/claude-sonnet-4.5",
        "report": "openai/gpt-4o",                # Good at writing
    }
    return models.get(task_type, "openai/gpt-4o-mini")

def analyze_with_right_model(data, task_type):
    from tools.openrouter_client import chat_structured
    
    model = get_model_for_task(task_type)
    
    return chat_structured(
        messages=[{"role": "user", "content": data}],
        schema=YourSchema,
        model=model
    )
```

## Pattern 6: Error Handling

Add proper error handling:

```python
from typing import Optional
import logging

logger = logging.getLogger(__name__)

def safe_analysis(data) -> Optional[AnalysisResult]:
    """Analysis with error handling."""
    from tools.openrouter_client import chat_structured
    
    try:
        result = chat_structured(
            messages=[{"role": "user", "content": data}],
            schema=AnalysisResult,
            temperature=0.3
        )
        
        if result:
            logger.info("Analysis successful: %s", result.category)
            return result
        else:
            logger.warning("Analysis returned None")
            return None
            
    except Exception as e:
        logger.error("Analysis failed: %s", e, exc_info=True)
        return None
```

## Pattern 7: Streaming (Future)

For long-running analyses:

```python
# Not yet implemented in openrouter_client, but planned:
def stream_analysis(data):
    from tools.openrouter_client import get_model
    
    model = get_model(temperature=0.3)
    
    for chunk in model.stream([
        {"role": "user", "content": data}
    ]):
        yield chunk.content
```

## Migration Checklist

For each agent that uses LLM:

- [ ] Define Pydantic schema for output
- [ ] Replace `daemon_client` import with `openrouter_client`
- [ ] Change `chat_json()` to `chat_structured()`
- [ ] Add type hints for return values
- [ ] Choose appropriate model for task
- [ ] Set appropriate temperature
- [ ] Add error handling
- [ ] Test with `test_openrouter.py`
- [ ] Update docstrings

## Example: Complete Agent Migration

### Before
```python
def triage(signals):
    from tools.daemon_client import chat_json
    
    result = chat_json([
        {"role": "user", "content": f"Triage: {signals}"}
    ])
    return result or {}
```

### After
```python
from pydantic import BaseModel, Field
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class TriageResult(BaseModel):
    """Structured triage result."""
    filtered_signals: list[dict] = Field(description="Signals that passed")
    confidence_score: float = Field(description="Confidence 0-100", ge=0, le=100)
    priority: str = Field(description="Priority level")

def triage(signals: list[dict]) -> Optional[TriageResult]:
    """
    Triage signals to filter noise and prioritize threats.
    
    Args:
        signals: List of signal dicts to triage.
    
    Returns:
        TriageResult with filtered signals and confidence, or None on error.
    """
    from tools.openrouter_client import chat_structured
    
    try:
        result = chat_structured(
            messages=[
                {"role": "system", "content": "You are Boromir, a triage specialist"},
                {"role": "user", "content": f"Triage these {len(signals)} signals: {signals}"}
            ],
            schema=TriageResult,
            model="openai/gpt-4o-mini",
            temperature=0.2
        )
        
        if result:
            logger.info(
                "Triage complete: %d/%d signals passed (%.0f%% confidence)",
                len(result.filtered_signals),
                len(signals),
                result.confidence_score
            )
        
        return result
        
    except Exception as e:
        logger.error("Triage failed: %s", e, exc_info=True)
        return None
```

## Benefits of Migration

✅ **Type Safety** - Pydantic validates all outputs
✅ **No JSON Parsing Errors** - Structured output handles it
✅ **Better IDE Support** - Autocomplete for result fields
✅ **Easier Testing** - Mock Pydantic objects
✅ **Self-Documenting** - Schema describes expected output
✅ **More Models** - Access to 50+ providers via OpenRouter
✅ **Cost Optimization** - Choose right model for each task
