#!/usr/bin/env python3
"""
OpenRouter Integration Examples for MORDOR

This file demonstrates various ways to use OpenRouter with LangChain
in the MORDOR malware analysis system.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def example_1_basic_chat():
    """Example 1: Basic chat completion."""
    print("\n" + "="*60)
    print("Example 1: Basic Chat Completion")
    print("="*60)
    
    from tools.openrouter_client import chat
    
    messages = [
        {"role": "system", "content": "You are a malware analysis expert."},
        {"role": "user", "content": "What does the CreateRemoteThread API indicate in malware?"}
    ]
    
    response = chat(messages, temperature=0.3)
    print(f"\nResponse:\n{response}")


def example_2_structured_output():
    """Example 2: Structured output with Pydantic."""
    print("\n" + "="*60)
    print("Example 2: Structured Output")
    print("="*60)
    
    from pydantic import BaseModel, Field
    from tools.openrouter_client import chat_structured
    
    class MalwareIndicator(BaseModel):
        """Structured malware indicator."""
        indicator_type: str = Field(description="Type: persistence, c2, injection, etc.")
        severity: str = Field(description="Severity: critical, high, medium, low")
        confidence: float = Field(description="Confidence 0-100", ge=0, le=100)
        description: str = Field(description="What this indicator means")
        mitigation: str = Field(description="How to mitigate this threat")
    
    messages = [
        {"role": "system", "content": "You are a malware analyst."},
        {
            "role": "user",
            "content": "Analyze this behavior: A process writes to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        }
    ]
    
    result = chat_structured(
        messages=messages,
        schema=MalwareIndicator,
        temperature=0.2
    )
    
    if result:
        print(f"\nIndicator Type: {result.indicator_type}")
        print(f"Severity: {result.severity}")
        print(f"Confidence: {result.confidence}%")
        print(f"Description: {result.description}")
        print(f"Mitigation: {result.mitigation}")


def example_3_multiple_models():
    """Example 3: Using different models for different tasks."""
    print("\n" + "="*60)
    print("Example 3: Multiple Models")
    print("="*60)
    
    from tools.openrouter_client import chat
    
    question = "Is CreateRemoteThread always malicious?"
    
    models = [
        ("openai/gpt-4o-mini", "Fast & Cheap"),
        ("anthropic/claude-sonnet-4.5", "Balanced"),
        ("google/gemini-2.5-flash", "Google's Fast Model"),
    ]
    
    for model, description in models:
        print(f"\n{description} ({model}):")
        response = chat(
            messages=[{"role": "user", "content": question}],
            model=model,
            temperature=0.3,
            max_tokens=100
        )
        print(f"  {response[:150]}...")


def example_4_saruman_agent():
    """Example 4: Using the Saruman agent for advanced analysis."""
    print("\n" + "="*60)
    print("Example 4: Saruman Agent (Advanced Analysis)")
    print("="*60)
    
    from agents.fellowship.saruman import analyze_with_structured_output
    
    # Mock data for demonstration
    sha256 = "a" * 64
    file_type = "PE32 executable (GUI) Intel 80386, for MS Windows"
    
    signals = [
        {"type": "import", "value": "CreateRemoteThread"},
        {"type": "import", "value": "VirtualAllocEx"},
        {"type": "import", "value": "WriteProcessMemory"},
        {"type": "string", "value": "http://malicious-c2.com/beacon"},
        {"type": "string", "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"type": "string", "value": "cmd.exe /c powershell -enc"},
    ]
    
    metadata = {
        "file_type": file_type,
        "imports_count": 45,
        "strings_count": 234,
        "sections_count": 5,
        "packer_hints": ["UPX"],
        "osint_malicious": True,
    }
    
    print("\nAnalyzing binary with Saruman...")
    print(f"SHA256: {sha256[:16]}...")
    print(f"Signals: {len(signals)}")
    
    result = analyze_with_structured_output(sha256, file_type, signals, metadata)
    
    if result:
        print("\n✓ Analysis Complete!")
        print(f"\nOverall Risk: {result.overall_risk}/100")
        
        print(f"\nHypotheses ({len(result.hypotheses)}):")
        for i, h in enumerate(result.hypotheses, 1):
            print(f"\n  {i}. {h.category.upper()}")
            print(f"     Description: {h.description[:80]}...")
            print(f"     Confidence: {h.confidence}%")
            print(f"     Risk Score: {h.risk_score}")
            if h.mitre_tactics:
                print(f"     MITRE Tactics: {', '.join(h.mitre_tactics)}")
        
        print("\nRecommended Actions:")
        for action in result.recommended_actions:
            print(f"  • {action}")
    else:
        print("✗ Analysis failed")


def example_5_cost_optimization():
    """Example 5: Cost optimization strategies."""
    print("\n" + "="*60)
    print("Example 5: Cost Optimization")
    print("="*60)
    
    from tools.openrouter_client import chat, get_model
    
    # Strategy 1: Use fast model for simple tasks
    print("\nStrategy 1: Fast model for triage")
    response = chat(
        messages=[{"role": "user", "content": "Is this suspicious: CreateFile"}],
        model="openai/gpt-4o-mini",  # Cheapest
        temperature=0.2,
        max_tokens=50  # Limit tokens
    )
    print(f"  Response: {response[:100]}...")
    
    # Strategy 2: Check token usage
    print("\nStrategy 2: Monitor token usage")
    model = get_model(model="openai/gpt-4o-mini")
    result = model.invoke([{"role": "user", "content": "What is malware?"}])
    
    if hasattr(result, 'usage_metadata'):
        usage = result.usage_metadata
        print(f"  Input tokens: {usage.get('input_tokens', 0)}")
        print(f"  Output tokens: {usage.get('output_tokens', 0)}")
        print(f"  Total tokens: {usage.get('total_tokens', 0)}")


def example_6_error_handling():
    """Example 6: Proper error handling."""
    print("\n" + "="*60)
    print("Example 6: Error Handling")
    print("="*60)
    
    from tools.openrouter_client import chat_structured
    from pydantic import BaseModel, Field
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    class Analysis(BaseModel):
        result: str = Field(description="Analysis result")
    
    # This will fail gracefully
    print("\nTesting with invalid model...")
    result = chat_structured(
        messages=[{"role": "user", "content": "test"}],
        schema=Analysis,
        model="invalid/model-name"
    )
    
    if result:
        print(f"  Result: {result.result}")
    else:
        print("  ✓ Handled error gracefully (returned None)")


def example_7_provider_routing():
    """Example 7: Provider routing and preferences."""
    print("\n" + "="*60)
    print("Example 7: Provider Routing")
    print("="*60)
    
    from langchain_openrouter import ChatOpenRouter
    import os
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("  ⚠ OPENROUTER_API_KEY not set, skipping example")
        return
    
    # Prefer specific providers
    model = ChatOpenRouter(
        model="anthropic/claude-sonnet-4.5",
        openrouter_api_key=api_key,
        openrouter_provider={
            "order": ["Anthropic", "Google"],  # Try Anthropic first
            "allow_fallbacks": True,
            "data_collection": "deny",  # Don't train on my data
        }
    )
    
    response = model.invoke([{"role": "user", "content": "Hello!"}])
    print(f"\n  Response: {response.content}")
    print(f"  Provider used: {response.response_metadata.get('model_provider', 'unknown')}")


def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("MORDOR OpenRouter Integration Examples")
    print("="*60)
    
    examples = [
        ("Basic Chat", example_1_basic_chat),
        ("Structured Output", example_2_structured_output),
        ("Multiple Models", example_3_multiple_models),
        ("Saruman Agent", example_4_saruman_agent),
        ("Cost Optimization", example_5_cost_optimization),
        ("Error Handling", example_6_error_handling),
        ("Provider Routing", example_7_provider_routing),
    ]
    
    print("\nAvailable examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    print("\nRunning all examples...\n")
    
    for name, func in examples:
        try:
            func()
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            break
        except Exception as e:
            print(f"\n✗ Example '{name}' failed: {e}")
    
    print("\n" + "="*60)
    print("Examples complete!")
    print("="*60)


if __name__ == "__main__":
    main()
