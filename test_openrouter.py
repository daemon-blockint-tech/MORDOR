#!/usr/bin/env python3
"""Test script for OpenRouter integration."""
from __future__ import annotations

import json
import logging
import sys

from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("test_openrouter")


def test_basic_chat():
    """Test basic chat completion."""
    from tools.openrouter_client import chat
    
    print("\n" + "="*60)
    print("TEST 1: Basic Chat Completion")
    print("="*60)
    
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is malware analysis? Answer in one sentence."}
    ]
    
    response = chat(messages, temperature=0.3)
    
    if response:
        print("✓ Success!")
        print(f"Response: {response}")
        return True
    else:
        print("✗ Failed - no response")
        return False


def test_json_response():
    """Test JSON-formatted response."""
    from tools.openrouter_client import chat_json
    
    print("\n" + "="*60)
    print("TEST 2: JSON Response")
    print("="*60)
    
    messages = [
        {"role": "system", "content": "You are a malware analyst."},
        {
            "role": "user",
            "content": """Analyze this suspicious behavior and return JSON:
            
Behavior: Process creates registry key at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

Return JSON with this structure:
{
  "threat_type": "persistence",
  "severity": "high/medium/low",
  "confidence": 0-100,
  "description": "brief explanation"
}"""
        }
    ]
    
    response = chat_json(messages, temperature=0.2)
    
    if response:
        print("✓ Success!")
        print(f"Response: {json.dumps(response, indent=2)}")
        return True
    else:
        print("✗ Failed - no response or invalid JSON")
        return False


def test_structured_output():
    """Test structured output with Pydantic schema."""
    from tools.openrouter_client import chat_structured
    
    print("\n" + "="*60)
    print("TEST 3: Structured Output (Pydantic)")
    print("="*60)
    
    class ThreatAssessment(BaseModel):
        """Threat assessment schema."""
        threat_type: str = Field(description="Type of threat")
        severity: str = Field(description="Severity: critical, high, medium, or low")
        confidence: float = Field(description="Confidence score 0-100", ge=0, le=100)
        indicators: list[str] = Field(description="List of indicators")
        recommended_action: str = Field(description="Recommended action")
    
    messages = [
        {"role": "system", "content": "You are a cybersecurity analyst."},
        {
            "role": "user",
            "content": """Assess this threat:
            
A binary is making network connections to multiple IPs in different countries,
encrypting files with AES, and creating scheduled tasks for persistence.

Provide a structured threat assessment."""
        }
    ]
    
    response = chat_structured(
        messages=messages,
        schema=ThreatAssessment,
        temperature=0.2
    )
    
    if response:
        print("✓ Success!")
        print(f"Threat Type: {response.threat_type}")
        print(f"Severity: {response.severity}")
        print(f"Confidence: {response.confidence}%")
        print(f"Indicators: {', '.join(response.indicators)}")
        print(f"Action: {response.recommended_action}")
        return True
    else:
        print("✗ Failed - no response")
        return False


def test_model_selection():
    """Test using different models."""
    from tools.openrouter_client import chat
    
    print("\n" + "="*60)
    print("TEST 4: Model Selection")
    print("="*60)
    
    models_to_test = [
        "openai/gpt-4o-mini",
        "anthropic/claude-sonnet-4.5",
        "google/gemini-2.5-flash",
    ]
    
    messages = [
        {"role": "user", "content": "Say 'Hello from [model name]' in one sentence."}
    ]
    
    results = []
    for model in models_to_test:
        print(f"\nTesting {model}...")
        try:
            response = chat(messages, model=model, temperature=0.5, max_tokens=50)
            if response:
                print(f"  ✓ {model}: {response[:100]}")
                results.append(True)
            else:
                print(f"  ✗ {model}: No response")
                results.append(False)
        except Exception as e:
            print(f"  ✗ {model}: Error - {e}")
            results.append(False)
    
    return all(results)


def test_saruman_agent():
    """Test the Saruman agent with structured output."""
    from agents.fellowship.saruman import analyze_with_structured_output
    
    print("\n" + "="*60)
    print("TEST 5: Saruman Agent (Structured Analysis)")
    print("="*60)
    
    # Mock data for testing
    sha256 = "a" * 64
    file_type = "PE32 executable"
    signals = [
        {"type": "import", "value": "CreateRemoteThread"},
        {"type": "import", "value": "VirtualAllocEx"},
        {"type": "string", "value": "http://malicious-c2.com/beacon"},
        {"type": "string", "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
    ]
    metadata = {
        "imports_count": 45,
        "strings_count": 234,
        "sections_count": 5,
        "packer_hints": ["UPX"],
    }
    
    result = analyze_with_structured_output(sha256, file_type, signals, metadata)
    
    if result:
        print("✓ Success!")
        print(f"\nOverall Risk: {result.overall_risk}/100")
        print(f"\nHypotheses ({len(result.hypotheses)}):")
        for i, h in enumerate(result.hypotheses, 1):
            print(f"  {i}. {h.category}: {h.description[:80]}...")
            print(f"     Confidence: {h.confidence}%, Risk: {h.risk_score}")
        print("\nRecommended Actions:")
        for action in result.recommended_actions:
            print(f"  - {action}")
        return True
    else:
        print("✗ Failed - no result")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("MORDOR OpenRouter Integration Tests")
    print("="*60)
    
    tests = [
        ("Basic Chat", test_basic_chat),
        ("JSON Response", test_json_response),
        ("Structured Output", test_structured_output),
        ("Model Selection", test_model_selection),
        ("Saruman Agent", test_saruman_agent),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            logger.error(f"Test '{name}' crashed: {e}", exc_info=True)
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
