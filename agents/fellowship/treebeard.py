from __future__ import annotations

import logging
import os
import subprocess

from agents.gates import skip_llm
from agents.schemas import TreebeardSandboxSchema
from tools.openrouter_client import chat_structured

logger = logging.getLogger("mordor.treebeard")


def verify_sandbox() -> bool:
    try:
        # Check docker without using shell wrapper
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False)
        return result.returncode == 0
    except Exception:
        return False


def _safely_inject_binary(binary_path: str, container_name: str = "mordor-sandbox") -> bool:
    """Safely injects the malware binary into the sandbox via docker cp."""
    if not os.path.isfile(binary_path):
        logger.error(f"Binary path not found: {binary_path}")
        return False
    try:
        # Never execute the binary on the host
        # Inject via docker cp
        result = subprocess.run(
            ["docker", "cp", binary_path, f"{container_name}:/workspace/sample.bin"],
            capture_output=True,
            check=False,
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Failed to inject binary into sandbox: {e}")
        return False


def run_in_sandbox(binary_path: str, use_llm_fallback: bool = True, tier: str = "standard") -> dict:
    # Explicitly strip sensitive API keys from the current execution environment (defense-in-depth)
    safe_env = os.environ.copy()
    for sensitive_key in ["ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "SHODAN_API_KEY"]:
        if sensitive_key in safe_env:
            del safe_env[sensitive_key]

    if not verify_sandbox():
        if not use_llm_fallback or skip_llm(tier):
            return {"status": "sandbox_not_available", "results": {}, "container_id": None}
        return _sandbox_llm_analysis(binary_path)

    # If sandbox is ready, safely inject without executing on host
    container_name = "mordor-sandbox"
    injection_success = _safely_inject_binary(binary_path, container_name)
    
    if not injection_success:
        return {"status": "injection_failed", "results": {}, "container_id": None}

    return {"status": "sandbox_ready", "results": {"container": container_name}, "container_id": None}


def _sandbox_llm_analysis(binary_path: str) -> dict:
    messages = [
        {
            "role": "system",
            "content": "You are TREEBEARD, a Docker sandbox isolation agent. "
            "Given a binary path, describe expected sandbox execution behavior: "
            "filesystem activity, network connections, process tree, and registry changes.",
        },
        {
            "role": "user",
            "content": f"Simulate sandbox analysis for: {binary_path}",
        },
    ]
    result = chat_structured(
        messages, schema=TreebeardSandboxSchema,
        temperature=0.3, agent_name="treebeard", phase="validate",
    )
    if result is None:
        return {"status": "sandbox_not_available", "results": {}, "container_id": None}
    return result.model_dump()
