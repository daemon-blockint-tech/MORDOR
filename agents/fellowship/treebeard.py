from __future__ import annotations

import logging
import os
import subprocess

from agents.gates import skip_llm
from agents.schemas import TreebeardSandboxSchema
from tools.openrouter_client import chat_structured
from tools.safe_util import safe_subprocess_env, get_subprocess_timeout, validate_docker_path, sanitize_for_prompt

logger = logging.getLogger("mordor.treebeard")


def verify_sandbox() -> bool:
    try:
        # Check docker without using shell wrapper
        result = subprocess.run(["docker", "info"], capture_output=True, text=True,
                                check=False, env=safe_subprocess_env(),
                                timeout=get_subprocess_timeout(30))
        return result.returncode == 0
    except Exception:
        return False


def _safely_inject_binary(binary_path: str, container_name: str = "mordor-sandbox") -> bool:
    """Safely injects the malware binary into the sandbox via docker cp."""
    allowed_base = os.environ.get("MORDOR_CASES_DIR", os.path.realpath("cases"))
    try:
        safe_path = validate_docker_path(binary_path, allowed_base)
    except (ValueError, FileNotFoundError) as e:
        logger.error(f"Binary injection blocked: {e}")
        return False
    try:
        # Never execute the binary on the host
        # Inject via docker cp
        result = subprocess.run(
            ["docker", "cp", safe_path, f"{container_name}:/workspace/sample.bin"],
            capture_output=True, check=False,
            env=safe_subprocess_env(), timeout=get_subprocess_timeout(60),
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Failed to inject binary into sandbox: {e}")
        return False


def run_in_sandbox(binary_path: str, use_llm_fallback: bool = True, tier: str = "standard") -> dict:
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
            "content": f"Simulate sandbox analysis for: {sanitize_for_prompt(binary_path)}",
        },
    ]
    result = chat_structured(
        messages, schema=TreebeardSandboxSchema,
        temperature=0.3, agent_name="treebeard", phase="validate",
    )
    if result is None:
        return {"status": "sandbox_not_available", "results": {}, "container_id": None}
    return result.model_dump()
