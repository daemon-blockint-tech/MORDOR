from __future__ import annotations

import logging
import os
import subprocess

from agents.gates import skip_llm
from agents.schemas import MerryDependencySchema
from tools.openrouter_client import chat_structured

logger = logging.getLogger("mordor.agents.merry")


def _check_otool(binary_path: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["otool", "-L", binary_path],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            deps = []
            for line in result.stdout.strip().split("\n")[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("(")
                name = parts[0].strip() if parts else line.strip()
                deps.append({"name": name, "version": "unknown", "source": "otool"})
            return deps
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("otool not available: %s", e)
    return []


def _check_ldd(binary_path: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["ldd", binary_path],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            deps = []
            for line in result.stdout.strip().split("\n"):
                parts = line.split("=>")
                if len(parts) >= 2:
                    name = parts[0].strip()
                    resolved = parts[1].strip().split()[0] if parts[1].strip() else ""
                    deps.append({"name": name, "version": resolved, "source": "ldd"})
            return deps
    except FileNotFoundError:
        logger.debug("ldd not available")
    return []


def audit_dependencies(binary_path: str, tier: str = "standard") -> dict:
    if not os.path.exists(binary_path):
        return {"dependencies": [], "recommendations": ["Binary file not found"]}

    deps = _check_otool(binary_path) or _check_ldd(binary_path)

    if deps:
        known_risky = {"libssl", "libcrypto", "libcurl", "libssh", "libz"}
        recommendations = []
        for d in deps:
            name = d.get("name", "").lower()
            for risky in known_risky:
                if risky in name:
                    recommendations.append(f"Verify {d['name']} is up-to-date and not vulnerable")

        if not recommendations:
            recommendations.append("No known vulnerable dependencies detected")

        return {"dependencies": deps, "recommendations": recommendations}

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are MERRY, a dependency auditor. "
                "Given a binary, list common dependency risks, known vulnerable libraries, "
                "and supply-chain concerns.",
            },
            {
                "role": "user",
                "content": f"Audit dependencies for this binary path: {binary_path}",
            },
        ]
        result = chat_structured(
            messages, schema=MerryDependencySchema,
            temperature=0.3, agent_name="merry", phase="fingerprint",
        )
        if result is not None:
            return result.model_dump()
    return {"dependencies": [], "recommendations": []}
