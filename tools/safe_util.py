from __future__ import annotations

import os
import re
from pathlib import Path

_SENSITIVE_ENV_PATTERNS = [
    re.compile(r"^(?:[A-Z0-9_]+_)?API_KEY$"),
    re.compile(r"^(?:[A-Z0-9_]+_)?TOKEN$"),
    re.compile(r"^(?:[A-Z0-9_]+_)?SECRET$"),
    re.compile(r"^(?:[A-Z0-9_]+_)?PASSWORD$"),
    re.compile(r"^(?:[A-Z0-9_]+_)?KEY$"),
]

_KNOWN_SENSITIVE_KEYS: set[str] = {
    "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "SHODAN_API_KEY",
    "IDA_API_KEY", "MORDOR_API_KEY",
}


def sanitize_path(user_path: str, allowed_base: str | Path | None = None) -> str:
    resolved = os.path.realpath(user_path)
    if allowed_base:
        base = os.path.realpath(str(allowed_base))
        if not resolved.startswith(base + "/") and resolved != base:
            raise ValueError(f"Path traversal blocked: {resolved} is not under {base}")
    return resolved


def safe_subprocess_env() -> dict[str, str]:
    safe_env = os.environ.copy()
    keys_to_remove: list[str] = []
    for key in safe_env:
        if key in _KNOWN_SENSITIVE_KEYS:
            keys_to_remove.append(key)
        elif any(p.match(key) for p in _SENSITIVE_ENV_PATTERNS):
            keys_to_remove.append(key)
    for k in keys_to_remove:
        del safe_env[k]
    return safe_env


def get_subprocess_timeout(default: int = 120) -> int:
    try:
        return int(os.environ.get("MORDOR_SUBPROCESS_TIMEOUT", str(default)))
    except (ValueError, TypeError):
        return default


def validate_docker_path(user_path: str, allowed_base: str | Path) -> str:
    resolved = os.path.realpath(user_path)
    base = os.path.realpath(str(allowed_base))
    if not resolved.startswith(base + "/") and resolved != base:
        raise ValueError(f"Docker path traversal blocked: {resolved} not under {base}")
    if not os.path.isfile(resolved):
        raise FileNotFoundError(f"Docker source path not found: {resolved}")
    return resolved


def validate_solana_address(address: str) -> bool:
    if not re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", address):
        return False
    return True


def validate_amount(amount: str) -> bool:
    try:
        val = float(amount)
        return val > 0
    except (ValueError, TypeError):
        return False


def escape_yara_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return escaped


def escape_sigma_value(value: str) -> str:
    if isinstance(value, str):
        return value.replace("\\", "\\\\").replace("'", "\\'")
    return value


def sanitize_for_prompt(value: str, max_len: int = 255) -> str:
    safe = os.path.basename(value)
    safe = re.sub(r"[\x00-\x1f\x7f]", "", safe)
    if len(safe) > max_len:
        safe = safe[:max_len]
    return safe
