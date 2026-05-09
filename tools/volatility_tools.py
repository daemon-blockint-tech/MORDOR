from __future__ import annotations

import logging
import os
import subprocess

from tools.safe_util import safe_subprocess_env, get_subprocess_timeout

logger = logging.getLogger("mordor.tools.volatility")


def _vol3_available() -> bool:
    try:
        import volatility3  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        subprocess.run(["vol", "--help"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        pass
    return False


def analyze_dump(dump_path: str) -> dict:
    if not os.path.exists(dump_path):
        logger.warning("Memory dump not found: %s", dump_path)
        return {"processes": [], "network": [], "registry": [], "status": "file_not_found"}

    try:
        from volatility3.cli import volshell  # noqa: F401
    except ImportError:
        logger.warning("volatility3 not installed, falling back to CLI")

    try:
        safe_env = safe_subprocess_env()
        result = subprocess.run(
            ["vol", "-f", dump_path, "windows.pstree"],
            capture_output=True, text=True, timeout=get_subprocess_timeout(300),
            env=safe_env, check=False,
        )
        if result.returncode == 0:
            return {"processes": result.stdout[:5000], "network": [], "registry": [], "status": "ok"}

        result = subprocess.run(
            ["vol", "-f", dump_path, "linux.pstree"],
            capture_output=True, text=True, timeout=get_subprocess_timeout(300),
            env=safe_env, check=False,
        )
        if result.returncode == 0:
            return {"processes": result.stdout[:5000], "network": [], "registry": [], "status": "ok"}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("Volatility analysis failed: %s", e)

    return {"processes": [], "network": [], "registry": [], "status": "unavailable"}
