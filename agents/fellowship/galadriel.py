from __future__ import annotations

import logging
from typing import Any

from tools.ida_tools import extract_with_ida

logger = logging.getLogger("mordor.agents.galadriel")

def analyze_with_ida(binary_path: str, file_type: str | None = None, tier: str = "standard") -> dict[str, Any]:
    """
    GALADRIEL: IDA Pro/Free Integration Agent.
    Runs headless static analysis via IDA Python scripts.
    """
    ida_result = extract_with_ida(binary_path)
    ida_ok = ida_result.get("status") == "ok"

    result = {
        "agent": "galadriel",
        "binary_path": binary_path,
        "ida_status": ida_result.get("status"),
        "error": ida_result.get("error")
    }

    if ida_ok:
        data = ida_result.get("results", {})
        result["functions"] = data.get("functions", [])
        result["strings"] = data.get("strings", [])
        result["imports"] = data.get("imports", [])

    return result
