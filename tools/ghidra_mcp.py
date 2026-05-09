from __future__ import annotations

import json
import logging
from typing import Any

import requests

logger = logging.getLogger("mordor.tools.ghidra")

GHIDRA_SERVER_URL = "http://127.0.0.1:8080/"
TIMEOUT = 30


def _get(endpoint: str, params: dict | None = None) -> list[str]:
    url = f"{GHIDRA_SERVER_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        resp = requests.get(url, params=params or {}, timeout=TIMEOUT)
        resp.encoding = "utf-8"
        if resp.ok:
            return resp.text.splitlines()
        logger.warning("Ghidra GET %s: %s", endpoint, resp.status_code)
        return []
    except requests.ConnectionError:
        logger.debug("Ghidra not reachable at %s", GHIDRA_SERVER_URL)
        return []
    except Exception as exc:
        logger.error("Ghidra GET %s failed: %s", endpoint, exc)
        return []


def _post(endpoint: str, data: dict | str) -> str | None:
    url = f"{GHIDRA_SERVER_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        payload = data if isinstance(data, str) else json.dumps(data)
        resp = requests.post(url, data=payload, timeout=TIMEOUT)
        resp.encoding = "utf-8"
        if resp.ok:
            return resp.text.strip()
        logger.warning("Ghidra POST %s: %s", endpoint, resp.status_code)
        return None
    except requests.ConnectionError:
        logger.debug("Ghidra not reachable at %s", GHIDRA_SERVER_URL)
        return None
    except Exception as exc:
        logger.error("Ghidra POST %s failed: %s", endpoint, exc)
        return None


def decompile_function(binary_path: str, function_name: str) -> dict[str, Any]:
    code = _post("decompile", function_name)
    return {
        "function": function_name,
        "decompiled": code or "",
        "binary_path": binary_path,
        "status": "ok" if code else "unreachable",
    }


def extract_call_graph(binary_path: str) -> dict[str, Any]:
    methods = _get("methods", {"offset": 0, "limit": 500})
    imports = _get("imports", {"offset": 0, "limit": 200})
    exports = _get("exports", {"offset": 0, "limit": 200})

    nodes = []
    edges = []

    for m in methods:
        if m and not m.startswith("Error"):
            nodes.append({"name": m.strip(), "type": "function"})

    for imp in imports:
        if imp and not imp.startswith("Error"):
            name = imp.strip()
            nodes.append({"name": name, "type": "import"})
            edges.append({"from": binary_path, "to": name, "type": "import"})

    for exp in exports:
        if exp and not exp.startswith("Error"):
            name = exp.strip()
            nodes.append({"name": name, "type": "export"})

    return {"nodes": nodes, "edges": edges, "status": "ok" if nodes else "unreachable"}


def get_imports(binary_path: str) -> list[dict[str, Any]]:
    raw = _get("imports", {"offset": 0, "limit": 500})
    return [
        {"name": i.strip(), "binary_path": binary_path}
        for i in raw
        if i and not i.startswith("Error")
    ]


def list_strings(filter_str: str | None = None) -> list[str]:
    params: dict[str, Any] = {"offset": 0, "limit": 2000}
    if filter_str:
        params["filter"] = filter_str
    raw = _get("strings", params)
    return [s.strip() for s in raw if s and not s.startswith("Error")]


def get_functions() -> list[dict[str, Any]]:
    raw = _get("methods", {"offset": 0, "limit": 1000})
    return [
        {"name": m.strip(), "address": ""}
        for m in raw
        if m and not m.startswith("Error")
    ]


def list_segments() -> list[dict[str, Any]]:
    raw = _get("segments", {"offset": 0, "limit": 100})
    return [
        {"name": s.strip()}
        for s in raw
        if s and not s.startswith("Error")
    ]


def is_available() -> bool:
    result = _get("methods", {"offset": 0, "limit": 1})
    return len(result) > 0 and not result[0].startswith("Error")
