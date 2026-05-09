from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any

from tools.safe_util import sanitize_path, safe_subprocess_env, get_subprocess_timeout

logger = logging.getLogger("mordor.tools.radare2")

R2_BIN = os.environ.get("R2_BIN", "/opt/homebrew/bin/r2")


def _r2(cmd: str, binary_path: str) -> str:
    if not os.path.isfile(binary_path):
        return ""
    try:
        safe_path = sanitize_path(binary_path)
        proc = subprocess.run(
            [R2_BIN, "-q", "-c", cmd, safe_path],
            capture_output=True, text=True, timeout=get_subprocess_timeout(60),
            env=safe_subprocess_env(),
        )
        return proc.stdout
    except Exception as exc:
        logger.error("r2 failed: %s", exc)
        return ""


def _parse_json_list(raw: str) -> list:
    if not raw.strip():
        return []
    try:
        data = json.loads(raw.strip())
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def _parse_json_dict(raw: str) -> dict:
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw.strip())
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def analyze_binary(binary_path: str) -> dict[str, Any]:
    ret: dict[str, Any] = {"sections": [], "functions": [], "strings": [], "imports": [], "exports": [], "info": {}, "status": "ok"}
    ret["sections"] = _parse_json_list(_r2("iSj", binary_path))
    ret["imports"] = _parse_json_list(_r2("iij", binary_path))
    ret["exports"] = _parse_json_list(_r2("iEj", binary_path))
    ret["strings"] = [{"value": s.get("string", ""), "addr": s.get("vaddr", 0), "section": s.get("section", "")} for s in _parse_json_list(_r2("izj", binary_path))]
    ret["info"] = _parse_json_dict(_r2("iIj", binary_path))
    if not any([ret["sections"], ret["imports"], ret["exports"]]):
        ret["status"] = "no_data"
        return ret
    func_raw = _r2("aaa; aflj", binary_path)
    ret["functions"] = [{"name": f.get("name", ""), "addr": f.get("addr", 0), "size": f.get("size", 0)} for f in _parse_json_list(func_raw)]
    return ret


def cross_reference(binary_path: str, address: str) -> list[dict[str, Any]]:
    raw = _r2(f"axtj {address}", binary_path)
    return [{"from": x.get("from", ""), "to": x.get("to", ""), "type": x.get("type", "")} for x in _parse_json_list(raw)]


def decompile_function(binary_path: str, function_name: str) -> dict[str, Any]:
    raw = _r2(f"s {function_name}; pdc", binary_path)
    return {"function": function_name, "decompiled": raw, "status": "ok" if raw else "error"}


def extract_call_graph(binary_path: str) -> dict[str, Any]:
    raw = _r2("aaa; aflj", binary_path)
    functions = _parse_json_list(raw)
    return {"nodes": [{"name": f.get("name", ""), "addr": f.get("addr", 0)} for f in functions], "edges": [], "status": "ok"}


def get_functions(binary_path: str) -> list[dict[str, Any]]:
    raw = _r2("aaa; aflj", binary_path)
    return [{"name": f.get("name", ""), "addr": f.get("addr", 0), "size": f.get("size", 0)} for f in _parse_json_list(raw)]


def get_imports(binary_path: str) -> list[dict[str, Any]]:
    raw = _r2("iij", binary_path)
    return [{"name": i.get("name", ""), "plt": i.get("plt", "")} for i in _parse_json_list(raw)]


def is_available() -> bool:
    return os.path.isfile(R2_BIN)
