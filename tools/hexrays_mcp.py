from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger("mordor.tools.hexrays")

IDA_BIN = os.environ.get("IDA_BIN", "idat64")
SCRIPTS_DIR = Path(__file__).resolve().parent / "hexrays_scripts"


def _find_ida() -> str:
    candidates = [
        IDA_BIN,
        "/Applications/IDA Pro 9.1/idat64",
        "/Applications/IDA Pro 9.0/idat64",
        "/Applications/IDA Professional 9.1/idat64",
        "/Applications/IDA Professional 9.0/idat64",
        "/usr/local/bin/idat64",
        "idat64",
    ]
    for c in candidates:
        proc = subprocess.run(
            ["which", c], capture_output=True, text=True, timeout=5
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    return IDA_BIN


def _run_ida_script(binary_path: str, script_name: str, *args: str) -> str:
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        logger.warning("IDA script not found: %s", script_path)
        return ""
    ida = _find_ida()
    if not os.path.isfile(ida) and not ida == IDA_BIN:
        logger.warning("IDA binary not found at %s", ida)
        return ""
    cmd = [ida, "-A", f"-S{script_path}"]
    cmd.extend(str(a) for a in args)
    cmd.append(binary_path)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return proc.stdout + proc.stderr
    except FileNotFoundError:
        logger.warning("IDA binary not found: %s", ida)
        return ""
    except subprocess.TimeoutExpired:
        logger.error("IDA script timed out: %s", script_name)
        return ""
    except Exception as exc:
        logger.error("IDA script failed: %s", exc)
        return ""


def _parse_function_blocks(raw: str) -> list[dict[str, Any]]:
    blocks = []
    current: dict[str, Any] = {}
    for line in raw.splitlines():
        if line.startswith("FUNCTION:"):
            if current:
                blocks.append(current)
            current = {"name": line[len("FUNCTION:"):].strip(), "pseudocode": [], "ast_lines": []}
        elif line.startswith("AST:"):
            current.setdefault("ast_lines", []).append(line[len("AST:"):].strip())
        elif line.startswith("---"):
            pass
        elif current:
            current.setdefault("pseudocode", []).append(line)
    if current:
        blocks.append(current)
    return blocks


def decompile_function(binary_path: str, function_name: str) -> dict[str, Any]:
    raw = _run_ida_script(binary_path, "decompile_func.py", function_name)
    if not raw:
        return {"function": function_name, "decompiled": "", "status": "unavailable"}
    blocks = _parse_function_blocks(raw)
    pseudocode = None
    ast_lines = None
    for b in blocks:
        if b.get("name") == function_name:
            pseudocode = "\n".join(b.get("pseudocode", []))
            ast_lines = b.get("ast_lines", [])
            break
    if not pseudocode:
        pseudocode = raw
    return {
        "function": function_name,
        "decompiled": pseudocode,
        "ast_lines": ast_lines or [],
        "status": "ok" if pseudocode else "no_output",
    }


def analyze_binary(binary_path: str) -> dict[str, Any]:
    known_sigs = _run_ida_script(binary_path, "signature_scan.py")
    local_decompile = _run_ida_script(binary_path, "decompile_all.py")
    functions = _parse_function_blocks(local_decompile)
    signatures = _parse_signature_results(known_sigs)
    return {
        "functions": functions,
        "signatures": signatures,
        "function_count": len(functions),
        "signature_count": len(signatures),
        "status": "ok" if functions else ("signatures_only" if signatures else "unavailable"),
    }


def _parse_signature_results(raw: str) -> list[dict[str, Any]]:
    results = []
    for line in raw.splitlines():
        m = re.match(r"SIG:\s*(\S+)\s*->\s*(.+)", line)
        if m:
            results.append({"library": m.group(1), "function": m.group(2)})
    return results


def list_functions(binary_path: str) -> list[dict[str, Any]]:
    raw = _run_ida_script(binary_path, "list_funcs.py")
    functions = []
    for line in raw.splitlines():
        m = re.match(r"FUNC:\s*(0x[0-9a-fA-F]+)\s+(\S+)", line)
        if m:
            functions.append({"address": m.group(1), "name": m.group(2)})
    return functions


def is_available() -> bool:
    ida = _find_ida()
    return os.path.isfile(ida)
