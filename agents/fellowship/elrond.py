from __future__ import annotations

import logging
from typing import Any

from tools.radare2_mcp import analyze_binary as r2_analyze

logger = logging.getLogger("mordor.agents.elrond")


def cross_validate(ghidra_results: dict) -> dict[str, Any]:
    binary_path = ghidra_results.get("binary_path", "")
    if not binary_path:
        return {
            "agreement_score": 0.0,
            "discrepancies": [],
            "confirmed_functions": [],
            "status": "no_binary",
        }

    r2_result = r2_analyze(binary_path)
    if r2_result.get("status") != "ok":
        return {
            "agreement_score": 0.0,
            "discrepancies": [{"issue": "radare2 analysis failed", "detail": r2_result.get("status", "unknown")}],
            "confirmed_functions": [],
            "status": "r2_failed",
        }

    ghidra_imports = {i.get("name", "").lower() for i in ghidra_results.get("imports", []) if isinstance(i, dict)}
    r2_imports = {i.get("name", "").lower() for i in r2_result.get("imports", [])}

    import_intersection = ghidra_imports & r2_imports
    import_union = ghidra_imports | r2_imports
    import_agreement = len(import_intersection) / max(len(import_union), 1)

    ghidra_only = ghidra_imports - r2_imports
    r2_only = r2_imports - ghidra_imports

    discrepancies = []
    for imp in ghidra_only:
        discrepancies.append({"type": "import", "detail": f"Ghidra only: {imp}", "severity": "low"})
    for imp in r2_only:
        discrepancies.append({"type": "import", "detail": f"radare2 only: {imp}", "severity": "low"})

    confirmed = []
    for imp in import_intersection:
        confirmed.append({"type": "import", "name": imp, "confirmed_by": ["ghidra", "radare2"]})

    ghidra_functions = {f.get("name", "").lower() for f in ghidra_results.get("functions", []) if isinstance(f, dict)}
    r2_functions = {f.get("name", "").lower() for f in r2_result.get("functions", [])}

    confirmed_fns = ghidra_functions & r2_functions
    for fn in confirmed_fns:
        if fn:
            confirmed.append({"type": "function", "name": fn, "confirmed_by": ["ghidra", "radare2"]})

    discrepancies_fns = ghidra_functions ^ r2_functions
    for fn in list(discrepancies_fns)[:20]:
        source = "Ghidra only" if fn in ghidra_functions else "radare2 only"
        discrepancies.append({"type": "function", "detail": f"{source}: {fn}", "severity": "info"})

    agreement_score = min(1.0, import_agreement)

    return {
        "agreement_score": round(agreement_score, 4),
        "import_agreement": round(import_agreement, 4),
        "discrepancies": discrepancies,
        "confirmed_functions": confirmed,
        "ghidra_only_count": len(ghidra_only),
        "r2_only_count": len(r2_only),
        "ghidra_import_count": len(ghidra_imports),
        "r2_import_count": len(r2_imports),
        "confirmed_import_count": len(import_intersection),
        "status": "ok",
    }
