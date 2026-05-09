from __future__ import annotations

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.gandalf import GandalfOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("mordor.batch")


def analyze_single(binary_path: str) -> dict:
    logger.info("Analyzing: %s", binary_path)
    orchestrator = GandalfOrchestrator()
    try:
        result = orchestrator.run(binary_path)
        return {
            "binary": binary_path,
            "status": "done",
            "confidence": result.get("confidence_overall", 0),
            "phases": len(result.get("phase_results", [])),
        }
    except Exception as exc:
        logger.error("Failed: %s — %s", binary_path, exc)
        return {"binary": binary_path, "status": "error", "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser(description="MORDOR Batch Malware Analysis")
    parser.add_argument("binaries", nargs="+", help="Paths to binaries to analyze")
    parser.add_argument("--max-workers", type=int, default=2, help="Parallel analyses")
    args = parser.parse_args()

    results = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = {pool.submit(analyze_single, b): b for b in args.binaries}
        for future in as_completed(futures):
            results.append(future.result())

    logger.info("=== Batch Summary ===")
    for r in results:
        status_icon = "\u2705" if r["status"] == "done" else "\u274c"
        logger.info("%s %s: %s", status_icon, r["binary"], r["status"])


if __name__ == "__main__":
    main()
