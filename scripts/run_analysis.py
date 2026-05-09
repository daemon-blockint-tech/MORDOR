from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.gandalf import GandalfOrchestrator

MORDOR_BANNER = r"""
  ___  __    ___  ___  __
 /\/\ /__\  /___\/__\ /__\
/    // \// //  // \// \/
/\/\// _  \/ \_// _  \ _
\/    \/ \_/\___/\/ \_/\/
"""

MORDOR_TAGLINE = "> \"One does not simply walk into Mordor — and no malware simply hides within it.\""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("mordor")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MORDOR — Malware Orchestration & Reverse engineering Detection Operations Runtime",
    )
    parser.add_argument("binary", type=str, help="Path to the binary to analyze")
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream phase updates in real time",
    )
    parser.add_argument(
        "--tier",
        type=str,
        default="standard",
        choices=["quick", "standard", "deep"],
        help="Analysis depth: quick (tool-only), standard (full), deep (full + extra validation)",
    )

    args = parser.parse_args()

    binary_path = Path(args.binary)

    print(MORDOR_BANNER)
    print(f"  {MORDOR_TAGLINE}")
    print("  SHA256  : computing...")
    print(f"  Binary  : {binary_path}")
    print(f"  Tier    : {args.tier}")
    print()

    if not binary_path.exists():
        logger.error("Binary not found: %s", binary_path)
        sys.exit(1)

    orchestrator = GandalfOrchestrator()

    if args.stream:
        for event in orchestrator.stream(str(binary_path), tier=args.tier):
            phase = event.get("current_phase", "unknown")
            logger.info("Phase: %s", phase)
            if phase == "done":
                logger.info("Analysis complete.")
            elif phase == "error":
                logger.error("Analysis failed: %s", event.get("error", "unknown error"))
    else:
        result = orchestrator.run(str(binary_path), tier=args.tier)
        final_phase = result.get("current_phase", "unknown")
        logger.info("Analysis finished at phase: %s", final_phase)


if __name__ == "__main__":
    main()
