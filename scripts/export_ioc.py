from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.fellowship.bilbo import export_sigma, export_stix2, export_yara


def load_iocs(case_dir: str) -> list[dict]:
    path = Path(case_dir)
    md_path = path / "final_report.md"
    if not md_path.exists():
        print(f"No final_report.md found in {case_dir}")
        return []

    iocs: list[dict] = []
    with open(md_path) as f:
        in_ioc_section = False
        for line in f:
            if line.startswith("## Indicators of Compromise"):
                in_ioc_section = True
                continue
            if in_ioc_section:
                if line.startswith("## "):
                    break
                if line.startswith("- [") and "`" in line:
                    parts = line.split("`")
                    if len(parts) >= 3:
                        iocs.append({
                            "value": parts[1],
                            "type": line.split("[")[1].split("]")[0],
                            "source": "report",
                            "confidence": 100,
                            "tags": [],
                        })
    return iocs


def main() -> None:
    parser = argparse.ArgumentParser(description="MORDOR IOC Export")
    parser.add_argument("case_dir", help="Path to case directory (cases/<sha256>)")
    parser.add_argument("--format", choices=["stix2", "yara", "sigma", "all"], default="all")
    parser.add_argument("--output", "-o", help="Output directory (defaults to case_dir)")
    args = parser.parse_args()

    iocs = load_iocs(args.case_dir)
    if not iocs:
        print(f"No IoCs found in {args.case_dir}")
        sys.exit(1)

    out_dir = Path(args.output or args.case_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("stix2", "all"):
        stix = export_stix2(iocs)
        (out_dir / "ioc_stix2.json").write_text(json.dumps(stix, indent=2))
        print(f"STIX 2.1: {out_dir / 'ioc_stix2.json'} ({len(stix.get('objects', []))} indicators)")

    if args.format in ("yara", "all"):
        yara = export_yara(iocs)
        (out_dir / "ioc_mordor.yar").write_text(yara)
        print(f"YARA: {out_dir / 'ioc_mordor.yar'}")

    if args.format in ("sigma", "all"):
        sigma = export_sigma(iocs)
        (out_dir / "ioc_sigma.yml").write_text(json.dumps(sigma, indent=2))
        print(f"Sigma: {out_dir / 'ioc_sigma.yml'}")


if __name__ == "__main__":
    main()
