from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("mordor.tools.yara")


def _get_rule_files(rules_path: str | list[str]) -> list[Path]:
    if isinstance(rules_path, list):
        return [Path(r) for r in rules_path if Path(r).exists()]
    p = Path(rules_path)
    if p.is_dir():
        return sorted(p.glob("**/*.yar")) + sorted(p.glob("**/*.yara"))
    return [p] if p.exists() else []


def scan_file(binary_path: str, rules_path: str | list[str] | None = None) -> list[dict]:
    try:
        import yara
    except ImportError:
        logger.warning("yara-python not installed, cannot scan with YARA")
        return []

    if rules_path is None:
        rules_path = str(Path(__file__).parent.parent / "rules" / "yara")

    rule_files = _get_rule_files(rules_path)
    if not rule_files:
        logger.warning("No YARA rule files found at %s", rules_path)
        return []

    matches: list[dict] = []
    for rf in rule_files:
        try:
            rules = yara.compile(filepath=str(rf))
            result = rules.match(binary_path)
            for m in result:
                matches.append({
                    "rule": str(m.rule),
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                    "strings": [
                        {"offset": s.offset, "identifier": s.identifier, "data": s.instances[0].hex() if s.instances else ""}
                        for s in m.strings
                    ],
                })
        except yara.Error as e:
            logger.warning("YARA compile/match error for %s: %s", rf, e)

    return matches


def scan_memory(memory_dump: str, rules_path: str | list[str] | None = None) -> list[dict]:
    return scan_file(memory_dump, rules_path)
