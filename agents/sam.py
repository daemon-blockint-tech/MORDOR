from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_case(case_dir: str) -> dict | None:
    path = Path(case_dir) / "metadata.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


def write_artifact(case_dir: str, name: str, data: dict | list | str) -> Path:
    path = Path(case_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2))
    else:
        path.write_text(data)
    return path


def list_artifacts(case_dir: str) -> list[str]:
    base = Path(case_dir)
    if not base.exists():
        return []
    return sorted(f.relative_to(base).as_posix() for f in base.rglob("*") if f.is_file())


def read_artifact(case_dir: str, name: str) -> Any:
    path = Path(case_dir) / name
    if not path.exists():
        return None
    if name.endswith(".json"):
        return json.loads(path.read_text())
    return path.read_text()


def save_state(case_dir: str, state: dict[str, Any]) -> None:
    write_artifact(case_dir, ".pipeline_state.json", state)


def resume_state(case_dir: str) -> dict[str, Any] | None:
    path = Path(case_dir) / ".pipeline_state.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


class CaseMemory:
    def __init__(self, case_dir: str):
        self.case_dir = Path(case_dir)

    def exists(self) -> bool:
        return self.case_dir.exists()

    def write_artifact(self, name: str, data: Any) -> None:
        write_artifact(str(self.case_dir), name, data)

    def read_artifact(self, name: str) -> Any:
        return read_artifact(str(self.case_dir), name)

    def list_artifacts(self) -> list[str]:
        return list_artifacts(str(self.case_dir))

    def resume_state(self) -> dict[str, Any] | None:
        return resume_state(str(self.case_dir))

    def save_state(self, state: dict[str, Any]) -> None:
        save_state(str(self.case_dir), state)
