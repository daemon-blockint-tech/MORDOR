from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any

from agents.gandalf import GandalfOrchestrator


STATUS_FILE = ".status.json"


class CaseManager:
    def __init__(self, cases_dir: str = "cases"):
        self.cases_dir = Path(cases_dir)
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self._locks: dict[str, Lock] = {}
        self._statuses: dict[str, dict[str, Any]] = {}

    def _status_path(self, case_id: str) -> Path:
        return self.cases_dir / case_id / STATUS_FILE

    def _persist_status(self, case_id: str) -> None:
        if case_id in self._statuses:
            path = self._status_path(case_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self._statuses[case_id], indent=2))

    def _load_status_from_disk(self, case_id: str) -> dict[str, Any] | None:
        path = self._status_path(case_id)
        if path.exists():
            data = json.loads(path.read_text())
            self._statuses[case_id] = data
            self._locks[case_id] = Lock()
            return data
        meta_path = self.cases_dir / case_id / "metadata.json"
        if meta_path.exists():
            data = {
                "case_id": case_id,
                "status": "completed",
                "phase": "done",
                "progress": 100.0,
                "error": None,
                "error_count": 0,
                "confidence": 0.0,
                "phases_completed": [],
            }
            self._statuses[case_id] = data
            self._locks[case_id] = Lock()
            self._persist_status(case_id)
            return data
        return None

    def create_case(self, binary_path: str, tier: str = "standard") -> tuple[str, dict[str, Any]]:
        sha256 = hashlib.sha256(open(binary_path, "rb").read()).hexdigest()
        case_dir = str(self.cases_dir / sha256)
        os.makedirs(case_dir, exist_ok=True)

        initial = {
            "binary_path": binary_path,
            "sha256": sha256,
            "case_dir": case_dir,
            "analysis_tier": tier,
            "current_phase": "fingerprint",
            "error": None,
            "error_count": 0,
            "phase_results": [],
            "hypotheses": [],
            "iocs": [],
            "artifacts": {},
            "confidence_overall": 0.0,
            "confidence_breakdown": {},
            "file_type": None,
            "file_size": os.path.getsize(binary_path),
            "cost_entries": [],
            "cost_summary": {},
        }

        self._statuses[sha256] = {
            "case_id": sha256,
            "status": "queued",
            "phase": "fingerprint",
            "progress": 0.0,
            "error": None,
            "error_count": 0,
            "confidence": 0.0,
            "phases_completed": [],
        }
        self._locks[sha256] = Lock()
        self._persist_status(sha256)

        return sha256, initial

    def update_status(self, case_id: str, **updates: Any) -> None:
        if case_id not in self._statuses:
            self._load_status_from_disk(case_id)
        if case_id in self._statuses:
            with self._locks.get(case_id, Lock()):
                self._statuses[case_id].update(updates)
                self._persist_status(case_id)

    def get_status(self, case_id: str) -> dict[str, Any] | None:
        if case_id in self._statuses:
            return self._statuses[case_id]
        return self._load_status_from_disk(case_id)

    def list_cases(self) -> list[dict[str, Any]]:
        results = []
        for case_dir in sorted(self.cases_dir.iterdir()):
            if case_dir.is_dir():
                case_id = case_dir.name
                if case_id not in self._statuses:
                    self._load_status_from_disk(case_id)
                st = self._statuses.get(case_id, {})
                meta_path = case_dir / "metadata.json"
                meta = {}
                if meta_path.exists():
                    meta = json.loads(meta_path.read_text())
                results.append({
                    "case_id": case_id,
                    "sha256": meta.get("sha256", case_id),
                    "file_type": meta.get("file_type"),
                    "file_size": meta.get("file_size"),
                    "status": st.get("status", "unknown"),
                    "phase": st.get("phase", "done"),
                    "confidence": st.get("confidence", 0),
                })
        return results

    def get_artifact(self, case_id: str, name: str) -> str | None:
        path = self.cases_dir / case_id / name
        if path.exists():
            return path.read_text()
        return None

    def list_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        case_path = self.cases_dir / case_id
        if not case_path.exists():
            return []
        artifacts = []
        for f in sorted(case_path.iterdir()):
            if f.is_file():
                size = f.stat().st_size
                artifacts.append({
                    "name": f.name,
                    "size": size,
                    "type": "json" if f.suffix == ".json" else "md" if f.suffix == ".md" else "txt" if f.suffix == ".txt" else "other",
                })
        return artifacts


def get_case_manager() -> CaseManager:
    return CaseManager()


def get_orchestrator() -> GandalfOrchestrator:
    return GandalfOrchestrator()
