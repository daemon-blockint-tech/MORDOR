from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx

API_DEFAULT = "http://127.0.0.1:8765"


class MordorClient:
    def __init__(self, base_url: str = API_DEFAULT):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, timeout=300)

    def health(self) -> dict[str, Any]:
        r = self.client.get("/v1/health")
        r.raise_for_status()
        return r.json()

    def analyze(self, binary_path: str, tier: str = "standard") -> dict[str, Any]:
        path = Path(binary_path)
        if not path.exists():
            print(f"Error: binary not found: {binary_path}", file=sys.stderr)
            sys.exit(1)

        with open(binary_path, "rb") as f:
            files = {"file": (path.name, f, "application/octet-stream")}
            data = {"tier": tier}
            r = self.client.post("/v1/analyze", files=files, data=data)
            r.raise_for_status()
            return r.json()

    def analyze_path(self, binary_path: str, tier: str = "standard") -> dict[str, Any]:
        r = self.client.post("/v1/analyze/path", data={"binary_path": binary_path, "tier": tier})
        r.raise_for_status()
        return r.json()

    def get_case(self, case_id: str) -> dict[str, Any]:
        r = self.client.get(f"/v1/cases/{case_id}")
        r.raise_for_status()
        return r.json()

    def list_cases(self) -> list[dict[str, Any]]:
        r = self.client.get("/v1/cases")
        r.raise_for_status()
        return r.json()

    def get_report(self, case_id: str) -> str:
        r = self.client.get(f"/v1/cases/{case_id}/report")
        r.raise_for_status()
        return r.text

    def get_artifact(self, case_id: str, name: str) -> str:
        r = self.client.get(f"/v1/cases/{case_id}/artifacts/{name}")
        r.raise_for_status()
        return r.text

    def list_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        r = self.client.get(f"/v1/cases/{case_id}/artifacts")
        r.raise_for_status()
        return r.json().get("artifacts", [])

    def stream_events(self, case_id: str):
        with self.client.stream("GET", f"/v1/stream/{case_id}") as r:
            for line in r.iter_lines():
                if line.startswith("data: "):
                    yield json.loads(line[6:])
                elif line.startswith("event: "):
                    continue
