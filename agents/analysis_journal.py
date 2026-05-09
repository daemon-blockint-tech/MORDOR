from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class JournalEntry:
    agent: str
    phase: str
    tier: str
    action: str
    status: str
    duration_ms: float = 0.0
    tool_used: str | None = None
    llm_called: bool = False
    result_summary: str | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class AnalysisJournal:
    def __init__(self, case_dir: str):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.case_dir / "analysis_journal.jsonl"
        self._entries: list[JournalEntry] = []

    def record(
        self,
        agent: str,
        phase: str,
        tier: str,
        action: str,
        status: str,
        duration_ms: float = 0.0,
        tool_used: str | None = None,
        llm_called: bool = False,
        result_summary: str | None = None,
        error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        entry = JournalEntry(
            agent=agent,
            phase=phase,
            tier=tier,
            action=action,
            status=status,
            duration_ms=duration_ms,
            tool_used=tool_used,
            llm_called=llm_called,
            result_summary=result_summary,
            error=error,
            details=details or {},
        )
        self._entries.append(entry)
        with open(self._path, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def timed(
        self,
        agent: str,
        phase: str,
        tier: str,
        action: str,
        tool_used: str | None = None,
        llm_called: bool = False,
        details: dict[str, Any] | None = None,
    ):
        start = time.monotonic()
        return _JournalTimedContext(self, agent, phase, tier, action, tool_used, llm_called, details, start)

    def entries(self) -> list[JournalEntry]:
        return list(self._entries)

    def summary(self) -> dict[str, Any]:
        all_entries = self.load_all()
        return self._build_summary(all_entries)

    def load_all(self) -> list[JournalEntry]:
        if not self._path.exists():
            return []
        entries = []
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(JournalEntry(**data))
                except (json.JSONDecodeError, TypeError):
                    continue
        return entries

    @staticmethod
    def _build_summary(entries: list[JournalEntry]) -> dict[str, Any]:
        total = len(entries)
        by_status: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        llm_count = 0
        tool_count = 0
        for e in entries:
            by_status[e.status] = by_status.get(e.status, 0) + 1
            by_agent[e.agent] = by_agent.get(e.agent, 0) + 1
            if e.llm_called:
                llm_count += 1
            if e.tool_used:
                tool_count += 1
        return {
            "total_entries": total,
            "by_status": by_status,
            "by_agent": by_agent,
            "llm_calls": llm_count,
            "tool_calls": tool_count,
        }


class _JournalTimedContext:
    def __init__(self, journal, agent, phase, tier, action, tool_used, llm_called, details, start):
        self.journal = journal
        self.agent = agent
        self.phase = phase
        self.tier = tier
        self.action = action
        self.tool_used = tool_used
        self.llm_called = llm_called
        self.details = details or {}
        self.start = start

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (time.monotonic() - self.start) * 1000
        self.journal.record(
            agent=self.agent,
            phase=self.phase,
            tier=self.tier,
            action=self.action,
            status="error" if exc_type else "ok",
            duration_ms=round(duration, 1),
            tool_used=self.tool_used,
            llm_called=self.llm_called,
            error=str(exc_val) if exc_val else None,
            details=self.details,
        )
