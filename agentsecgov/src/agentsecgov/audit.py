from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Iterable

from .models import AuditEvent, RedactionFinding


class AuditLogger:
    """In-memory audit logger with optional JSONL persistence.

    This is intentionally simple for course use. Replace with durable storage in production.
    """

    def __init__(self, jsonl_path: str | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._lock = Lock()
        self._jsonl_path = Path(jsonl_path) if jsonl_path else None

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._events.append(event)
            if self._jsonl_path:
                self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
                with self._jsonl_path.open("a", encoding="utf-8") as handle:
                    handle.write(event.model_dump_json() + "\n")
        return event

    def list_events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            if self._jsonl_path and self._jsonl_path.exists():
                self._jsonl_path.unlink()


def redaction_counts(findings: Iterable[RedactionFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.entity_type] = counts.get(finding.entity_type, 0) + finding.count
    return counts


def safe_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, default=str)