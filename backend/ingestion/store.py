"""Small SQLite event store with idempotent event ingestion."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from backend.ingestion.schema import AlertDraft, AlertRecord, EventRecord


class EventStore:
    """Persist event envelopes and rule alerts in a local SQLite database."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        """Create the data directory and tables if they do not already exist."""
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_received_at
                    ON events(received_at DESC);
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL REFERENCES events(event_id),
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(event_id, rule_id)
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                    ON alerts(created_at DESC);
                """
            )

    def ingest(self, event: EventRecord, alerts: list[AlertDraft]) -> bool:
        """Atomically save a new event and its alerts; return false on duplicates."""
        received_at = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO events
                    (event_id, host_id, platform, event_type, received_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.host.id,
                    event.host.platform,
                    event.event_type,
                    received_at,
                    event.model_dump_json(),
                ),
            )
            if cursor.rowcount == 0:
                return False

            for alert in alerts:
                connection.execute(
                    """
                    INSERT INTO alerts
                        (alert_id, event_id, rule_id, title, description, severity, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"{event.event_id}:{alert.rule_id}",
                        event.event_id,
                        alert.rule_id,
                        alert.title,
                        alert.description,
                        alert.severity,
                        received_at,
                    ),
                )
        return True

    def list_events(self, limit: int) -> list[EventRecord]:
        """Return recent event payloads, newest first."""
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT payload FROM events ORDER BY received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [EventRecord.model_validate(json.loads(row["payload"])) for row in rows]

    def list_alerts(self, limit: int) -> list[AlertRecord]:
        """Return recent alerts, newest first."""
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT alert_id, event_id, rule_id, title, description, severity, created_at
                FROM alerts
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            AlertRecord(
                alert_id=row["alert_id"],
                event_id=row["event_id"],
                rule_id=row["rule_id"],
                title=row["title"],
                description=row["description"],
                severity=row["severity"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
