"""Tests for event validation, rule evaluation, persistence, and HTTP endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from backend.api.app import create_app
from backend.ingestion.detection import RuleEngine
from backend.ingestion.schema import EventRecord
from backend.ingestion.store import EventStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_DIRECTORY = PROJECT_ROOT / "rules"


def sample_event(
    event_id: str = "test-event-1",
    platform: str = "linux",
    process_name: str = "nmap",
) -> dict[str, object]:
    """Build a representative valid event envelope for tests."""
    return {
        "schema_version": 1,
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": {
            "id": f"{platform}:test-host",
            "hostname": "test-host",
            "platform": platform,
        },
        "source": "host",
        "event_type": "process.started",
        "severity": "info",
        "data": {"pid": 1234, "name": process_name},
    }


def test_event_schema_rejects_unknown_fields() -> None:
    """Reject unexpected top-level properties instead of silently accepting them."""
    event = sample_event()
    event["unexpected"] = "not allowed"

    with pytest.raises(ValidationError):
        EventRecord.model_validate(event)


def test_event_schema_rejects_timezone_naive_timestamp() -> None:
    """Require explicit timezone information on every event timestamp."""
    event = sample_event()
    event["timestamp"] = "2026-10-14T12:00:00"

    with pytest.raises(ValidationError):
        EventRecord.model_validate(event)


def test_rule_engine_matches_only_the_correct_platform() -> None:
    """A Linux process rule must not trigger for a Windows event."""
    engine = RuleEngine.from_directory(RULES_DIRECTORY)
    linux_event = EventRecord.model_validate(sample_event())
    windows_event = EventRecord.model_validate(
        sample_event(event_id="windows-event", platform="windows", process_name="nmap")
    )

    assert [alert.rule_id for alert in engine.evaluate(linux_event)] == [
        "linux-network-analysis-tool"
    ]
    assert engine.evaluate(windows_event) == []


def test_store_ingestion_is_idempotent(tmp_path: Path) -> None:
    """Persist one event and avoid duplicating it or its alert on retry."""
    store = EventStore(tmp_path / "kuruta.db")
    store.initialize()
    event = EventRecord.model_validate(sample_event())
    alerts = RuleEngine.from_directory(RULES_DIRECTORY).evaluate(event)

    assert store.ingest(event, alerts) is True
    assert store.ingest(event, alerts) is False
    assert len(store.list_events(10)) == 1
    assert len(store.list_alerts(10)) == 1


def test_api_accepts_event_and_reports_duplicate(tmp_path: Path) -> None:
    """Exercise the HTTP validation, persistence, and duplicate response path."""
    app = create_app(tmp_path / "api.db", RULES_DIRECTORY)
    with TestClient(app) as client:
        first = client.post("/api/v1/events", json=sample_event())
        duplicate = client.post("/api/v1/events", json=sample_event())
        alerts = client.get("/api/v1/alerts")

    assert first.status_code == 202
    assert first.json()["alerts_created"] == 1
    assert duplicate.json()["duplicate"] is True
    assert len(alerts.json()) == 1


def test_api_rejects_payload_larger_than_limit(tmp_path: Path) -> None:
    """Reject an oversized HTTP body before attempting event parsing."""
    app = create_app(tmp_path / "large.db", RULES_DIRECTORY)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/events",
            content=json.dumps({"padding": "x" * (65 * 1024)}),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 413


def test_api_serves_manual_and_root(tmp_path: Path) -> None:
    """Verify that root and /manual endpoints return HTML documents."""
    app = create_app(tmp_path / "manual.db", RULES_DIRECTORY)
    with TestClient(app) as client:
        root_res = client.get("/")
        manual_res = client.get("/manual")

    assert root_res.status_code == 200
    assert "text/html" in root_res.headers.get("content-type", "")
    assert manual_res.status_code == 200
    assert "text/html" in manual_res.headers.get("content-type", "")
    assert "Kuruta IDS" in manual_res.text

