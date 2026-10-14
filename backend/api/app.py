"""HTTP endpoints for the local Kuruta event collector."""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, AsyncIterator

from fastapi import FastAPI, Query, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.ingestion.detection import RuleEngine
from backend.ingestion.schema import AlertRecord, EventRecord, HealthRecord
from backend.ingestion.store import EventStore

LOGGER = logging.getLogger("kuruta.api")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_REQUEST_BYTES = 64 * 1024


def default_data_directory() -> Path:
    """Return the operating system's per-user application data directory."""
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        if root:
            return Path(root) / "Kuruta"
        return Path.home() / "AppData" / "Local" / "Kuruta"
    root = os.environ.get("XDG_DATA_HOME")
    if root:
        return Path(root) / "kuruta"
    return Path.home() / ".local" / "share" / "kuruta"


def bundled_rules_directory() -> Path:
    """Find rules beside source files or inside a PyInstaller one-file bundle."""
    bundle_root = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
    return bundle_root / "rules"


class RequestBodySizeLimitMiddleware:
    """Buffer only bounded API event bodies, including chunked requests."""

    def __init__(self, app: ASGIApp, maximum_bytes: int) -> None:
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        is_event_post = (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and scope["path"] == "/api/v1/events"
        )
        if not is_event_post:
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        body_size = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            body_size += len(chunk)
            if body_size > self.maximum_bytes:
                response_body = b'{"detail":"Request body exceeds the 64 KiB limit."}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": response_body,
                    }
                )
                return
            chunks.append(chunk)
            more_body = message.get("more_body", False)

        async def receive_buffered() -> Message:
            if chunks:
                chunk = chunks.pop(0)
                return {
                    "type": "http.request",
                    "body": chunk,
                    "more_body": bool(chunks),
                }
            return await receive()

        await self.app(scope, receive_buffered, send)


def create_app(
    database_path: Path | None = None,
    rules_directory: Path | None = None,
) -> FastAPI:
    """Create an API instance with injectable local storage and rule paths."""
    db_path = database_path or Path(
        os.environ.get("KURUTA_DB_PATH", default_data_directory() / "kuruta.db")
    )
    rules_path = rules_directory or Path(
        os.environ.get("KURUTA_RULES_DIR", bundled_rules_directory())
    )
    store = EventStore(db_path)
    rule_engine = RuleEngine.from_directory(rules_path)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        """Create the SQLite schema before accepting requests."""
        application.state.store.initialize()
        yield

    app = FastAPI(
        title="Kuruta IDS",
        version="0.1.0",
        description="Local event ingestion and alert API for Kuruta.",
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.rule_engine = rule_engine
    app.add_middleware(
        RequestBodySizeLimitMiddleware,
        maximum_bytes=MAX_REQUEST_BYTES,
    )

    @app.get("/health", response_model=HealthRecord)
    def health() -> HealthRecord:
        """Report that the HTTP service is responding."""
        return HealthRecord(status="ok", service="kuruta-api")

    @app.post("/api/v1/events", status_code=202)
    def ingest_event(event: EventRecord, request: Request) -> dict[str, object]:
        """Validate, persist, and evaluate one host or network event."""
        alerts = request.app.state.rule_engine.evaluate(event)
        inserted = request.app.state.store.ingest(event, alerts)
        if not inserted:
            return {"accepted": True, "duplicate": True, "alerts_created": 0}
        LOGGER.info(
            "Accepted event %s from host %s; created %s alert(s)",
            event.event_id,
            event.host.id,
            len(alerts),
        )
        return {"accepted": True, "duplicate": False, "alerts_created": len(alerts)}

    @app.get("/api/v1/events", response_model=list[EventRecord])
    def list_events(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[EventRecord]:
        """Return the newest stored events, bounded to 500 records."""
        return request.app.state.store.list_events(limit)

    @app.get("/api/v1/alerts", response_model=list[AlertRecord])
    def list_alerts(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[AlertRecord]:
        """Return the newest rule matches, bounded to 500 records."""
        return request.app.state.store.list_alerts(limit)

    return app


app = create_app()
