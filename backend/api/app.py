"""HTTP endpoints, live sniffer API, and desktop console assets for Kuruta."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.ingestion.detection import RuleEngine
from backend.ingestion.schema import (
    AlertRecord,
    CaptureStartRequest,
    EventRecord,
    HealthRecord,
)
from backend.ingestion.store import EventStore
from backend.sniffer.anomalies import AnomalyFinding
from backend.sniffer.capture import CaptureEngine, list_capture_interfaces
from backend.sniffer.display_filter import validate_display_filter
from backend.sniffer.models import StoredPacket

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


def bundled_frontend_directory() -> Path:
    """Find the desktop console files in source or in a frozen bundle."""
    return Path(getattr(sys, "_MEIPASS", PROJECT_ROOT)) / "frontend"


def bundled_assets_directory() -> Path:
    """Find the project logo and related assets."""
    return Path(getattr(sys, "_MEIPASS", PROJECT_ROOT)) / "assets"


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


class LiveHub:
    """Fan-out captured packet summaries to desktop WebSocket clients."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def add(self, websocket: WebSocket) -> None:
        self._clients.add(websocket)

    def discard(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)

    def publish(self, message: dict[str, Any]) -> None:
        loop = self._loop
        if loop is None:
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(message), loop)

    async def _broadcast(self, message: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for client in list(self._clients):
            try:
                await client.send_json(message)
            except Exception:
                stale.append(client)
        for client in stale:
            self._clients.discard(client)


def create_app(
    database_path: Path | None = None,
    rules_directory: Path | None = None,
    capture_engine: CaptureEngine | None = None,
) -> FastAPI:
    """Create an API instance with injectable local storage, rules, and sniffer."""
    db_path = database_path or Path(
        os.environ.get("KURUTA_DB_PATH", default_data_directory() / "kuruta.db")
    )
    rules_path = rules_directory or Path(
        os.environ.get("KURUTA_RULES_DIR", bundled_rules_directory())
    )
    store = EventStore(db_path)
    rule_engine = RuleEngine.from_directory(rules_path)
    hub = LiveHub()

    def persist_and_publish(packet: StoredPacket, findings: list[AnomalyFinding]) -> None:
        hub.publish({"type": "packet", "packet": packet.summary.to_dict()})
        for finding in findings:
            event = capture.detector().to_event(finding)
            alerts = rule_engine.evaluate(event)
            store.ingest(event, alerts)
            hub.publish(
                {
                    "type": "anomaly",
                    "anomaly": {
                        **asdict(finding),
                        "event_id": event.event_id,
                    },
                }
            )

    capture = capture_engine or CaptureEngine(on_packet=persist_and_publish)
    if capture_engine is not None:
        capture.set_on_packet(persist_and_publish)

    capture.ips().set_on_mitigation(lambda action: hub.publish({"type": "ips_mitigation", "action": action.to_dict()}))
    capture.ips().set_on_quarantine(lambda record: hub.publish({"type": "ips_quarantine", "record": record.to_dict()}))
    capture.nac().set_on_alert(lambda alert: hub.publish({"type": "nac_alert", "alert": alert.to_dict()}))
    capture.nac().set_on_device(lambda device: hub.publish({"type": "nac_device", "device": device}))

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        """Create the SQLite schema before accepting requests."""
        application.state.store.initialize()
        application.state.hub.bind(asyncio.get_running_loop())
        yield
        application.state.capture.stop()

    app = FastAPI(
        title="Kuruta IDS / IPS / NAC",
        version="0.3.5",
        description="Enterprise network security suite: Sniffer, IDS, IPS active defense, and NAC asset control.",
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.rule_engine = rule_engine
    app.state.capture = capture
    app.state.hub = hub
    app.add_middleware(
        RequestBodySizeLimitMiddleware,
        maximum_bytes=MAX_REQUEST_BYTES,
    )

    @app.get("/health", response_model=HealthRecord)
    def health() -> HealthRecord:
        """Report that the HTTP service is responding."""
        return HealthRecord(status="ok", service="kuruta-api")

    @app.get("/api/v1/version")
    def api_version() -> dict[str, str]:
        """Return the running build version."""
        from backend.updater import CURRENT_VERSION
        return {"version": CURRENT_VERSION}

    @app.get("/api/v1/update/check")
    async def update_check() -> dict[str, object]:
        """Check GitHub Releases for a newer version (non-blocking, runs in thread pool)."""
        import asyncio
        from backend.updater import check_for_update
        loop = asyncio.get_running_loop()
        info = await loop.run_in_executor(None, check_for_update)
        return {
            "current": info.current,
            "latest": info.latest,
            "has_update": info.has_update,
            "release_notes": info.release_notes,
            "download_url": info.download_url,
            "tag": info.tag,
        }

    @app.post("/api/v1/update/apply")
    async def update_apply(request: Request) -> dict[str, object]:
        """Download and hot-swap the new binary. The process restarts automatically."""
        import asyncio
        from backend.updater import _download_and_replace
        body = await request.json()
        download_url: str = body.get("download_url", "")
        if not download_url:
            raise HTTPException(status_code=400, detail="Se requiere download_url")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _download_and_replace, download_url)
        return {"status": "restarting"}

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

    @app.get("/api/v1/sniffer/interfaces")
    def sniffer_interfaces() -> dict[str, object]:
        """List local capture interfaces discovered by Scapy/Npcap/libpcap."""
        return {"interfaces": list_capture_interfaces()}

    @app.get("/api/v1/sniffer/status")
    def sniffer_status(request: Request) -> dict[str, object]:
        return request.app.state.capture.status()

    @app.post("/api/v1/sniffer/start")
    def sniffer_start(body: CaptureStartRequest, request: Request) -> dict[str, object]:
        try:
            return request.app.state.capture.start(body.interface, body.bpf, body.promiscuous)
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/sniffer/stop")
    def sniffer_stop(request: Request) -> dict[str, object]:
        return request.app.state.capture.stop()

    @app.post("/api/v1/sniffer/clear")
    def sniffer_clear(request: Request) -> dict[str, object]:
        request.app.state.capture.clear()
        return request.app.state.capture.status()

    @app.get("/api/v1/sniffer/filter")
    def sniffer_filter(q: str = "") -> dict[str, object]:
        error = validate_display_filter(q)
        return {"expression": q, "ok": error is None, "error": error}

    @app.get("/api/v1/sniffer/packets")
    def sniffer_packets(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=5000)] = 500,
        after: Annotated[int, Query(ge=0)] = 0,
        display_filter: str = "",
    ) -> dict[str, object]:
        try:
            return request.app.state.capture.list_packets(limit, after, display_filter)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/api/v1/sniffer/packets/{number}")
    def sniffer_packet(number: int, request: Request) -> dict[str, object]:
        try:
            return request.app.state.capture.get_packet(number)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Packet not in the capture buffer.") from error

    @app.get("/api/v1/sniffer/streams/{stream_id}")
    def sniffer_stream(stream_id: str, request: Request) -> dict[str, object]:
        return request.app.state.capture.follow_stream(stream_id)

    @app.get("/api/v1/sniffer/stats")
    def sniffer_stats(request: Request) -> dict[str, object]:
        return request.app.state.capture.statistics()

    @app.get("/api/v1/sniffer/anomalies")
    def sniffer_anomalies(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, object]:
        return {"anomalies": request.app.state.capture.anomalies(limit)}

    @app.get("/api/v1/sniffer/export.pcap")
    def sniffer_export(request: Request) -> Response:
        payload = request.app.state.capture.export_pcap()
        return Response(
            content=payload,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": "attachment; filename=kuruta-capture.pcap"},
        )

    @app.get("/api/v1/sniffer/export.json")
    def sniffer_export_json(request: Request) -> Response:
        """Export all captured packets as a structured JSON file."""
        import json as _json
        from datetime import datetime as _dt
        data = request.app.state.capture.list_packets(5000, 0, "")
        packets = data.get("packets", [])
        payload = _json.dumps({
            "exported_at": _dt.utcnow().isoformat() + "Z",
            "packet_count": len(packets),
            "packets": packets,
        }, indent=2, default=str).encode("utf-8")
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=kuruta-capture.json"},
        )

    @app.get("/api/v1/sniffer/export.csv")
    def sniffer_export_csv(request: Request) -> Response:
        """Export all captured packets as a UTF-8 CSV file (Excel-compatible)."""
        import io as _io
        import csv as _csv
        data = request.app.state.capture.list_packets(5000, 0, "")
        packets = data.get("packets", [])
        buf = _io.StringIO()
        writer = _csv.writer(buf)
        writer.writerow(["No.", "Time (rel)", "Source", "Destination", "Protocol", "Length", "Info", "Flagged"])
        for p in packets:
            writer.writerow([
                p.get("no", ""),
                p.get("rel_time", ""),
                p.get("src", ""),
                p.get("dst", ""),
                p.get("protocol", ""),
                p.get("length", ""),
                p.get("info", ""),
                "yes" if p.get("flagged") else "no",
            ])
        payload = buf.getvalue().encode("utf-8-sig")  # BOM for Excel
        return Response(
            content=payload,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=kuruta-capture.csv"},
        )

    @app.get("/api/v1/sniffer/export-anomalies.json")
    def sniffer_export_anomalies(request: Request) -> Response:
        """Export all IDS anomaly findings as JSON."""
        import json as _json
        from datetime import datetime as _dt
        anomalies = request.app.state.capture.anomalies(500)
        payload = _json.dumps({
            "exported_at": _dt.utcnow().isoformat() + "Z",
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
        }, indent=2, default=str).encode("utf-8")
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=kuruta-anomalies.json"},
        )

    @app.get("/api/v1/nac/export.json")
    def nac_export_json(request: Request) -> Response:
        """Export NAC device inventory as JSON."""
        import json as _json
        from datetime import datetime as _dt
        nac = request.app.state.capture.nac()
        devices = nac.list_devices()
        summary = nac.summary()
        payload = _json.dumps({
            "exported_at": _dt.utcnow().isoformat() + "Z",
            "summary": summary,
            "devices": devices,
        }, indent=2, default=str).encode("utf-8")
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=kuruta-nac-inventory.json"},
        )

    @app.get("/api/v1/ips/export.json")
    def ips_export_json(request: Request) -> Response:
        """Export IPS quarantine list and mitigation history as JSON."""
        import json as _json
        from datetime import datetime as _dt
        ips = request.app.state.capture.ips()
        payload = _json.dumps({
            "exported_at": _dt.utcnow().isoformat() + "Z",
            "quarantine": ips.list_quarantine(),
            "history": ips.list_history(250),
        }, indent=2, default=str).encode("utf-8")
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=kuruta-ips-report.json"},
        )

    @app.post("/api/v1/sniffer/simulate")
    def sniffer_simulate(request: Request) -> dict[str, object]:
        packets = request.app.state.capture.simulate_traffic()
        return {"simulated": len(packets)}

    @app.post("/api/v1/sniffer/import-pcap")
    async def sniffer_import(request: Request) -> dict[str, object]:
        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="Empty PCAP payload.")
        try:
            count = request.app.state.capture.import_pcap(body)
            return {"imported": count}
        except Exception as error:
            raise HTTPException(status_code=400, detail=f"Failed to parse PCAP: {error}") from error

    @app.websocket("/api/v1/sniffer/live")
    async def sniffer_live(websocket: WebSocket) -> None:
        await websocket.accept()
        websocket.app.state.hub.add(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            websocket.app.state.hub.discard(websocket)

    # -------------------------------------------------------------
    # IPS (Intrusion Prevention System) Endpoints
    # -------------------------------------------------------------
    @app.get("/api/v1/ips/status")
    def ips_status(request: Request) -> dict[str, object]:
        """Return real-time IPS defense status, mode, and counters."""
        return request.app.state.capture.ips().status()

    @app.get("/api/v1/ips/quarantine")
    def ips_quarantine(request: Request) -> dict[str, object]:
        """List active and historical host quarantine records."""
        return {"quarantine": request.app.state.capture.ips().list_quarantine()}

    @app.get("/api/v1/ips/history")
    def ips_history(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=250)] = 50,
    ) -> dict[str, object]:
        """List audit log of defensive mitigation actions taken."""
        return {"history": request.app.state.capture.ips().list_history(limit)}

    @app.post("/api/v1/ips/config")
    async def ips_config(request: Request) -> dict[str, object]:
        """Update IPS defense parameters: mode, auto_block, duration, whitelist."""
        body = await request.json()
        cfg = request.app.state.capture.ips().update_config(
            mode=body.get("mode"),
            auto_block=body.get("auto_block"),
            block_duration_sec=body.get("block_duration_sec"),
            auto_rst_injection=body.get("auto_rst_injection"),
            whitelist=body.get("whitelist"),
        )
        return {"config": cfg}

    @app.post("/api/v1/ips/block")
    async def ips_block(request: Request) -> dict[str, object]:
        """Manually quarantine an IP address via firewall and drop engine."""
        body = await request.json()
        ip = str(body.get("ip", "")).strip()
        reason = str(body.get("reason", "Manual administrative block")).strip()
        duration = body.get("duration_sec")
        if duration is not None:
            try:
                duration = int(duration)
            except (ValueError, TypeError):
                duration = None
        record = request.app.state.capture.ips().block_ip(
            ip=ip,
            reason=reason,
            severity="high",
            duration_sec=duration,
            mac=str(body.get("mac", "")),
        )
        if not record:
            raise HTTPException(status_code=400, detail="Cannot block address (invalid or whitelisted).")
        return {"quarantined": True, "record": record.to_dict()}

    @app.post("/api/v1/ips/unblock")
    async def ips_unblock(request: Request) -> dict[str, object]:
        """Release an IP address from quarantine and delete firewall rules."""
        body = await request.json()
        ip = str(body.get("ip", "")).strip()
        released = request.app.state.capture.ips().unblock_ip(ip)
        return {"unblocked": released, "ip": ip}

    # -------------------------------------------------------------
    # NAC (Network Access Control) Endpoints
    # -------------------------------------------------------------
    @app.get("/api/v1/nac/devices")
    def nac_devices(
        request: Request,
        status: str | None = None,
    ) -> dict[str, object]:
        """List profiled network devices with MAC OUI, OS fingerprint, and trust status."""
        nac = request.app.state.capture.nac()
        return {
            "devices": nac.list_devices(status=status),
            "summary": nac.summary(),
        }

    @app.get("/api/v1/nac/summary")
    def nac_summary(request: Request) -> dict[str, object]:
        """Return asset count distribution (authorized, unknown, rogue, quarantined)."""
        return {"summary": request.app.state.capture.nac().summary()}

    @app.get("/api/v1/nac/alerts")
    def nac_alerts(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, object]:
        """Return rogue device and gateway hijack alerts."""
        return {"alerts": request.app.state.capture.nac().alerts(limit)}

    @app.post("/api/v1/nac/devices/{mac}/authorize")
    def nac_authorize(mac: str, request: Request) -> dict[str, object]:
        """Mark a device as trusted/authorized."""
        dev = request.app.state.capture.nac().authorize(mac)
        if not dev:
            raise HTTPException(status_code=404, detail="Device MAC not found.")
        return {"authorized": True, "device": dev}

    @app.post("/api/v1/nac/devices/{mac}/quarantine")
    def nac_quarantine(mac: str, request: Request) -> dict[str, object]:
        """Isolate a rogue device, marking it quarantined and blocking its IP in IPS."""
        dev = request.app.state.capture.nac().quarantine(mac)
        if not dev:
            raise HTTPException(status_code=404, detail="Device MAC not found.")
        # Also block current IP if present
        if dev.get("current_ip"):
            request.app.state.capture.ips().block_ip(
                ip=dev["current_ip"],
                mac=mac,
                reason=f"NAC Device Quarantine ({dev.get('vendor', 'Unknown')})",
                severity="critical",
            )
        return {"quarantined": True, "device": dev}

    @app.post("/api/v1/nac/devices/{mac}/status")
    async def nac_set_status(mac: str, request: Request) -> dict[str, object]:
        """Set custom trust status for a device."""
        body = await request.json()
        new_status = str(body.get("status", "unknown")).lower()
        if new_status not in {"authorized", "unknown", "rogue", "quarantined"}:
            raise HTTPException(status_code=400, detail="Invalid status.")
        dev = request.app.state.capture.nac().set_status(mac, new_status)  # type: ignore[arg-type]
        if not dev:
            raise HTTPException(status_code=404, detail="Device MAC not found.")
        return {"device": dev}

    @app.post("/api/v1/nac/devices/{mac}/rename")
    async def nac_rename(mac: str, request: Request) -> dict[str, object]:
        """Assign a friendly name or hostname to a device."""
        body = await request.json()
        name = str(body.get("name", "")).strip()
        dev = request.app.state.capture.nac().rename_device(mac, name)
        if not dev:
            raise HTTPException(status_code=404, detail="Device MAC not found.")
        return {"device": dev}

    @app.post("/api/v1/nac/gateway")
    async def nac_set_gateway(request: Request) -> dict[str, object]:
        """Configure legitimate default gateway IP and MAC for spoof detection."""
        body = await request.json()
        ip = str(body.get("ip", "")).strip()
        mac = str(body.get("mac", "")).strip()
        request.app.state.capture.nac().set_gateway(ip, mac)
        return {"gateway_ip": ip, "gateway_mac": mac}

    frontend_dir = bundled_frontend_directory()
    assets_dir = bundled_assets_directory()
    if frontend_dir.is_dir():
        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

        @app.get("/")
        def console() -> FileResponse:
            return FileResponse(frontend_dir / "index.html")

        @app.get("/manual")
        def user_manual() -> FileResponse:
            return FileResponse(frontend_dir / "manual.html")

    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    return app


app = create_app()
