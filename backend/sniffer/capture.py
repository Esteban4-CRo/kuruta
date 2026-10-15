"""In-memory packet capture session with interface listing and PCAP export."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from scapy.all import get_if_list, sniff, wrpcap
from scapy.packet import Packet, Raw

from backend.ingestion.schema import HostIdentity
from backend.sniffer.anomalies import AnomalyDetector, AnomalyFinding
from backend.sniffer.decode import decode_frame
from backend.sniffer.display_filter import compile_display_filter, validate_display_filter
from backend.sniffer.models import StoredPacket

MAX_PACKETS = 12_000
MAX_FRAME_BYTES = 65_535
OnPacket = Callable[[StoredPacket, list[AnomalyFinding]], None]


def local_host() -> HostIdentity:
    """Identify the machine that is capturing packets."""
    platform_name = "windows" if os.name == "nt" else "linux"
    hostname = socket.gethostname() or "kuruta-host"
    return HostIdentity(id=f"{platform_name}:{hostname}", hostname=hostname, platform=platform_name)


def list_capture_interfaces() -> list[dict[str, str]]:
    """Return capture devices with a stable id and a human-readable name."""
    interfaces: list[dict[str, str]] = []
    if os.name == "nt":
        try:
            from scapy.arch.windows import get_windows_if_list

            for item in get_windows_if_list():
                name = str(item.get("name") or item.get("guid") or "")
                description = str(item.get("description") or name)
                if not name:
                    continue
                interfaces.append(
                    {
                        "id": name,
                        "name": description,
                        "mac": str(item.get("mac") or ""),
                    }
                )
        except Exception:
            interfaces = []
    if not interfaces:
        for name in get_if_list():
            interfaces.append({"id": name, "name": name, "mac": ""})
    return interfaces


class CaptureEngine:
    """Thread-safe ring buffer plus a Scapy sniffing worker."""

    def __init__(self, host: HostIdentity | None = None, on_packet: OnPacket | None = None) -> None:
        self._lock = threading.RLock()
        self._host = host or local_host()
        self._on_packet = on_packet
        self._packets: dict[int, StoredPacket] = {}
        self._order: deque[int] = deque()
        self._anomalies: deque[dict[str, Any]] = deque(maxlen=500)
        self._detector = AnomalyDetector(self._host)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._interface = ""
        self._bpf = ""
        self._promiscuous = True
        self._error = ""
        self._started_at = 0.0
        self._next_no = 1
        self._dropped = 0
        self._bytes = 0
        self._by_protocol: dict[str, int] = {}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "interface": self._interface,
                "bpf": self._bpf,
                "promiscuous": self._promiscuous,
                "packets": len(self._order),
                "next_no": self._next_no,
                "dropped": self._dropped,
                "bytes": self._bytes,
                "error": self._error,
                "started_at": self._started_at,
            }

    def start(self, interface: str, bpf: str = "", promiscuous: bool = True) -> dict[str, Any]:
        """Start a live capture. Requires local capture privileges and Npcap/libpcap."""
        with self._lock:
            if self._running:
                raise RuntimeError("A capture is already running.")
            self._error = ""
            self._interface = interface
            self._bpf = bpf.strip()
            self._promiscuous = promiscuous
            self._stop.clear()
            self._running = True
            self._started_at = datetime.now(timezone.utc).timestamp()
            self._thread = threading.Thread(target=self._sniff_loop, name="kuruta-sniffer", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and threading.current_thread() is not thread:
            thread.join(timeout=2.5)
        with self._lock:
            self._running = False
            self._thread = None
        return self.status()

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._order.clear()
            self._anomalies.clear()
            self._detector = AnomalyDetector(self._host)
            self._next_no = 1
            self._dropped = 0
            self._bytes = 0
            self._by_protocol = {}

    def ingest_packet(self, packet: Packet) -> StoredPacket:
        """Decode and store a packet. Used by the sniffer thread and by tests."""
        with self._lock:
            original_time = float(getattr(packet, "time", 0.0) or 0.0)
            if not self._started_at:
                self._started_at = original_time or datetime.now(timezone.utc).timestamp()
            raw = bytes(packet)
            if len(raw) > MAX_FRAME_BYTES:
                packet = Raw(load=raw[:MAX_FRAME_BYTES])
                packet.time = original_time
            number = self._next_no
            self._next_no += 1
            stored = decode_frame(packet, number, self._started_at or float(getattr(packet, "time", 0.0)))
            findings = self._detector.observe(stored)
            self._packets[number] = stored
            self._order.append(number)
            self._bytes += stored.summary.length
            self._by_protocol[stored.summary.protocol] = self._by_protocol.get(stored.summary.protocol, 0) + 1
            while len(self._order) > MAX_PACKETS:
                old = self._order.popleft()
                self._packets.pop(old, None)
                self._dropped += 1
            for finding in findings:
                self._anomalies.appendleft(
                    {
                        "kind": finding.kind,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity,
                        "event_type": finding.event_type,
                        "packet_no": finding.packet_no,
                        "data": finding.data,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
        if self._on_packet is not None:
            self._on_packet(stored, findings)
        return stored

    def list_packets(self, limit: int = 200, after: int = 0, display_filter: str = "") -> dict[str, Any]:
        error = validate_display_filter(display_filter)
        if error:
            raise ValueError(error)
        predicate = compile_display_filter(display_filter)
        with self._lock:
            rows = []
            for number in self._order:
                if number <= after:
                    continue
                packet = self._packets[number]
                if not predicate(packet):
                    continue
                rows.append(packet.summary.to_dict())
                if len(rows) >= limit:
                    break
            return {
                "packets": rows,
                "displayed": len(rows),
                "captured": len(self._order),
                "filter_error": None,
            }

    def get_packet(self, number: int) -> dict[str, Any]:
        with self._lock:
            packet = self._packets.get(number)
            if packet is None:
                raise KeyError(number)
            return packet.detail_dict()

    def follow_stream(self, stream_id: str, limit: int = 64) -> dict[str, Any]:
        chunks: list[dict[str, Any]] = []
        text_parts: list[str] = []
        with self._lock:
            for number in self._order:
                packet = self._packets[number]
                if packet.summary.stream_id != stream_id:
                    continue
                payload = packet.payload
                preview = payload.decode("utf-8", "replace") if payload else ""
                chunks.append(
                    {
                        "no": packet.summary.no,
                        "src": packet.summary.src,
                        "dst": packet.summary.dst,
                        "length": len(payload),
                        "payload_text": preview[:4000],
                    }
                )
                if preview:
                    text_parts.append(preview)
                if len(chunks) >= limit:
                    break
        return {"stream_id": stream_id, "segments": chunks, "text": "".join(text_parts)[:100_000]}

    def statistics(self) -> dict[str, Any]:
        with self._lock:
            elapsed = 0.0
            if self._started_at:
                end = datetime.now(timezone.utc).timestamp() if self._running else (
                    self._packets[self._order[-1]].summary.timestamp if self._order else self._started_at
                )
                elapsed = max(0.001, end - self._started_at)
            conversations: dict[str, dict[str, Any]] = {}
            endpoints: dict[str, dict[str, Any]] = {}
            for number in self._order:
                packet = self._packets[number]
                left, right = sorted((packet.src_ip or packet.summary.src, packet.dst_ip or packet.summary.dst))
                key = f"{packet.summary.protocol}:{left}-{right}"
                convo = conversations.setdefault(
                    key,
                    {"protocol": packet.summary.protocol, "a": left, "b": right, "packets": 0, "bytes": 0},
                )
                convo["packets"] += 1
                convo["bytes"] += packet.summary.length
                for address in (packet.src_ip, packet.dst_ip):
                    if not address:
                        continue
                    endpoint = endpoints.setdefault(
                        address, {"address": address, "packets": 0, "bytes": 0}
                    )
                    endpoint["packets"] += 1
                    endpoint["bytes"] += packet.summary.length
            top_convos = sorted(conversations.values(), key=lambda item: item["bytes"], reverse=True)[:30]
            top_endpoints = sorted(endpoints.values(), key=lambda item: item["bytes"], reverse=True)[:30]
            return {
                "captured": len(self._order),
                "bytes": self._bytes,
                "dropped": self._dropped,
                "packets_per_second": round(len(self._order) / elapsed, 2) if self._started_at else 0,
                "protocols": dict(sorted(self._by_protocol.items(), key=lambda item: item[1], reverse=True)),
                "conversations": top_convos,
                "endpoints": top_endpoints,
            }

    def anomalies(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._anomalies)[:limit]

    def export_pcap(self) -> bytes:
        """Serialize the ring buffer as a PCAP file for download."""
        with self._lock:
            frames = [Raw(load=self._packets[number].raw) for number in self._order]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            path = Path(handle.name)
        try:
            wrpcap(str(path), frames)
            return path.read_bytes()
        finally:
            path.unlink(missing_ok=True)

    def detector(self) -> AnomalyDetector:
        return self._detector

    def set_on_packet(self, callback: OnPacket | None) -> None:
        self._on_packet = callback

    def _sniff_loop(self) -> None:
        try:
            while not self._stop.is_set():
                sniff(
                    iface=self._interface or None,
                    filter=self._bpf or None,
                    prn=self.ingest_packet,
                    store=False,
                    timeout=0.4,
                    promisc=self._promiscuous,
                    stop_filter=lambda _frame: self._stop.is_set(),
                )
        except Exception as error:
            with self._lock:
                self._error = str(error)
                self._running = False
            self._stop.set()
        else:
            with self._lock:
                self._running = False
