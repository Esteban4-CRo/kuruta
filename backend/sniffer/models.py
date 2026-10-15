"""Serializable views used by the sniffer API and desktop console."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class LayerField:
    """One decoded protocol field, similar to a Wireshark tree leaf."""

    name: str
    value: str


@dataclass(slots=True)
class ProtocolLayer:
    """One protocol layer in the dissection tree."""

    name: str
    fields: list[LayerField]


@dataclass(slots=True)
class PacketSummary:
    """Compact packet row shown in the capture list."""

    no: int
    timestamp: float
    rel_time: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str
    stream_id: str
    flagged: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the row to JSON-ready primitives."""
        return {
            "no": self.no,
            "timestamp": self.timestamp,
            "rel_time": round(self.rel_time, 6),
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
            "stream_id": self.stream_id,
            "flagged": self.flagged,
        }


@dataclass(slots=True)
class StoredPacket:
    """Full captured frame retained in the in-memory ring buffer."""

    summary: PacketSummary
    raw: bytes
    layers: list[ProtocolLayer]
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: str = ""
    dst_mac: str = ""
    ip_version: int | None = None
    tcp_flags: str = ""
    dns_qname: str = ""
    http_host: str = ""
    payload: bytes = b""
    extra: dict[str, Any] = field(default_factory=dict)

    def detail_dict(self) -> dict[str, Any]:
        """Return dissection plus hex dump for the packet detail panes."""
        return {
            **self.summary.to_dict(),
            "layers": [
                {
                    "name": layer.name,
                    "fields": [{"name": item.name, "value": item.value} for item in layer.fields],
                }
                for layer in self.layers
            ],
            "hex": hexdump(self.raw),
            "stream_id": self.summary.stream_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
        }


def hexdump(data: bytes, width: int = 16) -> str:
    """Render a classic offset / hex / ASCII dump."""
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hex_part:<{width * 3}} {ascii_part}")
    return "\n".join(lines) if lines else ""
