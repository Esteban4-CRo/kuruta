"""Data models for Network Access Control (NAC) and asset profiling."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

DeviceTrustStatus = Literal["authorized", "unknown", "rogue", "quarantined"]


@dataclass(slots=True)
class NetworkDevice:
    """One discovered network endpoint profiled by L2/L3 heuristics."""

    mac: str
    vendor: str
    ips: list[str] = field(default_factory=list)
    hostname: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets_count: int = 0
    bytes_count: int = 0
    os_hint: str = "Unknown"
    status: DeviceTrustStatus = "unknown"
    notes: str = ""
    is_gateway: bool = False
    is_dhcp_server: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["current_ip"] = self.ips[-1] if self.ips else ""
        return data


@dataclass(slots=True)
class NACSummary:
    """High-level asset counts for the NAC dashboard."""

    total_devices: int = 0
    authorized: int = 0
    unknown: int = 0
    rogue: int = 0
    quarantined: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(slots=True)
class NACAlert:
    """Event triggered by unauthorized device activity or spoofing."""

    event_type: str
    title: str
    description: str
    mac: str
    ip: str
    severity: Literal["low", "medium", "high", "critical"]
    timestamp: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
