"""Data models for Intrusion Prevention System (IPS) policies and mitigation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

IPSMode = Literal["monitor", "active"]


@dataclass(slots=True)
class QuarantineRecord:
    """An active or historical IP isolation entry in the IPS quarantine table."""

    ip: str
    mac: str = ""
    reason: str = ""
    severity: str = "high"
    blocked_at: float = 0.0
    expires_at: float = 0.0  # 0.0 = permanent until manually unblocked
    blocked_packets: int = 0
    rule_id: str = ""
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MitigationAction:
    """Audit log entry for an active defense action executed by Kuruta IPS."""

    action_type: str
    target_ip: str
    reason: str
    timestamp: float
    success: bool
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IPSConfig:
    """User-configurable IPS defensive sensitivity and behavior."""

    mode: IPSMode = "monitor"  # "monitor" (passive IDS alerts) vs "active" (real-time IPS blocking)
    auto_block: bool = True  # Automatically isolate hosts triggering HIGH/CRITICAL anomalies
    block_duration_sec: int = 600  # Default 10 minutes (0 = permanent)
    auto_rst_injection: bool = True  # Inject TCP RST frames on exploit detection
    whitelist: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "::1", "192.168.1.1", "1.1.1.1", "8.8.8.8"]
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
