"""Intrusion Prevention System (IPS) defense engine and active mitigation coordinator."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Callable

from backend.ips.firewall import FirewallController
from backend.ips.models import IPSConfig, IPSMode, MitigationAction, QuarantineRecord
from backend.sniffer.models import StoredPacket

LOGGER = logging.getLogger("kuruta.ips.engine")


class IPSEngine:
    """Active defensive coordinator: packet filtering, host quarantine, and firewall drops."""

    def __init__(self, config: IPSConfig | None = None) -> None:
        self._lock = threading.RLock()
        self._config = config or IPSConfig()
        self._firewall = FirewallController()
        self._quarantine: dict[str, QuarantineRecord] = {}
        self._history: deque[MitigationAction] = deque(maxlen=250)
        self._blocked_packets_count = 0
        self._on_mitigation: Callable[[MitigationAction], None] | None = None
        self._on_quarantine: Callable[[QuarantineRecord], None] | None = None

    def set_on_mitigation(self, callback: Callable[[MitigationAction], None] | None) -> None:
        self._on_mitigation = callback

    def set_on_quarantine(self, callback: Callable[[QuarantineRecord], None] | None) -> None:
        self._on_quarantine = callback

    def _notify_mitigation(self, action: MitigationAction) -> None:
        if self._on_mitigation is not None:
            try:
                self._on_mitigation(action)
            except Exception:
                pass

    def _notify_quarantine(self, record: QuarantineRecord) -> None:
        if self._on_quarantine is not None:
            try:
                self._on_quarantine(record)
            except Exception:
                pass

    @property
    def config(self) -> IPSConfig:
        return self._config

    def update_config(
        self,
        mode: IPSMode | None = None,
        auto_block: bool | None = None,
        block_duration_sec: int | None = None,
        auto_rst_injection: bool | None = None,
        whitelist: list[str] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if mode is not None:
                self._config.mode = mode
            if auto_block is not None:
                self._config.auto_block = auto_block
            if block_duration_sec is not None:
                self._config.block_duration_sec = max(0, block_duration_sec)
            if auto_rst_injection is not None:
                self._config.auto_rst_injection = auto_rst_injection
            if whitelist is not None:
                self._config.whitelist = [w.strip() for w in whitelist if w.strip()]
            return self._config.to_dict()

    def is_whitelisted(self, ip: str) -> bool:
        if not ip or ip in {"?", "0.0.0.0", "127.0.0.1", "::1"}:
            return True
        return ip in self._config.whitelist

    def is_blocked(self, ip: str, now: float | None = None) -> bool:
        """Check whether an IP is currently blocked, cleaning up expired entries."""
        if not ip or self.is_whitelisted(ip):
            return False

        moment = now if now is not None else time.time()
        with self._lock:
            record = self._quarantine.get(ip)
            if not record or not record.active:
                return False

            # Check for TTL expiration
            if record.expires_at > 0.0 and moment >= record.expires_at:
                record.active = False
                self._firewall.unblock_ip(ip)
                action = MitigationAction(
                    action_type="quarantine_expired",
                    target_ip=ip,
                    reason="Block duration TTL expired",
                    timestamp=moment,
                    success=True,
                )
                self._history.appendleft(action)
                self._notify_mitigation(action)
                return False

            record.blocked_packets += 1
            self._blocked_packets_count += 1
            return True

    def block_ip(
        self,
        ip: str,
        reason: str,
        severity: str = "high",
        duration_sec: int | None = None,
        rule_id: str = "",
        mac: str = "",
    ) -> QuarantineRecord | None:
        """Isolate an IP address immediately using firewall and in-memory drop tables."""
        clean_ip = ip.strip()
        if not clean_ip or self.is_whitelisted(clean_ip):
            LOGGER.info("Refusing to block whitelisted/invalid IP: %s", clean_ip)
            return None

        duration = self._config.block_duration_sec if duration_sec is None else duration_sec
        moment = time.time()
        expires_at = (moment + duration) if duration > 0 else 0.0

        with self._lock:
            # Execute OS-level firewall block if active mode
            fw_success = False
            details = "In-memory packet drop"
            if self._config.mode == "active":
                fw_success, details = self._firewall.block_ip(clean_ip)

            record = QuarantineRecord(
                ip=clean_ip,
                mac=mac,
                reason=reason,
                severity=severity,
                blocked_at=moment,
                expires_at=expires_at,
                rule_id=rule_id,
                active=True,
            )
            self._quarantine[clean_ip] = record

            action = MitigationAction(
                action_type="host_quarantine",
                target_ip=clean_ip,
                reason=reason,
                timestamp=moment,
                success=True,
                details=details,
            )
            self._history.appendleft(action)
            self._notify_quarantine(record)
            self._notify_mitigation(action)
            LOGGER.warning("IPS QUARANTINE APPLIED -> IP: %s | Reason: %s", clean_ip, reason)
            return record

    def unblock_ip(self, ip: str) -> bool:
        """Release an IP from the quarantine table and remove OS firewall rules."""
        clean_ip = ip.strip()
        moment = time.time()
        with self._lock:
            record = self._quarantine.get(clean_ip)
            if not record or not record.active:
                return False

            record.active = False
            self._firewall.unblock_ip(clean_ip)
            action = MitigationAction(
                action_type="quarantine_removed",
                target_ip=clean_ip,
                reason="Manual administrative unblock",
                timestamp=moment,
                success=True,
            )
            self._history.appendleft(action)
            self._notify_quarantine(record)
            self._notify_mitigation(action)
            return True

    def handle_threat(
        self,
        ip: str,
        mac: str = "",
        reason: str = "",
        severity: str = "high",
        rule_id: str = "",
    ) -> QuarantineRecord | None:
        """Callback from IDS detectors to trigger automatic mitigation if active."""
        if self._config.mode != "active" or not self._config.auto_block:
            return None

        if severity.lower() not in {"high", "critical"}:
            return None

        return self.block_ip(
            ip=ip,
            mac=mac,
            reason=reason,
            severity=severity,
            rule_id=rule_id,
        )

    def inject_tcp_rst(self, packet: StoredPacket) -> bool:
        """Synthesize and inject a TCP RST packet to terminate an offensive connection."""
        if not self._config.auto_rst_injection or self._config.mode != "active":
            return False

        if packet.summary.protocol != "TCP" or not packet.src_port or not packet.dst_port:
            return False

        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import send

            # Construct RST from target back to attacker
            rst_pkt = IP(src=packet.dst_ip, dst=packet.src_ip) / TCP(
                sport=packet.dst_port, dport=packet.src_port, flags="R"
            )
            send(rst_pkt, verbose=False)
            self._history.appendleft(
                MitigationAction(
                    action_type="tcp_rst_injected",
                    target_ip=packet.src_ip,
                    reason=f"TCP connection terminated (Port {packet.dst_port})",
                    timestamp=time.time(),
                    success=True,
                )
            )
            return True
        except Exception as error:
            LOGGER.warning("TCP RST injection failed: %s", error)
            return False

    def list_quarantine(self) -> list[dict[str, Any]]:
        with self._lock:
            now = time.time()
            # Clean expired
            for ip, r in list(self._quarantine.items()):
                if r.active and r.expires_at > 0.0 and now >= r.expires_at:
                    r.active = False
                    self._firewall.unblock_ip(ip)

            records = list(self._quarantine.values())
            records.sort(key=lambda r: r.blocked_at, reverse=True)
            return [r.to_dict() for r in records]

    def list_history(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [h.to_dict() for h in list(self._history)[:limit]]

    def status(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            active_count = sum(
                1 for r in self._quarantine.values() if r.active and (r.expires_at == 0 or r.expires_at > now)
            )
            return {
                "mode": self._config.mode,
                "auto_block": self._config.auto_block,
                "active_quarantined": active_count,
                "total_blocked_packets": self._blocked_packets_count,
                "block_duration_sec": self._config.block_duration_sec,
                "auto_rst_injection": self._config.auto_rst_injection,
                "whitelist": self._config.whitelist,
            }

    def clear(self) -> None:
        with self._lock:
            for ip, r in self._quarantine.items():
                if r.active:
                    self._firewall.unblock_ip(ip)
            self._quarantine.clear()
            self._history.clear()
            self._blocked_packets_count = 0
