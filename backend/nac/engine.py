"""Network Access Control (NAC) engine for zero-trust asset discovery and rogue device mitigation."""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from typing import Any, Callable

from backend.nac.models import DeviceTrustStatus, NACAlert, NACSummary, NetworkDevice
from backend.nac.oui import lookup_vendor, normalize_mac
from backend.sniffer.models import StoredPacket


class NACEngine:
    """Zero-trust device profiler, asset registry, and rogue device detector."""

    def __init__(self, default_gateway_ip: str = "192.168.1.1", gateway_mac: str = "") -> None:
        self._lock = threading.RLock()
        self._devices: dict[str, NetworkDevice] = {}
        self._alerts: deque[NACAlert] = deque(maxlen=200)
        self._default_gateway_ip = default_gateway_ip
        self._gateway_mac = normalize_mac(gateway_mac) if gateway_mac else ""
        self._ip_to_mac: dict[str, str] = {}
        self._on_alert: Callable[[NACAlert], None] | None = None
        self._on_device: Callable[[dict[str, Any]], None] | None = None

    def set_on_alert(self, callback: Callable[[NACAlert], None] | None) -> None:
        self._on_alert = callback

    def set_on_device(self, callback: Callable[[dict[str, Any]], None] | None) -> None:
        self._on_device = callback

    def _notify_alert(self, alert: NACAlert) -> None:
        if self._on_alert is not None:
            try:
                self._on_alert(alert)
            except Exception:
                pass

    def _notify_device(self, device: NetworkDevice) -> None:
        if self._on_device is not None:
            try:
                self._on_device(device.to_dict())
            except Exception:
                pass

    def set_gateway(self, ip: str, mac: str = "") -> None:
        with self._lock:
            self._default_gateway_ip = ip.strip()
            if mac:
                self._gateway_mac = normalize_mac(mac)

    def observe(self, packet: StoredPacket, now: float | None = None) -> list[NACAlert]:
        """Inspect packet headers to discover, profile, and detect rogue hosts."""
        moment = now if now is not None else time.time()
        new_alerts: list[NACAlert] = []

        src_mac = normalize_mac(packet.src_mac)
        if not src_mac or src_mac in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
            return new_alerts

        # Skip multicast/broadcast source MACs
        try:
            if int(src_mac[:2], 16) & 0x01:
                return new_alerts
        except Exception:
            pass

        src_ip = packet.src_ip.strip() if packet.src_ip and packet.src_ip != "?" else ""

        with self._lock:
            is_new = src_mac not in self._devices
            if is_new:
                vendor = lookup_vendor(src_mac)
                device = NetworkDevice(
                    mac=src_mac,
                    vendor=vendor,
                    ips=[src_ip] if src_ip else [],
                    first_seen=moment,
                    last_seen=moment,
                    packets_count=1,
                    bytes_count=packet.summary.length,
                    status="unknown",
                )
                self._devices[src_mac] = device

                # New device alert
                alert = NACAlert(
                    event_type="nac.device_discovered",
                    title="New Network Device Discovered",
                    description=f"Device {src_mac} ({vendor}) connected with IP {src_ip or 'unassigned'}.",
                    mac=src_mac,
                    ip=src_ip,
                    severity="low",
                    timestamp=moment,
                )
                self._alerts.appendleft(alert)
                new_alerts.append(alert)
            else:
                device = self._devices[src_mac]
                device.last_seen = moment
                device.packets_count += 1
                device.bytes_count += packet.summary.length
                if src_ip and src_ip not in device.ips:
                    device.ips.append(src_ip)

            # Detect OS hints from TTL if IPv4
            for layer in packet.layers:
                if layer.name == "IP":
                    for f in layer.fields:
                        if f.name == "ttl":
                            try:
                                ttl = int(f.value)
                                if ttl <= 64:
                                    device.os_hint = "Linux / macOS / Android"
                                elif ttl <= 128:
                                    device.os_hint = "Windows NT / 10 / 11"
                                else:
                                    device.os_hint = "Network Appliance / BSD / Cisco"
                            except Exception:
                                pass

            # Extract hostname from DHCP/mDNS/LLMNR/DNS
            if not device.hostname:
                hostname = self._extract_hostname(packet)
                if hostname:
                    device.hostname = hostname

            # Gateway Impersonation / Rogue Gateway Detection
            if src_ip and src_ip == self._default_gateway_ip:
                if not self._gateway_mac:
                    # First time seeing the gateway MAC: lock it in
                    self._gateway_mac = src_mac
                    device.is_gateway = True
                    device.status = "authorized"
                elif self._gateway_mac != src_mac:
                    # Rogue Gateway! Different MAC claiming gateway IP
                    device.status = "rogue"
                    alert = NACAlert(
                        event_type="nac.rogue_gateway",
                        title="CRITICAL: Rogue Gateway / ARP Hijack Detected",
                        description=f"Unauthorized device {src_mac} ({device.vendor}) claims gateway IP {src_ip}! Legitimate gateway is {self._gateway_mac}.",
                        mac=src_mac,
                        ip=src_ip,
                        severity="critical",
                        timestamp=moment,
                    )
                    self._alerts.appendleft(alert)
                    new_alerts.append(alert)

            # Track IP-to-MAC mapping consistency
            if src_ip:
                prior_mac = self._ip_to_mac.get(src_ip)
                if prior_mac and prior_mac != src_mac:
                    # IP conflict or MAC spoofing
                    alert = NACAlert(
                        event_type="nac.ip_conflict_spoof",
                        title="IP / MAC Conflict Detected",
                        description=f"IP {src_ip} shifted from {prior_mac} to {src_mac} ({device.vendor}). Possible MAC spoof or duplicate IP.",
                        mac=src_mac,
                        ip=src_ip,
                        severity="high",
                        timestamp=moment,
                    )
                    self._alerts.appendleft(alert)
                    new_alerts.append(alert)
                self._ip_to_mac[src_ip] = src_mac

            # Detect Rogue DHCP Server (UDP 67 -> 68 DHCPOFFER or DHCPACK)
            if packet.src_port == 67 and packet.dst_port == 68:
                if not device.is_dhcp_server and device.status != "authorized":
                    device.status = "rogue"
                    alert = NACAlert(
                        event_type="nac.rogue_dhcp",
                        title="CRITICAL: Rogue DHCP Server Detected",
                        description=f"Unauthorized device {src_mac} ({device.vendor}) is sending DHCP offers on the LAN!",
                        mac=src_mac,
                        ip=src_ip,
                        severity="critical",
                        timestamp=moment,
                    )
                    self._alerts.appendleft(alert)
                    new_alerts.append(alert)

            for a in new_alerts:
                self._notify_alert(a)
            if is_new:
                self._notify_device(device)

        return new_alerts

    def _extract_hostname(self, packet: StoredPacket) -> str:
        """Heuristically retrieve device hostname from packet layers or payloads."""
        info = packet.summary.info
        if "DHCP" in info or packet.summary.protocol == "DHCP":
            # Search payload for hostname option
            match = re.search(r"Host Name: ([^\s,]+)", info)
            if match:
                return match.group(1)
        if "MDNS" in info or packet.summary.protocol == "MDNS":
            match = re.search(r"([a-zA-Z0-9_-]+)\.local", info)
            if match:
                return match.group(1)
        if packet.dns_qname and packet.dns_qname.endswith(".local"):
            return packet.dns_qname.replace(".local", "")
        return ""

    def list_devices(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            devices = list(self._devices.values())
            if status:
                devices = [d for d in devices if d.status == status]
            # Sort by last_seen descending
            devices.sort(key=lambda d: d.last_seen, reverse=True)
            return [d.to_dict() for d in devices]

    def get_device(self, mac: str) -> dict[str, Any] | None:
        norm = normalize_mac(mac)
        with self._lock:
            device = self._devices.get(norm)
            return device.to_dict() if device else None

    def authorize(self, mac: str) -> dict[str, Any] | None:
        norm = normalize_mac(mac)
        with self._lock:
            device = self._devices.get(norm)
            if device:
                device.status = "authorized"
                self._notify_device(device)
                return device.to_dict()
            return None

    def quarantine(self, mac: str) -> dict[str, Any] | None:
        norm = normalize_mac(mac)
        with self._lock:
            device = self._devices.get(norm)
            if device:
                device.status = "quarantined"
                self._notify_device(device)
                return device.to_dict()
            return None

    def set_status(self, mac: str, status: DeviceTrustStatus) -> dict[str, Any] | None:
        norm = normalize_mac(mac)
        with self._lock:
            device = self._devices.get(norm)
            if device:
                device.status = status
                self._notify_device(device)
                return device.to_dict()
            return None

    def rename_device(self, mac: str, name: str) -> dict[str, Any] | None:
        norm = normalize_mac(mac)
        with self._lock:
            device = self._devices.get(norm)
            if device:
                device.hostname = name.strip()
                self._notify_device(device)
                return device.to_dict()
            return None

    def summary(self) -> dict[str, int]:
        with self._lock:
            total = len(self._devices)
            auth = sum(1 for d in self._devices.values() if d.status == "authorized")
            unknown = sum(1 for d in self._devices.values() if d.status == "unknown")
            rogue = sum(1 for d in self._devices.values() if d.status == "rogue")
            quar = sum(1 for d in self._devices.values() if d.status == "quarantined")
            return NACSummary(
                total_devices=total,
                authorized=auth,
                unknown=unknown,
                rogue=rogue,
                quarantined=quar,
            ).to_dict()

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in list(self._alerts)[:limit]]

    def clear(self) -> None:
        with self._lock:
            self._devices.clear()
            self._alerts.clear()
            self._ip_to_mac.clear()
