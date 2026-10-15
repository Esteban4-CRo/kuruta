"""Heuristic anomaly signals over a live capture. Findings are reviewable, not verdicts."""

from __future__ import annotations

import math
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from backend.ingestion.schema import EventRecord, HostIdentity, Severity
from backend.sniffer.models import StoredPacket

Kind = Literal[
    "vertical-port-scan",
    "horizontal-port-scan",
    "syn-flood",
    "arp-conflict",
    "suspicious-tcp-flags",
    "icmp-flood",
    "dns-anomaly",
    "volume-spike",
    "dns-tunneling",
    "invalid-tcp-flags",
    "tcp-rst-storm",
    "arp-storm",
]


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (bits per symbol)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


@dataclass(slots=True)
class AnomalyFinding:
    """One debounced network anomaly derived from captured frames."""

    kind: Kind
    title: str
    description: str
    severity: Severity
    event_type: str
    packet_no: int
    data: dict[str, str | int | float | bool | None]


class AnomalyDetector:
    """Sliding-window detectors for scans, floods, ARP conflicts, and DNS outliers."""

    def __init__(self, host: HostIdentity) -> None:
        self._host = host
        self._ports: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self._hosts: dict[tuple[str, int], deque[tuple[float, str]]] = defaultdict(deque)
        self._syns: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._rsts: dict[str, deque[float]] = defaultdict(deque)
        self._icmp: dict[str, deque[float]] = defaultdict(deque)
        self._volume: dict[str, deque[float]] = defaultdict(deque)
        self._arp_requests: dict[str, deque[float]] = defaultdict(deque)
        self._arp_mac: dict[str, str] = {}
        self._last_emit: dict[str, float] = {}
        self._dns_labels: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

    def observe(self, packet: StoredPacket, now: float | None = None) -> list[AnomalyFinding]:
        """Update counters with one frame and return newly raised findings."""
        moment = now if now is not None else time.time()
        findings: list[AnomalyFinding] = []
        src = packet.src_ip
        dst = packet.dst_ip
        protocol = packet.summary.protocol

        if src and src not in {"?", "00:00:00:00:00:00"}:
            volume = self._trim(self._volume[src], moment, 2.0)
            volume.append(moment)
            if len(volume) >= 500:
                findings.extend(
                    self._maybe_emit(
                        key=f"volume:{src}",
                        now=moment,
                        packet=packet,
                        kind="volume-spike",
                        event_type="network.volume_spike",
                        severity="medium",
                        title="Host volume spike",
                        description=f"{src} sent {len(volume)} frames in 2s on the captured interface.",
                        data={"src": src, "packets": len(volume), "kind": "volume-spike"},
                    )
                )

        if protocol in {"TCP", "UDP", "DNS", "HTTP", "TLS"} and packet.dst_port:
            ports = self._trim(self._ports[(src, dst)], moment, 15.0)
            ports.append((moment, int(packet.dst_port)))
            unique_ports = {item[1] for item in ports}
            if len(unique_ports) >= 30:
                findings.extend(
                    self._maybe_emit(
                        key=f"vscan:{src}:{dst}",
                        now=moment,
                        packet=packet,
                        kind="vertical-port-scan",
                        event_type="network.port_scan",
                        severity="high",
                        title="Vertical port scan",
                        description=(
                            f"{src} contacted {len(unique_ports)} destination ports on {dst} within 15s."
                        ),
                        data={
                            "src": src,
                            "dst": dst,
                            "ports": len(unique_ports),
                            "kind": "vertical-port-scan",
                        },
                    )
                )

            if packet.dst_port is not None:
                hosts = self._trim(self._hosts[(src, int(packet.dst_port))], moment, 15.0)
                hosts.append((moment, dst))
                unique_hosts = {item[1] for item in hosts}
                if len(unique_hosts) >= 40:
                    findings.extend(
                        self._maybe_emit(
                            key=f"hscan:{src}:{packet.dst_port}",
                            now=moment,
                            packet=packet,
                            kind="horizontal-port-scan",
                            event_type="network.port_scan",
                            severity="high",
                            title="Horizontal scan",
                            description=(
                                f"{src} contacted {len(unique_hosts)} hosts on port "
                                f"{packet.dst_port} within 15s."
                            ),
                            data={
                                "src": src,
                                "port": int(packet.dst_port),
                                "hosts": len(unique_hosts),
                                "kind": "horizontal-port-scan",
                            },
                        )
                    )

        flags = str(packet.tcp_flags or "").upper()
        if protocol == "TCP" and "S" in flags and "A" not in flags:
            syns = self._trim(self._syns[(src, dst)], moment, 5.0)
            syns.append(moment)
            if len(syns) >= 200:
                findings.extend(
                    self._maybe_emit(
                        key=f"syn:{src}:{dst}",
                        now=moment,
                        packet=packet,
                        kind="syn-flood",
                        event_type="network.syn_flood",
                        severity="high",
                        title="SYN flood pattern",
                        description=f"{src} sent {len(syns)} TCP SYN frames to {dst} in 5s.",
                        data={"src": src, "dst": dst, "syns": len(syns), "kind": "syn-flood"},
                    )
                )

        flag_set = set(flags.replace(" ", ""))
        if protocol == "TCP" and "S" in flag_set and "F" in flag_set:
            findings.extend(
                self._maybe_emit(
                    key=f"synfin:{src}:{dst}",
                    now=moment,
                    packet=packet,
                    kind="invalid-tcp-flags",
                    event_type="network.invalid_tcp_flags",
                    severity="high",
                    title="Invalid TCP flags (SYN+FIN)",
                    description=f"{src} → {dst} sent invalid TCP SYN+FIN combination (RFC 793 violation / evasion scan).",
                    data={"src": src, "dst": dst, "flags": flags, "kind": "invalid-tcp-flags"},
                )
            )

        unusual_flags = protocol == "TCP" and (
            flags in {"", "0"}
            or flag_set == {"F"}
            or ({"F", "P", "U"} <= flag_set and "S" not in flag_set and "A" not in flag_set)
        )
        if unusual_flags:
            findings.extend(
                self._maybe_emit(
                    key=f"flags:{src}:{dst}:{flags}",
                    now=moment,
                    packet=packet,
                    kind="suspicious-tcp-flags",
                    event_type="network.tcp_scan_flags",
                    severity="medium",
                    title="Unusual TCP flags",
                    description=f"{src} → {dst} used TCP flags {flags or 'NULL'}.",
                    data={"src": src, "dst": dst, "flags": flags or "NULL", "kind": "suspicious-tcp-flags"},
                )
            )

        if protocol == "TCP" and "R" in flag_set:
            rsts = self._trim(self._rsts[src], moment, 3.0)
            rsts.append(moment)
            if len(rsts) >= 60:
                findings.extend(
                    self._maybe_emit(
                        key=f"rst:{src}",
                        now=moment,
                        packet=packet,
                        kind="tcp-rst-storm",
                        event_type="network.tcp_rst_storm",
                        severity="medium",
                        title="TCP RST storm",
                        description=f"{src} sent {len(rsts)} TCP RST frames in 3s (potential scan rejection or RST injection).",
                        data={"src": src, "packets": len(rsts), "kind": "tcp-rst-storm"},
                    )
                )

        if protocol == "ICMP":
            icmp = self._trim(self._icmp[src], moment, 3.0)
            icmp.append(moment)
            if len(icmp) >= 100:
                findings.extend(
                    self._maybe_emit(
                        key=f"icmp:{src}",
                        now=moment,
                        packet=packet,
                        kind="icmp-flood",
                        event_type="network.icmp_flood",
                        severity="medium",
                        title="ICMP flood pattern",
                        description=f"{src} sent {len(icmp)} ICMP frames in 3s.",
                        data={"src": src, "packets": len(icmp), "kind": "icmp-flood"},
                    )
                )

        if protocol == "ARP" and packet.src_ip:
            arp_reqs = self._trim(self._arp_requests[packet.src_ip], moment, 3.0)
            arp_reqs.append(moment)
            if len(arp_reqs) >= 60:
                findings.extend(
                    self._maybe_emit(
                        key=f"arpstorm:{packet.src_ip}",
                        now=moment,
                        packet=packet,
                        kind="arp-storm",
                        event_type="network.arp_storm",
                        severity="medium",
                        title="ARP storm / sweep pattern",
                        description=f"{packet.src_ip} sent {len(arp_reqs)} ARP frames in 3s.",
                        data={"src": packet.src_ip, "packets": len(arp_reqs), "kind": "arp-storm"},
                    )
                )

            if packet.src_mac:
                previous = self._arp_mac.get(packet.src_ip)
                if previous and previous.lower() != packet.src_mac.lower():
                    findings.extend(
                        self._maybe_emit(
                            key=f"arp:{packet.src_ip}",
                            now=moment,
                            packet=packet,
                            kind="arp-conflict",
                            event_type="network.arp_conflict",
                            severity="high",
                            title="ARP address conflict",
                            description=(
                                f"IP {packet.src_ip} was advertised by {previous} and {packet.src_mac}."
                            ),
                            data={
                                "ip": packet.src_ip,
                                "mac_previous": previous,
                                "mac_current": packet.src_mac,
                                "kind": "arp-conflict",
                            },
                        )
                    )
                else:
                    self._arp_mac[packet.src_ip] = packet.src_mac

        if protocol in {"DNS", "mDNS"} and packet.dns_qname:
            qname = packet.dns_qname
            
            # Shannon entropy check for DNS tunneling
            for label in qname.split("."):
                if len(label) >= 20:
                    ent = shannon_entropy(label)
                    if ent >= 3.65:
                        findings.extend(
                            self._maybe_emit(
                                key=f"dnstunnel:{src}:{label[:16]}",
                                now=moment,
                                packet=packet,
                                kind="dns-tunneling",
                                event_type="network.dns_tunneling",
                                severity="high",
                                title="Potential DNS Tunneling / Exfiltration",
                                description=(
                                    f"{src} queried high-entropy label '{label[:28]}…' "
                                    f"(entropy={ent:.2f}, length={len(label)})."
                                ),
                                data={
                                    "src": src,
                                    "label": label[:60],
                                    "entropy": round(ent, 2),
                                    "kind": "dns-tunneling",
                                },
                            )
                        )
                        break

            labels = self._trim(self._dns_labels[src], moment, 30.0)
            labels.append((moment, qname))
            unique = {item[1] for item in labels}
            if len(qname) >= 80 or (len(unique) >= 40 and len(qname) >= 40):
                findings.extend(
                    self._maybe_emit(
                        key=f"dns:{src}",
                        now=moment,
                        packet=packet,
                        kind="dns-anomaly",
                        event_type="network.dns_anomaly",
                        severity="medium",
                        title="Unusual DNS query pattern",
                        description=(
                            f"{src} issued long or highly unique DNS names "
                            f"(latest {qname[:80]})."
                        ),
                        data={
                            "src": src,
                            "qname_length": len(qname),
                            "unique_names": len(unique),
                            "kind": "dns-anomaly",
                        },
                    )
                )

        return findings

    def to_event(self, finding: AnomalyFinding) -> EventRecord:
        """Wrap a finding in the versioned event envelope."""
        return EventRecord(
            schema_version=1,
            event_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            host=self._host,
            source="network",
            event_type=finding.event_type,
            severity=finding.severity,
            data=finding.data,
        )

    def _maybe_emit(
        self,
        *,
        key: str,
        now: float,
        packet: StoredPacket,
        kind: Kind,
        event_type: str,
        severity: Severity,
        title: str,
        description: str,
        data: dict[str, str | int | float | bool | None],
        debounce: float = 30.0,
    ) -> list[AnomalyFinding]:
        last = self._last_emit.get(key)
        if last is not None and now - last < debounce:
            return []
        self._last_emit[key] = now
        packet.summary.flagged = True
        return [
            AnomalyFinding(
                kind=kind,
                title=title,
                description=description,
                severity=severity,
                event_type=event_type,
                packet_no=packet.summary.no,
                data=data,
            )
        ]

    def _trim(self, window: deque, now: float, span: float) -> deque:
        while window and _head_time(window[0]) < now - span:
            window.popleft()
        return window


def _head_time(item: object) -> float:
    if isinstance(item, tuple):
        return float(item[0])
    return float(item)
