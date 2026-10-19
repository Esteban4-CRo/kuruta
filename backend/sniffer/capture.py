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
from backend.ips.engine import IPSEngine
from backend.nac.engine import NACEngine
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
    """Thread-safe ring buffer, Scapy sniffer worker, and NAC/IPS defense controller."""

    def __init__(
        self,
        host: HostIdentity | None = None,
        on_packet: OnPacket | None = None,
        ips_engine: IPSEngine | None = None,
        nac_engine: NACEngine | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._host = host or local_host()
        self._on_packet = on_packet
        self._packets: dict[int, StoredPacket] = {}
        self._order: deque[int] = deque()
        self._anomalies: deque[dict[str, Any]] = deque(maxlen=500)
        self._detector = AnomalyDetector(self._host)
        self._ips = ips_engine or IPSEngine()
        self._nac = nac_engine or NACEngine()
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

    def ips(self) -> IPSEngine:
        return self._ips

    def nac(self) -> NACEngine:
        return self._nac

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
            self._nac.clear()
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

            # IPS packet inspection: check if sender/target is under active quarantine
            is_blocked = self._ips.is_blocked(stored.src_ip) or self._ips.is_blocked(stored.dst_ip)
            if is_blocked:
                stored.summary.flagged = True
                stored.summary.info = f"[IPS BLOCKED] {stored.summary.info}"

            # NAC asset profiling and rogue device detection
            nac_alerts = self._nac.observe(stored)

            # Heuristic and signature anomaly detection
            findings = self._detector.observe(stored)

            # Active Defense: IPS threat mitigation on High/Critical findings
            for finding in findings:
                if finding.severity in {"high", "critical"}:
                    self._ips.handle_threat(
                        ip=stored.src_ip,
                        mac=stored.src_mac,
                        reason=finding.title,
                        severity=finding.severity,
                        rule_id=finding.kind,
                    )

            # Active Defense: IPS threat mitigation on Rogue NAC alerts
            for n_alert in nac_alerts:
                if n_alert.severity in {"high", "critical"}:
                    self._ips.handle_threat(
                        ip=n_alert.ip,
                        mac=n_alert.mac,
                        reason=n_alert.title,
                        severity=n_alert.severity,
                        rule_id=n_alert.event_type,
                    )

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

    def import_pcap(self, pcap_bytes: bytes) -> int:
        """Import packets from an uploaded PCAP file."""
        from scapy.utils import rdpcap
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_bytes)
            path = Path(f.name)
        try:
            packets = rdpcap(str(path))
            for pkt in packets:
                self.ingest_packet(pkt)
            return len(packets)
        finally:
            path.unlink(missing_ok=True)

    def simulate_traffic(self) -> list[StoredPacket]:
        """Generate realistic packets, multi-vendor NAC assets, and IPS-actionable attacks."""
        import time
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether
        from scapy.packet import Raw

        generated: list[StoredPacket] = []
        now = time.time()

        # 1. Cisco Gateway Announcement & Baseline (NAC: Authorized Gateway)
        gateway_mac = "00:00:0C:44:55:66"
        p_gw = Ether(src=gateway_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc="192.168.1.1", pdst="192.168.1.254", hwsrc=gateway_mac
        )
        p_gw.time = now
        generated.append(self.ingest_packet(p_gw))

        # 2. Apple MacBook Pro on LAN (NAC: Apple Inc., macOS TTL=64)
        apple_mac = "00:03:93:11:22:33"
        p_apple_dns = Ether(src=apple_mac) / IP(src="192.168.1.15", dst="1.1.1.1", ttl=64) / UDP(sport=54123, dport=53) / DNS(
            id=0x1234, qd=DNSQR(qname="kuruta.local")
        )
        p_apple_dns.time = now + 0.01
        generated.append(self.ingest_packet(p_apple_dns))

        p_apple_resp = Ether(src=gateway_mac) / IP(src="1.1.1.1", dst="192.168.1.15", ttl=56) / UDP(sport=53, dport=54123) / DNS(
            id=0x1234, qr=1, qd=DNSQR(qname="kuruta.local"), an=DNSRR(rrname="kuruta.local", rdata="192.168.1.1")
        )
        p_apple_resp.time = now + 0.02
        generated.append(self.ingest_packet(p_apple_resp))

        # 3. Raspberry Pi HomeLab Server (NAC: Raspberry Pi Trading, Linux TTL=64)
        rpi_mac = "B8:27:EB:77:88:99"
        p_rpi = Ether(src=rpi_mac) / IP(src="192.168.1.50", dst="192.168.1.1", ttl=64) / TCP(sport=22, dport=51234, flags="SA")
        p_rpi.time = now + 0.03
        generated.append(self.ingest_packet(p_rpi))

        # 4. Espressif ESP32 Smart IoT Sensor (NAC: Espressif Inc., MQTT)
        esp_mac = "24:0A:C4:AA:BB:CC"
        p_esp = Ether(src=esp_mac) / IP(src="192.168.1.75", dst="192.168.1.50", ttl=255) / UDP(sport=1883, dport=1883) / Raw(
            load=b'{"sensor":"temp","value":22.4}'
        )
        p_esp.time = now + 0.04
        generated.append(self.ingest_packet(p_esp))

        # 5. Dell Windows 11 Workstation (NAC: Dell Inc., Windows TTL=128, HTTP API)
        dell_mac = "00:14:22:88:99:AA"
        p_dell = Ether(src=dell_mac) / IP(src="192.168.1.110", dst="192.168.1.1", ttl=128) / TCP(sport=51234, dport=80, flags="PA") / Raw(
            load=b"GET /api/status HTTP/1.1\r\nHost: kuruta.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        )
        p_dell.time = now + 0.05
        generated.append(self.ingest_packet(p_dell))

        # 6. Attacker VM (Oracle VirtualBox) - Vertical port scan (IDS: vertical-port-scan, IPS: Host Quarantine)
        attacker_mac = "08:00:27:12:34:56"
        scanner_ip = "192.168.1.88"
        target_ip = "192.168.1.1"
        for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9200, 27017, 5000, 8000, 8081, 8848, 10000]:
            scan_pkt = Ether(src=attacker_mac) / IP(src=scanner_ip, dst=target_ip) / TCP(sport=49152, dport=port, flags="S")
            scan_pkt.time = now + 0.06
            generated.append(self.ingest_packet(scan_pkt))

        # 7. DNS Tunneling query (IDS: dns-tunneling anomaly via Shannon entropy, IPS: Threat Logged)
        p_tunnel = Ether(src="00:16:EA:44:33:22") / IP(src="192.168.1.99", dst="8.8.8.8") / UDP(sport=61234, dport=53) / DNS(
            id=0xABCD, qd=DNSQR(qname="a7f9b2c3d4e5f67890123456789abcdef0.exfil.domain.com")
        )
        p_tunnel.time = now + 0.1
        generated.append(self.ingest_packet(p_tunnel))

        # 8. Invalid TCP flags SYN+FIN (RFC 793 violation / nmap evasion attempt)
        p_synfin = Ether(src=attacker_mac) / IP(src=scanner_ip, dst=target_ip) / TCP(sport=49153, dport=80, flags="SF")
        p_synfin.time = now + 0.15
        generated.append(self.ingest_packet(p_synfin))

        # 9. Rogue Gateway / ARP Poisoning attack (NAC: Rogue Gateway Detected! Critical Alert & IPS Quarantine)
        rogue_gw_mac = "AA:BB:CC:DD:EE:FF"
        p_arp_spoof = Ether(src=rogue_gw_mac) / ARP(
            op=2, psrc="192.168.1.1", hwsrc=rogue_gw_mac
        )
        p_arp_spoof.time = now + 0.2
        generated.append(self.ingest_packet(p_arp_spoof))

        return generated

    def detector(self) -> AnomalyDetector:
        return self._detector

    def set_on_packet(self, callback: OnPacket | None) -> None:
        self._on_packet = callback

    def _fallback_raw_socket_loop(self) -> None:
        """Driverless IP packet capture on Windows using Winsock SIO_RCVALL."""
        from scapy.layers.inet import IP
        local_ip = "127.0.0.1"
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            sock.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    data = sock.recv(65535)
                    if data:
                        pkt = IP(data)
                        self.ingest_packet(pkt)
                except socket.timeout:
                    continue
        finally:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            sock.close()

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
            # Fallback for Windows if Npcap is missing
            if os.name == "nt" and not self._stop.is_set():
                try:
                    self._fallback_raw_socket_loop()
                    return
                except Exception as fallback_err:
                    error_msg = f"{error} (Fallback Winsock: {fallback_err})"
                else:
                    return
            else:
                error_msg = str(error)

            with self._lock:
                self._error = error_msg
                self._running = False
            self._stop.set()
        else:
            with self._lock:
                self._running = False
