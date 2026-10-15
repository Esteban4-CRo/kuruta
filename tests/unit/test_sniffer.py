"""Tests for packet decoding, display filters, anomalies, and sniffer API."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from scapy.layers.l2 import ARP, Ether

from backend.api.app import create_app
from backend.ingestion.schema import HostIdentity
from backend.sniffer.anomalies import AnomalyDetector
from backend.sniffer.capture import CaptureEngine
from backend.sniffer.decode import decode_frame
from backend.sniffer.display_filter import compile_display_filter, validate_display_filter

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_DIRECTORY = PROJECT_ROOT / "rules"
HOST = HostIdentity(id="linux:test-host", hostname="test-host", platform="linux")


def _tcp(dport: int, flags: str = "S", src: str = "10.0.0.8", dst: str = "10.0.0.1") -> object:
    packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src=src, dst=dst) / TCP(
        sport=49152, dport=dport, flags=flags
    )
    packet.time = 1.0
    return packet


def test_decode_tcp_syn_summary() -> None:
    stored = decode_frame(_tcp(80), 1, 0.0)
    assert stored.summary.protocol == "TCP"
    assert stored.src_ip == "10.0.0.8"
    assert stored.dst_port == 80
    assert "SYN" in stored.summary.info
    assert "0000" in stored.detail_dict()["hex"]


def test_display_filter_tcp_and_port() -> None:
    syn = decode_frame(_tcp(80), 1, 0.0)
    dns = Ether() / IP(src="10.0.0.8", dst="1.1.1.1") / UDP(sport=1234, dport=53) / DNS(
        id=1, qd=DNSQR(qname="example.test")
    )
    dns.time = 1.0
    named = decode_frame(dns, 2, 0.0)
    predicate = compile_display_filter("tcp and tcp.port == 80")
    assert predicate(syn) is True
    assert predicate(named) is False
    assert validate_display_filter("not-a-filter") is not None

    # Advanced concatenated queries & parentheses
    pred_or = compile_display_filter("(tcp and tcp.port == 80) or udp")
    assert pred_or(syn) is True
    assert pred_or(named) is True

    # CIDR subnet & NOT operator
    pred_cidr = compile_display_filter("ip.src in 10.0.0.0/24 and not tcp")
    assert pred_cidr(named) is True
    assert pred_cidr(syn) is False

    # DNS qname contains
    pred_dns = compile_display_filter('dns and dns.qname contains "example"')
    assert pred_dns(named) is True
    assert pred_dns(syn) is False

    # TCP flags and length comparisons
    pred_syn_flag = compile_display_filter("tcp.flags.syn == 1 and frame.len >= 54")
    assert pred_syn_flag(syn) is True
    assert pred_syn_flag(named) is False


def test_vertical_port_scan_emits_finding() -> None:
    detector = AnomalyDetector(HOST)
    finding_kinds: list[str] = []
    for port in range(1, 36):
        stored = decode_frame(_tcp(port), port, 0.0)
        findings = detector.observe(stored, now=10.0)
        finding_kinds.extend(item.kind for item in findings)
    assert "vertical-port-scan" in finding_kinds


def test_arp_conflict_emits_finding() -> None:
    detector = AnomalyDetector(HOST)
    first = Ether(src="00:11:22:33:44:55") / ARP(op=2, psrc="192.168.1.10", hwsrc="00:11:22:33:44:55")
    second = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
    first.time = second.time = 1.0
    detector.observe(decode_frame(first, 1, 0.0), now=1.0)
    findings = detector.observe(decode_frame(second, 2, 0.0), now=1.1)
    assert findings and findings[0].kind == "arp-conflict"


def test_unusual_tcp_flags() -> None:
    detector = AnomalyDetector(HOST)
    stored = decode_frame(_tcp(22, flags="FPU"), 1, 0.0)
    findings = detector.observe(stored, now=1.0)
    assert any(item.kind == "suspicious-tcp-flags" for item in findings)


def test_sniffer_api_ingests_packets_without_live_capture(tmp_path: Path) -> None:
    engine = CaptureEngine(host=HOST)
    engine.ingest_packet(_tcp(443, flags="PA"))
    app = create_app(tmp_path / "sniffer.db", RULES_DIRECTORY, capture_engine=engine)
    with TestClient(app) as client:
        listed = client.get("/api/v1/sniffer/packets")
        detail = client.get("/api/v1/sniffer/packets/1")
        stats = client.get("/api/v1/sniffer/stats")
        page = client.get("/")
        logo = client.get("/assets/kuruta-logo.png")
        bad_filter = client.get("/api/v1/sniffer/filter", params={"q": "drop tables"})

    assert listed.status_code == 200
    assert listed.json()["captured"] == 1
    assert detail.json()["protocol"] in {"TCP", "TLS", "HTTP"}
    assert stats.json()["captured"] == 1
    assert page.status_code == 200
    assert b"KURUTA" in page.content
    assert logo.status_code == 200
    assert bad_filter.json()["ok"] is False


def test_icmp_and_http_decode() -> None:
    ping = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=8, code=0)
    ping.time = 1.0
    http = (
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=3333, dport=80, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: kuruta.local\r\n\r\n")
    )
    http.time = 1.0
    assert decode_frame(ping, 1, 0.0).summary.protocol == "ICMP"
    web = decode_frame(http, 2, 0.0)
    assert web.summary.protocol == "HTTP"
    assert "GET /" in web.summary.info


def test_invalid_tcp_syn_fin_anomaly() -> None:
    detector = AnomalyDetector(HOST)
    packet = _tcp(80, flags="SF")
    findings = detector.observe(decode_frame(packet, 1, 0.0), now=1.0)
    assert any(item.kind == "invalid-tcp-flags" for item in findings)


def test_dns_tunneling_entropy_anomaly() -> None:
    detector = AnomalyDetector(HOST)
    # High entropy hex/base64 encoded label in query
    payload_name = "a7f9b2c3d4e5f67890123456789abcdef0.exfil.domain.com"
    dns = Ether() / IP(src="10.0.0.8", dst="1.1.1.1") / UDP(sport=1234, dport=53) / DNS(
        id=1, qd=DNSQR(qname=payload_name)
    )
    dns.time = 1.0
    findings = detector.observe(decode_frame(dns, 1, 0.0), now=1.0)
    assert any(item.kind == "dns-tunneling" for item in findings)


def test_filter_flagged_and_protocols() -> None:
    syn = decode_frame(_tcp(80), 1, 0.0)
    syn.summary.flagged = True
    assert compile_display_filter("flagged")(syn) is True
    assert compile_display_filter("anomaly")(syn) is True
    syn.summary.flagged = False
    assert compile_display_filter("flagged")(syn) is False


def test_simulate_traffic_generates_anomalies() -> None:
    session = CaptureEngine(HOST)
    simulated = session.simulate_traffic()
    assert len(simulated) > 5
    result = session.list_packets()
    assert result["captured"] >= len(simulated)
    # Check that anomalies were flagged
    assert any(pkt["flagged"] for pkt in result["packets"])


def test_import_pcap_roundtrip() -> None:
    session = CaptureEngine(HOST)
    session.ingest_packet(Ether() / IP(src="10.0.0.8", dst="10.0.0.1") / TCP(sport=1234, dport=80, flags="S"))
    pcap_data = session.export_pcap()
    assert isinstance(pcap_data, bytes)
    assert len(pcap_data) > 24

    new_session = CaptureEngine(HOST)
    count = new_session.import_pcap(pcap_data)
    assert count >= 1
    assert new_session.list_packets()["packets"][0]["protocol"] == "TCP"



