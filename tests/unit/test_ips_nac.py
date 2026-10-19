"""Unit tests for Network Access Control (NAC) and Intrusion Prevention System (IPS)."""

import time
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from backend.api.app import create_app
from backend.ips.engine import IPSEngine
from backend.ips.models import IPSConfig
from backend.nac.engine import NACEngine
from backend.nac.oui import lookup_vendor, normalize_mac
from backend.sniffer.capture import CaptureEngine
from backend.sniffer.decode import decode_frame


def test_oui_vendor_lookup() -> None:
    assert lookup_vendor("00:03:93:11:22:33") == "Apple Inc."
    assert lookup_vendor("00:00:0C:44:55:66") == "Cisco Systems"
    assert lookup_vendor("B8:27:EB:77:88:99") == "Raspberry Pi Foundation"
    assert lookup_vendor("24:0A:C4:AA:BB:CC") == "Espressif Inc."
    assert lookup_vendor("08:00:27:12:34:56") == "Oracle VirtualBox"
    assert lookup_vendor("00:02:B3:01:02:03") == "Intel Corporation"
    assert normalize_mac("00-03-93-11-22-33") == "00:03:93:11:22:33"


def test_nac_engine_profiling_and_rogue_detection() -> None:
    nac = NACEngine(default_gateway_ip="192.168.1.1")
    now = time.time()

    # Legitimate Gateway ARP
    p_gw = Ether(src="00:00:0C:11:22:33") / ARP(op=2, psrc="192.168.1.1", hwsrc="00:00:0C:11:22:33")
    stored_gw = decode_frame(p_gw, 1, now)
    alerts = nac.observe(stored_gw, now)
    assert len(alerts) >= 1  # Device discovered

    summary = nac.summary()
    assert summary["total_devices"] == 1
    assert summary["authorized"] == 1  # First gateway device auto-authorized

    # Apple Device connection
    p_apple = Ether(src="00:03:93:44:55:66") / IP(src="192.168.1.55", dst="1.1.1.1", ttl=64) / TCP(sport=5000, dport=80)
    stored_apple = decode_frame(p_apple, 2, now)
    nac.observe(stored_apple, now)

    dev_apple = nac.get_device("00:03:93:44:55:66")
    assert dev_apple is not None
    assert dev_apple["vendor"] == "Apple Inc."
    assert "Linux / macOS / Android" in dev_apple["os_hint"]

    # Rogue Gateway ARP Spoof attempt
    p_rogue = Ether(src="AA:BB:CC:DD:EE:FF") / ARP(op=2, psrc="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF")
    stored_rogue = decode_frame(p_rogue, 3, now)
    rogue_alerts = nac.observe(stored_rogue, now)
    assert any(a.event_type == "nac.rogue_gateway" for a in rogue_alerts)

    rogue_dev = nac.get_device("AA:BB:CC:DD:EE:FF")
    assert rogue_dev is not None
    assert rogue_dev["status"] == "rogue"


def test_ips_engine_quarantine_and_whitelist() -> None:
    ips = IPSEngine(IPSConfig(mode="active", auto_block=True, block_duration_sec=300))

    # Cannot block loopback or whitelisted IP
    assert ips.block_ip("127.0.0.1", "Test") is None
    assert not ips.is_blocked("127.0.0.1")

    # Block an attacker
    rec = ips.block_ip("192.168.1.88", reason="SYN Flood", severity="high")
    assert rec is not None
    assert rec.ip == "192.168.1.88"
    assert ips.is_blocked("192.168.1.88")

    # Unblock
    assert ips.unblock_ip("192.168.1.88")
    assert not ips.is_blocked("192.168.1.88")


def test_ips_and_nac_api_endpoints() -> None:
    capture = CaptureEngine()
    app = create_app(capture_engine=capture)
    client = TestClient(app)

    # 1. Check IPS Status
    res = client.get("/api/v1/ips/status")
    assert res.status_code == 200
    assert "mode" in res.json()

    # 2. Block IP via API
    res = client.post("/api/v1/ips/block", json={"ip": "10.0.0.99", "reason": "Test Block"})
    assert res.status_code == 200
    assert res.json()["quarantined"] is True

    # 3. Check Quarantine Table
    res = client.get("/api/v1/ips/quarantine")
    assert res.status_code == 200
    quar = res.json()["quarantine"]
    assert any(q["ip"] == "10.0.0.99" for q in quar)

    # 4. Unblock IP via API
    res = client.post("/api/v1/ips/unblock", json={"ip": "10.0.0.99"})
    assert res.status_code == 200
    assert res.json()["unblocked"] is True

    # 5. Simulate Traffic & Check NAC Discovery
    client.post("/api/v1/sniffer/simulate")
    res = client.get("/api/v1/nac/devices")
    assert res.status_code == 200
    data = res.json()
    assert len(data["devices"]) > 0
    assert data["summary"]["total_devices"] > 0
