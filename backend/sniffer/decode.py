"""Dissect captured frames into Wireshark-like rows, trees, and info lines."""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from backend.sniffer.models import LayerField, PacketSummary, ProtocolLayer, StoredPacket

_TCP_FLAG_NAMES = (
    ("F", "FIN"),
    ("S", "SYN"),
    ("R", "RST"),
    ("P", "PSH"),
    ("A", "ACK"),
    ("U", "URG"),
    ("E", "ECE"),
    ("C", "CWR"),
)


def decode_frame(packet: Packet, number: int, capture_start: float) -> StoredPacket:
    """Turn a Scapy packet into a stored frame with summary and tree."""
    raw = bytes(packet)
    timestamp = float(getattr(packet, "time", capture_start) or capture_start)
    ethernet = packet.getlayer(Ether)
    ip4 = packet.getlayer(IP)
    ip6 = packet.getlayer(IPv6)
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)
    arp = packet.getlayer(ARP)
    dns = packet.getlayer(DNS)
    raw_layer = packet.getlayer(Raw)
    payload = bytes(raw_layer.load) if raw_layer is not None else b""

    src_mac = getattr(ethernet, "src", "") if ethernet is not None else ""
    dst_mac = getattr(ethernet, "dst", "") if ethernet is not None else ""
    src_ip = _ip_src(ip4, ip6, arp, src_mac)
    dst_ip = _ip_dst(ip4, ip6, arp, dst_mac)
    src_port = int(tcp.sport) if tcp is not None else int(udp.sport) if udp is not None else None
    dst_port = int(tcp.dport) if tcp is not None else int(udp.dport) if udp is not None else None
    tcp_flags = str(tcp.flags) if tcp is not None else ""
    protocol, info, dns_qname, http_host = _protocol_and_info(
        packet, ip4, ip6, tcp, udp, icmp, arp, dns, payload, src_port, dst_port
    )
    stream_id = _stream_id(src_ip, dst_ip, src_port, dst_port, protocol)
    summary = PacketSummary(
        no=number,
        timestamp=timestamp,
        rel_time=max(0.0, timestamp - capture_start),
        src=_endpoint(src_ip, src_port),
        dst=_endpoint(dst_ip, dst_port),
        protocol=protocol,
        length=len(raw),
        info=info,
        stream_id=stream_id,
    )
    return StoredPacket(
        summary=summary,
        raw=raw,
        layers=_layers(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ip_version=4 if ip4 is not None else 6 if ip6 is not None else None,
        tcp_flags=tcp_flags,
        dns_qname=dns_qname,
        http_host=http_host,
        payload=payload,
        extra={"http": protocol == "HTTP", "tls": protocol == "TLS"},
    )


def _ip_src(ip4: IP | None, ip6: IPv6 | None, arp: ARP | None, fallback: str) -> str:
    if ip4 is not None:
        return str(ip4.src)
    if ip6 is not None:
        return str(ip6.src)
    if arp is not None:
        return str(arp.psrc)
    return fallback or "?"


def _ip_dst(ip4: IP | None, ip6: IPv6 | None, arp: ARP | None, fallback: str) -> str:
    if ip4 is not None:
        return str(ip4.dst)
    if ip6 is not None:
        return str(ip6.dst)
    if arp is not None:
        return str(arp.pdst)
    return fallback or "?"


def _endpoint(address: str, port: int | None) -> str:
    if port is None:
        return address
    if ":" in address and not address.startswith("["):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def _stream_id(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> str:
    left = (src_ip, src_port or 0)
    right = (dst_ip, dst_port or 0)
    first, second = sorted((left, right), key=lambda item: (item[0], item[1]))
    return f"{protocol}:{first[0]}:{first[1]}-{second[0]}:{second[1]}"


def _extract_tls_sni(payload: bytes) -> str:
    """Extract Server Name Indication (SNI) hostname from TLS ClientHello."""
    try:
        if len(payload) < 45 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
            return ""
        pos = 43
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = int.from_bytes(payload[pos:pos+2], "big")
        pos += 2 + cipher_suites_len
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(payload):
            return ""
        ext_len = int.from_bytes(payload[pos:pos+2], "big")
        pos += 2
        end_ext = min(pos + ext_len, len(payload))
        while pos + 4 <= end_ext:
            ext_type = int.from_bytes(payload[pos:pos+2], "big")
            ext_data_len = int.from_bytes(payload[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0:  # server_name extension
                if pos + 5 <= len(payload):
                    name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                    name_bytes = payload[pos+5:pos+5+name_len]
                    return name_bytes.decode("ascii", "ignore")
            pos += ext_data_len
    except Exception:
        pass
    return ""


def _format_tcp_flags(flags_str: str) -> str:
    labels = [name for letter, name in _TCP_FLAG_NAMES if letter in flags_str]
    return f"[{', '.join(labels)}]" if labels else f"[{flags_str or 'NONE'}]"


def _protocol_and_info(
    packet: Packet,
    ip4: IP | None,
    ip6: IPv6 | None,
    tcp: TCP | None,
    udp: UDP | None,
    icmp: ICMP | None,
    arp: ARP | None,
    dns: DNS | None,
    payload: bytes,
    src_port: int | None,
    dst_port: int | None,
) -> tuple[str, str, str, str]:
    if arp is not None:
        if int(arp.op) == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif int(arp.op) == 2:
            info = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            info = f"ARP op={arp.op} {arp.psrc} -> {arp.pdst}"
        return "ARP", info, "", ""

    # DHCP / BOOTP
    dhcp_layer = packet.getlayer("DHCP")
    bootp_layer = packet.getlayer("BOOTP")
    if dhcp_layer is not None or bootp_layer is not None or (src_port in (67, 68) and dst_port in (67, 68)):
        dhcp_type = "Message"
        if dhcp_layer is not None:
            for opt in getattr(dhcp_layer, "options", []):
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    type_map = {
                        1: "Discover",
                        2: "Offer",
                        3: "Request",
                        4: "Decline",
                        5: "ACK",
                        6: "NAK",
                        7: "Release",
                        8: "Inform",
                    }
                    dhcp_type = type_map.get(opt[1], f"Type {opt[1]}")
                    break
        xid = hex(int(getattr(bootp_layer, "xid", 0))) if bootp_layer is not None else ""
        yiaddr = str(getattr(bootp_layer, "yiaddr", "")) if bootp_layer is not None else ""
        info = f"DHCP {dhcp_type} (xid={xid}" + (f", assigned={yiaddr})" if yiaddr and yiaddr != "0.0.0.0" else ")")
        return "DHCP", info, "", ""

    if dns is not None:
        qname = ""
        if dns.qd is not None:
            question = dns.qd
            if hasattr(question, "qname"):
                qname = _dns_name(getattr(question, "qname"))
            elif isinstance(question, (list, tuple)) and len(question) > 0 and hasattr(question[0], "qname"):
                qname = _dns_name(getattr(question[0], "qname"))
            elif isinstance(question, DNSQR):
                qname = _dns_name(question.qname)
        
        # Check if mDNS / LLMNR
        proto_label = "DNS"
        if src_port == 5353 or dst_port == 5353:
            proto_label = "mDNS"
        elif src_port == 5355 or dst_port == 5355:
            proto_label = "LLMNR"

        if int(dns.qr) == 0:
            info = f"Standard query 0x{int(dns.id):04x} {qname}".strip()
        else:
            answers: list[str] = []
            try:
                records = dns.an if hasattr(dns.an, "__iter__") else ([dns.an] if dns.an is not None else [])
                for record in records:
                    if hasattr(record, "rdata"):
                        answers.append(str(record.rdata))
                    if len(answers) >= 4:
                        break
            except Exception:
                pass
            ans_preview = f" -> {' '.join(answers)}" if answers else ""
            info = f"Standard response 0x{int(dns.id):04x} {qname}{ans_preview}".strip()
        return proto_label, info, qname, ""

    # ICMPv6
    icmp6 = packet.getlayer("ICMPv6EchoRequest") or packet.getlayer("ICMPv6EchoReply") or packet.getlayer("ICMPv6ND_NS") or packet.getlayer("ICMPv6ND_NA")
    if icmp6 is not None:
        return "ICMPv6", icmp6.summary(), "", ""

    if icmp is not None:
        icmp_type_names = {
            0: "Echo (ping) reply",
            3: "Destination unreachable",
            5: "Redirect",
            8: "Echo (ping) request",
            11: "Time-to-live exceeded",
        }
        type_name = icmp_type_names.get(int(icmp.type), f"type={icmp.type} code={icmp.code}")
        return "ICMP", f"{type_name} (code={icmp.code})", "", ""

    if tcp is not None:
        flag_summary = _format_tcp_flags(str(tcp.flags))
        seq = int(getattr(tcp, "seq", 0) or 0)
        window = int(getattr(tcp, "window", 0) or 0)

        # SSH Detection
        if (src_port == 22 or dst_port == 22) and payload.startswith(b"SSH-"):
            banner = payload.split(b"\r\n", 1)[0].decode("ascii", "ignore")
            return "SSH", f"SSH Protocol: {banner}", "", ""

        # HTTP Detection
        http_line, http_host = _http_preview(payload)
        if http_line:
            return "HTTP", f"{http_line} [Host: {http_host}]" if http_host else http_line, "", http_host

        # TLS Detection
        if _looks_like_tls(payload):
            sni = _extract_tls_sni(payload)
            tls_desc = _tls_info(payload, src_port, dst_port)
            if sni:
                tls_desc += f" (SNI: {sni})"
            return "TLS", tls_desc, "", sni

        info = f"{src_port} → {dst_port} {flag_summary} Seq={seq} Win={window} Len={len(payload)}"
        return "TCP", info, "", ""

    if udp is not None:
        # SSDP (Simple Service Discovery Protocol)
        if src_port == 1900 or dst_port == 1900:
            preview = payload.split(b"\r\n", 1)[0].decode("ascii", "ignore")
            if preview:
                return "SSDP", preview[:100], "", ""
            return "SSDP", f"{src_port} → {dst_port} SSDP", "", ""

        # NTP (Network Time Protocol)
        if src_port == 123 or dst_port == 123:
            return "NTP", f"Network Time Protocol ({src_port} → {dst_port})", "", ""

        if _looks_like_tls(payload):
            return "DTLS", f"{src_port} → {dst_port} DTLS", "", ""
        return "UDP", f"{src_port} → {dst_port} Len={len(payload)}", "", ""

    if ip4 is not None:
        return "IPv4", f"{ip4.src} → {ip4.dst} proto={ip4.proto}", "", ""
    if ip6 is not None:
        return "IPv6", f"{ip6.src} → {ip6.dst} nh={ip6.nh}", "", ""
    top = packet.name if packet else "ETH"
    return top.upper(), packet.summary() if packet else "frame", "", ""


def _dns_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").rstrip(".")
    return str(value).rstrip(".")


def _http_preview(payload: bytes) -> tuple[str, str]:
    if not payload:
        return "", ""
    try:
        text = payload.split(b"\r\n\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return "", ""
    first = text.split("\r\n", 1)[0]
    methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ")
    if first.startswith(methods) or first.startswith("HTTP/"):
        host = ""
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return first[:180], host
    return "", ""


def _looks_like_tls(payload: bytes) -> bool:
    return len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03


def _tls_info(payload: bytes, src_port: int | None, dst_port: int | None) -> str:
    content = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "ApplicationData"}
    kind = content.get(payload[0], "Record")
    return f"{src_port} → {dst_port} {kind}"


def _layers(packet: Packet) -> list[ProtocolLayer]:
    layers: list[ProtocolLayer] = []
    current: Packet | None = packet
    while current is not None:
        fields: list[LayerField] = []
        for name in list(getattr(current, "fields_desc", []) or []):
            field_name = getattr(name, "name", None)
            if not field_name:
                continue
            try:
                value = current.getfieldval(field_name)
            except Exception:
                continue
            if value is None:
                continue
            rendered = _render_field(value)
            if rendered == "":
                continue
            fields.append(LayerField(name=field_name, value=rendered))
        layers.append(ProtocolLayer(name=current.name, fields=fields))
        payload = current.payload
        current = payload if isinstance(payload, Packet) and payload.name != "NoPayload" else None
        if current is not None and current.name == "Raw":
            load = bytes(getattr(current, "load", b"") or b"")
            preview = load[:64].hex(" ")
            layers.append(
                ProtocolLayer(
                    name="Data",
                    fields=[
                        LayerField(name="len", value=str(len(load))),
                        LayerField(name="bytes", value=preview),
                    ],
                )
            )
            break
    return layers


def _render_field(value: Any) -> str:
    if isinstance(value, bytes):
        if len(value) > 48:
            return value[:48].hex(" ") + "…"
        try:
            text = value.decode("utf-8")
            if text.isprintable():
                return text
        except UnicodeDecodeError:
            pass
        return value.hex(" ")
    return str(value)
