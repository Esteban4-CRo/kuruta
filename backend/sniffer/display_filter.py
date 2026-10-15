"""Small display-filter language inspired by Wireshark's most used tokens."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from backend.sniffer.models import StoredPacket

Predicate = Callable[[StoredPacket], bool]

_ATOM = re.compile(
    r"""
    ^(?:
        ip\.addr\s*==\s*(?P<ipaddr>\S+)
        |ip\.src\s*==\s*(?P<ipsrc>\S+)
        |ip\.dst\s*==\s*(?P<ipdst>\S+)
        |tcp\.port\s*==\s*(?P<tcpport>\d+)
        |udp\.port\s*==\s*(?P<udpport>\d+)
        |frame\s+contains\s+(?P<contains>\S+)
        |frame\.len\s*>\s*(?P<len_gt>\d+)
        |frame\.len\s*<\s*(?P<len_lt>\d+)
        |(?P<word>tcp|udp|arp|icmp|icmpv6|dns|mdns|llmnr|ssdp|ntp|ssh|dhcp|bootp|http|tls|ipv4|ipv6|ip|flagged|anomaly)
    )$
    """,
    re.VERBOSE | re.IGNORECASE,
)


def validate_display_filter(expression: str) -> str | None:
    """Return an error message when the expression cannot be parsed."""
    if not expression.strip():
        return None
    try:
        compile_display_filter(expression)
    except ValueError as error:
        return str(error)
    return None


def compile_display_filter(expression: str) -> Predicate:
    """Compile a filter into a predicate over stored packets.

    Supported forms: protocol names, `and` / `or`, `ip.addr ==`, `ip.src ==`,
    `ip.dst ==`, `tcp.port ==`, `udp.port ==`, `frame contains`, `frame.len >|<`.
    """
    text = expression.strip()
    if not text:
        return lambda _packet: True

    groups: list[list[Predicate]] = []
    for or_part in re.split(r"\s+or\s+", text, flags=re.IGNORECASE):
        clauses: list[Predicate] = []
        for and_part in re.split(r"\s+and\s+", or_part.strip(), flags=re.IGNORECASE):
            atom = and_part.strip()
            if not atom:
                raise ValueError("Empty display filter clause")
            clauses.append(_compile_atom(atom))
        groups.append(clauses)

    def predicate(packet: StoredPacket) -> bool:
        return any(all(clause(packet) for clause in group) for group in groups)

    return predicate


def _compile_atom(atom: str) -> Predicate:
    match = _ATOM.match(atom)
    if match is None:
        raise ValueError(f"Unknown display filter token: {atom}")
    if match.group("word"):
        token = match.group("word").lower()
        if token in {"flagged", "anomaly"}:
            return lambda packet: packet.summary.flagged
        return lambda packet, token=token: _matches_protocol(packet, token)
    if match.group("ipaddr"):
        value = _ip(match.group("ipaddr"))
        return lambda packet, value=value: packet.src_ip == value or packet.dst_ip == value
    if match.group("ipsrc"):
        value = _ip(match.group("ipsrc"))
        return lambda packet, value=value: packet.src_ip == value
    if match.group("ipdst"):
        value = _ip(match.group("ipdst"))
        return lambda packet, value=value: packet.dst_ip == value
    if match.group("tcpport"):
        port = int(match.group("tcpport"))
        return lambda packet, port=port: packet.summary.protocol in {"TCP", "HTTP", "TLS", "SSH"} and port in {
            packet.src_port,
            packet.dst_port,
        }
    if match.group("udpport"):
        port = int(match.group("udpport"))
        return lambda packet, port=port: packet.summary.protocol in {"UDP", "DNS", "mDNS", "LLMNR", "SSDP", "NTP", "DHCP"} and port in {
            packet.src_port,
            packet.dst_port,
        }
    if match.group("contains"):
        needle = match.group("contains").strip("\"'").encode("utf-8", "replace")
        return lambda packet, needle=needle: needle in packet.raw
    if match.group("len_gt"):
        size = int(match.group("len_gt"))
        return lambda packet, size=size: packet.summary.length > size
    size = int(match.group("len_lt"))
    return lambda packet, size=size: packet.summary.length < size


def _matches_protocol(packet: StoredPacket, token: str) -> bool:
    protocol = packet.summary.protocol.upper()
    if token == "ip":
        return packet.ip_version in {4, 6}
    if token == "ipv4":
        return packet.ip_version == 4
    if token == "ipv6":
        return packet.ip_version == 6
    if token == "bootp":
        return protocol == "DHCP"
    return protocol == token.upper()


def _ip(text: str) -> str:
    return str(ipaddress.ip_address(text.strip()))
