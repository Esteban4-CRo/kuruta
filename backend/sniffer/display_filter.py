"""Advanced display-filter compiler supporting Wireshark-like boolean logic,
nested parentheses, CIDR subnets, port matching, payload inspection, and TCP flags.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any

from backend.sniffer.models import StoredPacket

Predicate = Callable[[StoredPacket], bool]


# ---------------------------------------------------------------------------
# Lexer & AST
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<LPAREN>\()
        |(?P<RPAREN>\))
        |(?P<AND>&&|\band\b)
        |(?P<OR>\|\||\bor\b)
        |(?P<NOT>!|\bnot\b)
        |(?P<ATOM>
            (?:
                [a-zA-Z0-9_\.]+\s*(?:==|!=|>=|<=|>|<|\bin\b|\bcontains\b)\s*(?:"[^"]*"|'[^']*'|[^()\s]+)
                |[a-zA-Z0-9_\.]+
            )
        )
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def validate_display_filter(expression: str) -> str | None:
    """Return an error message if the expression cannot be parsed, else None."""
    if not expression or not expression.strip():
        return None
    try:
        compile_display_filter(expression)
    except ValueError as error:
        return str(error)
    return None


def compile_display_filter(expression: str) -> Predicate:
    """Compile a filter into an executable predicate over StoredPacket."""
    text = expression.strip()
    if not text:
        return lambda _packet: True

    tokens = _tokenize(text)
    if not tokens:
        return lambda _packet: True

    parser = _Parser(tokens)
    predicate = parser.parse()
    return predicate


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            # Skip stray whitespace or report error
            remaining = text[pos:].strip()
            if not remaining:
                break
            raise ValueError(f"Caracter o token inesperado en filtro: '{remaining[:20]}'")
        for kind in ("LPAREN", "RPAREN", "AND", "OR", "NOT", "ATOM"):
            val = m.group(kind)
            if val is not None:
                tokens.append((kind, val.strip()))
                break
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> tuple[str, str] | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self, expected_kind: str | None = None) -> tuple[str, str]:
        token = self.peek()
        if token is None:
            raise ValueError("Fin inesperado de expresión de filtro")
        if expected_kind and token[0] != expected_kind:
            raise ValueError(f"Se esperaba '{expected_kind}', se obtuvo '{token[1]}'")
        self.pos += 1
        return token

    def parse(self) -> Predicate:
        pred = self.expr()
        if self.pos < len(self.tokens):
            extra = self.tokens[self.pos][1]
            raise ValueError(f"Token adicional inesperado: '{extra}'")
        return pred

    def expr(self) -> Predicate:
        return self.or_expr()

    def or_expr(self) -> Predicate:
        left = self.and_expr()
        while True:
            token = self.peek()
            if token and token[0] == "OR":
                self.consume()
                right = self.and_expr()
                l_pred, r_pred = left, right
                left = lambda p, l=l_pred, r=r_pred: l(p) or r(p)
            else:
                break
        return left

    def and_expr(self) -> Predicate:
        left = self.not_expr()
        while True:
            token = self.peek()
            if token and token[0] == "AND":
                self.consume()
                right = self.not_expr()
                l_pred, r_pred = left, right
                left = lambda p, l=l_pred, r=r_pred: l(p) and r(p)
            else:
                break
        return left

    def not_expr(self) -> Predicate:
        token = self.peek()
        if token and token[0] == "NOT":
            self.consume()
            sub = self.not_expr()
            return lambda p, s=sub: not s(p)
        return self.primary()

    def primary(self) -> Predicate:
        token = self.peek()
        if token is None:
            raise ValueError("Expresión incompleta al final de la consulta")
        if token[0] == "LPAREN":
            self.consume("LPAREN")
            inner = self.expr()
            self.consume("RPAREN")
            return inner
        if token[0] == "ATOM":
            self.consume("ATOM")
            return _compile_atom(token[1])
        raise ValueError(f"Sintaxis inválida en '{token[1]}'")


# ---------------------------------------------------------------------------
# Atom Compilers
# ---------------------------------------------------------------------------

_COMPARISON_RE = re.compile(
    r"""
    ^\s*(?P<field>[a-zA-Z0-9_\.]+)\s*
    (?P<op>==|!=|>=|<=|>|<|\bin\b|\bcontains\b)\s*
    (?P<value>.*)$
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _compile_atom(atom: str) -> Predicate:
    atom = atom.strip()
    m = _COMPARISON_RE.match(atom)
    if m:
        field = m.group("field").lower()
        op = m.group("op").lower()
        val = m.group("value").strip().strip("\"'")
        return _compile_comparison(field, op, val)

    # Bare keyword
    word = atom.lower()
    if word in {"flagged", "anomaly", "alert"}:
        return lambda p: p.summary.flagged
    if word in {
        "tcp", "udp", "arp", "icmp", "icmpv6", "dns", "mdns", "llmnr", "ssdp",
        "ntp", "ssh", "dhcp", "bootp", "http", "tls", "ipv4", "ipv6", "ip",
    }:
        return lambda p, w=word: _matches_protocol(p, w)

    raise ValueError(f"Token de filtro desconocido o malformado: '{atom}'")


def _compile_comparison(field: str, op: str, val: str) -> Predicate:
    # 1. IP Addresses (Exact & CIDR)
    if field in {"ip.addr", "ip.src", "ip.dst"}:
        if op == "in":
            try:
                network = ipaddress.ip_network(val, strict=False)
            except ValueError as e:
                raise ValueError(f"Subred CIDR inválida en '{field} in {val}': {e}") from e
            if field == "ip.src":
                return lambda p, net=network: _ip_in_network(p.src_ip, net)
            if field == "ip.dst":
                return lambda p, net=network: _ip_in_network(p.dst_ip, net)
            return lambda p, net=network: _ip_in_network(p.src_ip, net) or _ip_in_network(p.dst_ip, net)

        if op in {"==", "!="}:
            try:
                canon_ip = str(ipaddress.ip_address(val))
            except ValueError as e:
                raise ValueError(f"Dirección IP inválida '{val}': {e}") from e
            if field == "ip.src":
                return lambda p, ip=canon_ip, equals=(op == "=="): (p.src_ip == ip) if equals else (p.src_ip != ip)
            if field == "ip.dst":
                return lambda p, ip=canon_ip, equals=(op == "=="): (p.dst_ip == ip) if equals else (p.dst_ip != ip)
            return lambda p, ip=canon_ip, equals=(op == "=="): ((p.src_ip == ip or p.dst_ip == ip) if equals else (p.src_ip != ip and p.dst_ip != ip))

    # 2. Port Filters (TCP, UDP, Generic)
    if field in {"tcp.port", "tcp.srcport", "tcp.dstport", "udp.port", "udp.srcport", "udp.dstport", "port"}:
        try:
            port = int(val)
        except ValueError as e:
            raise ValueError(f"Número de puerto inválido en '{field}': '{val}'") from e

        is_tcp = field.startswith("tcp.")
        is_udp = field.startswith("udp.")

        def port_eval(p: StoredPacket) -> bool:
            proto = p.summary.protocol.upper()
            if is_tcp and proto not in {"TCP", "HTTP", "TLS", "SSH"}:
                return False
            if is_udp and proto not in {"UDP", "DNS", "MDNS", "LLMNR", "SSDP", "NTP", "DHCP"}:
                return False

            ports: set[int] = set()
            if "srcport" in field:
                if p.src_port is not None:
                    ports.add(p.src_port)
            elif "dstport" in field:
                if p.dst_port is not None:
                    ports.add(p.dst_port)
            else:
                if p.src_port is not None:
                    ports.add(p.src_port)
                if p.dst_port is not None:
                    ports.add(p.dst_port)

            if op == "==":
                return port in ports
            if op == "!=":
                return port not in ports
            if op == ">":
                return any(pt > port for pt in ports)
            if op == ">=":
                return any(pt >= port for pt in ports)
            if op == "<":
                return any(pt < port for pt in ports)
            if op == "<=":
                return any(pt <= port for pt in ports)
            return False

        return port_eval

    # 3. Frame / Packet Length
    if field in {"frame.len", "length", "len"}:
        try:
            size = int(val)
        except ValueError as e:
            raise ValueError(f"Tamaño de longitud inválido en '{field}': '{val}'") from e

        if op == "==":
            return lambda p, s=size: p.summary.length == s
        if op == "!=":
            return lambda p, s=size: p.summary.length != s
        if op == ">":
            return lambda p, s=size: p.summary.length > s
        if op == ">=":
            return lambda p, s=size: p.summary.length >= s
        if op == "<":
            return lambda p, s=size: p.summary.length < s
        if op == "<=":
            return lambda p, s=size: p.summary.length <= s

    # 4. Content / Payload Search (frame contains, payload contains, data contains)
    if field in {"frame", "payload", "data"} and op == "contains":
        needle = val.encode("utf-8", "replace")
        if field == "payload":
            return lambda p, n=needle: n in p.payload
        return lambda p, n=needle: n in p.raw

    # 5. DNS Question Name
    if field in {"dns.qname", "dns.query"}:
        val_lower = val.lower()
        if op == "==":
            return lambda p, target=val_lower: p.dns_qname.lower() == target
        if op == "!=":
            return lambda p, target=val_lower: p.dns_qname.lower() != target
        if op == "contains":
            return lambda p, target=val_lower: target in p.dns_qname.lower()

    # 6. HTTP Host
    if field in {"http.host", "host"}:
        val_lower = val.lower()
        if op == "==":
            return lambda p, target=val_lower: p.http_host.lower() == target
        if op == "contains":
            return lambda p, target=val_lower: target in p.http_host.lower()

    # 7. TCP Flags
    if field in {"tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.rst", "tcp.flags.psh", "tcp.flags.urg"}:
        flag_char = field.split(".")[-1][0].upper()
        expected = val in {"1", "true", "True"}
        return lambda p, ch=flag_char, exp=expected: (ch in p.tcp_flags) == exp

    if field == "tcp.flags":
        if op == "contains":
            target = val.upper()
            return lambda p, t=target: all(c in p.tcp_flags for c in t)
        if op == "==":
            target = val.upper()
            return lambda p, t=target: p.tcp_flags == t

    # 8. Stream ID
    if field in {"stream.id", "stream_id", "tcp.stream"}:
        if op == "==":
            return lambda p, s=val: p.summary.stream_id == s
        if op == "!=":
            return lambda p, s=val: p.summary.stream_id != s

    # 9. Protocol field
    if field in {"protocol", "proto"}:
        val_upper = val.upper()
        if op == "==":
            return lambda p, u=val_upper: p.summary.protocol.upper() == u
        if op == "!=":
            return lambda p, u=val_upper: p.summary.protocol.upper() != u

    raise ValueError(f"Expresión de filtro no soportada: '{field} {op} {val}'")


def _matches_protocol(packet: StoredPacket, token: str) -> bool:
    token_upper = token.upper()
    if token == "ip":
        return packet.ip_version in {4, 6}
    if token == "ipv4":
        return packet.ip_version == 4
    if token == "ipv6":
        return packet.ip_version == 6
    if token == "bootp":
        token_upper = "DHCP"

    summary_proto = packet.summary.protocol.upper()
    if summary_proto == token_upper:
        return True

    # TCP family
    if token_upper == "TCP":
        if summary_proto in {"TCP", "HTTP", "TLS", "SSH"}:
            return True
        return any(layer.name.upper() == "TCP" for layer in packet.layers)

    # UDP family
    if token_upper == "UDP":
        if summary_proto in {"UDP", "DNS", "MDNS", "LLMNR", "SSDP", "NTP", "DHCP"}:
            return True
        return any(layer.name.upper() == "UDP" for layer in packet.layers)

    return any(layer.name.upper() == token_upper for layer in packet.layers)


def _ip_in_network(ip_str: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr in network
    except ValueError:
        return False
