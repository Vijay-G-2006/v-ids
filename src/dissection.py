"""
V-IDS Dissection Engine
========================
Strips raw packets and extracts structured metadata from Ethernet frames,
IPv4 headers, TCP/UDP/ICMP headers, and payload data.

Returns PacketInfo dataclass instances for type-safe downstream processing
by the analysis and reporting engines.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw, Packet

logger = logging.getLogger("v-ids.dissection")


# ── Structured packet representation ───────────────────────────────────────
@dataclass
class PacketInfo:
    """Structured representation of a dissected network packet."""

    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "UNKNOWN"       # "TCP", "UDP", "ICMP", or "UNKNOWN"
    protocol_num: int = 0           # Raw protocol number (6, 17, 1, etc.)
    tcp_flags: str = ""             # String representation, e.g. "S", "SA", "FA"
    tcp_flags_int: int = 0          # Raw integer flags value
    payload: bytes = field(default_factory=bytes)
    packet_size: int = 0
    is_valid: bool = False          # Set to True only if parsing succeeded


# ── Protocol number → name mapping ─────────────────────────────────────────
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def dissect_packet(packet: Packet) -> Optional[PacketInfo]:
    """
    Dissect a raw Scapy packet into a structured PacketInfo object.

    Extracts:
      - Source/Destination IP addresses
      - Source/Destination ports (TCP/UDP only)
      - Protocol type (TCP, UDP, ICMP)
      - TCP flags (SYN, ACK, FIN, RST, PSH, URG)
      - Raw payload bytes
      - Packet size

    Args:
        packet: A raw Scapy Packet object captured by sniff().

    Returns:
        A PacketInfo dataclass if the packet contains an IP layer,
        or None if the packet is not an IP packet (e.g., ARP, pure L2).
    """
    # We only process IP packets
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    info = PacketInfo(
        timestamp=float(packet.time),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol_num=ip_layer.proto,
        protocol=PROTOCOL_MAP.get(ip_layer.proto, "UNKNOWN"),
        packet_size=len(packet),
        is_valid=True,
    )

    # ── TCP ─────────────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        info.src_port = tcp_layer.sport
        info.dst_port = tcp_layer.dport
        info.tcp_flags = str(tcp_layer.flags)
        try:
            info.tcp_flags_int = int(tcp_layer.flags)
        except (ValueError, TypeError):
            info.tcp_flags_int = 0

    # ── UDP ─────────────────────────────────────────────────────────────
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        info.src_port = udp_layer.sport
        info.dst_port = udp_layer.dport

    # ── ICMP ────────────────────────────────────────────────────────────
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        # Store ICMP type/code in port fields for consistent downstream access
        info.src_port = icmp_layer.type
        info.dst_port = icmp_layer.code

    # ── Payload extraction ──────────────────────────────────────────────
    if packet.haslayer(Raw):
        try:
            info.payload = bytes(packet[Raw].load)
        except Exception:
            info.payload = b""

    logger.debug(
        "Dissected: %s %s:%s -> %s:%s [%s] flags=%s size=%d",
        info.protocol, info.src_ip, info.src_port,
        info.dst_ip, info.dst_port, info.protocol,
        info.tcp_flags, info.packet_size,
    )

    return info


def format_flags(flags_str: str) -> str:
    """
    Convert Scapy's compact flag representation to a human-readable form.

    Example:
        "S"  → "SYN"
        "SA" → "SYN-ACK"
        "FA" → "FIN-ACK"
        "R"  → "RST"

    Args:
        flags_str: Scapy TCP flags string (e.g., "S", "SA", "PA").

    Returns:
        Human-readable flag description.
    """
    flag_names = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    if not flags_str:
        return "NONE"

    parts = [flag_names.get(ch, ch) for ch in flags_str]
    return "-".join(parts)
