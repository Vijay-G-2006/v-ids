"""
Unit tests for the V-IDS Dissection Engine.
Tests packet parsing for TCP, UDP, ICMP, and edge cases.
"""

import pytest
from unittest.mock import MagicMock
from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

from src.dissection import dissect_packet, format_flags, PacketInfo


# ── Helper: create mock Scapy packets ──────────────────────────────────────

def _make_mock_packet(
    src_ip="192.168.1.100", dst_ip="10.0.0.1",
    proto=6, sport=12345, dport=80,
    tcp_flags="S", payload=None,
    has_ip=True, has_tcp=True, has_udp=False, has_icmp=False,
    icmp_type=None, icmp_code=None,
    pkt_time=1000000.0, pkt_len=100,
):
    """Build a mock Scapy Packet object for testing."""
    packet = MagicMock()
    packet.time = pkt_time
    packet.__len__ = MagicMock(return_value=pkt_len)

    if has_ip:
        ip_layer = MagicMock()
        ip_layer.src = src_ip
        ip_layer.dst = dst_ip
        ip_layer.proto = proto

        tcp_mock = MagicMock()
        tcp_mock.sport = sport
        tcp_mock.dport = dport
        tcp_mock.flags = tcp_flags

        udp_mock = MagicMock()
        udp_mock.sport = sport
        udp_mock.dport = dport

        icmp_mock = MagicMock()
        icmp_mock.type = icmp_type or 8
        icmp_mock.code = icmp_code or 0

        raw_mock = MagicMock()
        raw_mock.load = payload

        # Map Scapy layer classes to their mock instances and availability
        layer_map = {
            IP: (True, ip_layer),
            TCP: (has_tcp, tcp_mock),
            UDP: (has_udp, udp_mock),
            ICMP: (has_icmp, icmp_mock),
            Raw: (payload is not None, raw_mock),
        }

        def haslayer(layer):
            entry = layer_map.get(layer)
            return entry[0] if entry else False

        def getitem(layer):
            entry = layer_map.get(layer)
            return entry[1] if entry else MagicMock()

        packet.haslayer = haslayer
        packet.__getitem__ = MagicMock(side_effect=getitem)
    else:
        packet.haslayer = lambda layer: False

    return packet


# ── Tests ──────────────────────────────────────────────────────────────────

class TestDissectPacket:
    """Tests for the dissect_packet function."""

    def test_tcp_syn_packet(self):
        """Dissects a TCP SYN packet correctly."""
        pkt = _make_mock_packet(
            src_ip="10.0.0.5", dst_ip="10.0.0.1",
            sport=54321, dport=443, tcp_flags="S",
            proto=6, has_tcp=True,
        )
        info = dissect_packet(pkt)
        assert info is not None
        assert info.src_ip == "10.0.0.5"
        assert info.dst_ip == "10.0.0.1"
        assert info.src_port == 54321
        assert info.dst_port == 443
        assert info.protocol == "TCP"
        assert "S" in info.tcp_flags

    def test_udp_packet(self):
        """Dissects a UDP packet correctly."""
        pkt = _make_mock_packet(
            src_ip="172.16.0.50", dst_ip="8.8.8.8",
            sport=5000, dport=53,
            proto=17, has_tcp=False, has_udp=True,
        )
        info = dissect_packet(pkt)
        assert info is not None
        assert info.protocol == "UDP"
        assert info.src_port == 5000
        assert info.dst_port == 53
        assert info.tcp_flags == ""

    def test_icmp_packet(self):
        """Dissects an ICMP packet correctly."""
        pkt = _make_mock_packet(
            proto=1, has_tcp=False, has_icmp=True,
            icmp_type=8, icmp_code=0,
        )
        info = dissect_packet(pkt)
        assert info is not None
        assert info.protocol == "ICMP"
        assert info.src_port == 8  # ICMP type stored in src_port

    def test_payload_extraction(self):
        """Extracts raw payload correctly."""
        payload = b"USER admin\r\n"
        pkt = _make_mock_packet(payload=payload, dport=21)
        info = dissect_packet(pkt)
        assert info is not None
        assert info.payload == payload

    def test_non_ip_packet_returns_none(self):
        """Non-IP packets (ARP, etc.) return None."""
        pkt = _make_mock_packet(has_ip=False)
        info = dissect_packet(pkt)
        assert info is None

    def test_packet_size(self):
        """Packet size is captured correctly."""
        pkt = _make_mock_packet(pkt_len=1500)
        info = dissect_packet(pkt)
        assert info is not None
        assert info.packet_size == 1500


class TestFormatFlags:
    """Tests for the format_flags helper."""

    def test_syn(self):
        assert format_flags("S") == "SYN"

    def test_syn_ack(self):
        assert format_flags("SA") == "SYN-ACK"

    def test_fin_ack(self):
        assert format_flags("FA") == "FIN-ACK"

    def test_rst(self):
        assert format_flags("R") == "RST"

    def test_empty(self):
        assert format_flags("") == "NONE"

    def test_complex_flags(self):
        result = format_flags("FSRPAU")
        assert "FIN" in result
        assert "SYN" in result
        assert "RST" in result
        assert "PSH" in result
        assert "ACK" in result
        assert "URG" in result
