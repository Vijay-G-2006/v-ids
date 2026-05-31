"""
Unit tests for the V-IDS Analysis Engine.
Tests all 5 production-grade detection rules.
"""

import time
import pytest
from collections import defaultdict

from src.dissection import PacketInfo
from src.analysis import (
    Alert, PortScanRule, CleartextRule, ICMPFloodRule,
    SSHBruteForceRule, HTTPThreatRule, AnalysisEngine,
)
from src.config_loader import DEFAULT_CONFIG


def _make_pkt(**overrides):
    defaults = dict(
        timestamp=time.time(), src_ip="192.168.1.100", dst_ip="10.0.0.1",
        src_port=54321, dst_port=80, protocol="TCP", tcp_flags="S",
        payload=b"", packet_size=64, is_valid=True,
    )
    defaults.update(overrides)
    return PacketInfo(**defaults)


# ═══════════════════════════════════════════════════════════════════════════
# Rule 1: Port Scan (unique destination ports tracking)
# ═══════════════════════════════════════════════════════════════════════════

class TestPortScanRule:
    def _cfg(self, **overrides):
        cfg = dict(DEFAULT_CONFIG)
        cfg["detection"] = dict(cfg["detection"])
        cfg["detection"]["port_scan"] = {
            "enabled": True, "unique_ports_threshold": 5,
            "window_seconds": 10, "severity": "HIGH",
        }
        cfg["detection"]["port_scan"].update(overrides)
        return cfg

    def test_no_alert_below_threshold(self):
        rule = PortScanRule(self._cfg())
        for port in range(4):
            result = rule.evaluate(_make_pkt(dst_port=port, tcp_flags="S"))
        assert result is None

    def test_alert_at_threshold_unique_ports(self):
        rule = PortScanRule(self._cfg())
        for port in range(5):
            result = rule.evaluate(_make_pkt(dst_port=port, tcp_flags="S"))
        assert result is not None
        assert result.rule_name == "PORT_SCAN"
        assert "unique ports" in result.message

    def test_same_port_no_alert(self):
        """Repeated SYNs to the same port should NOT trigger (they're not scanning)."""
        rule = PortScanRule(self._cfg())
        for _ in range(20):
            result = rule.evaluate(_make_pkt(dst_port=80, tcp_flags="S"))
        assert result is None  # Only 1 unique port

    def test_syn_ack_ignored(self):
        rule = PortScanRule(self._cfg())
        for port in range(10):
            result = rule.evaluate(_make_pkt(dst_port=port, tcp_flags="SA"))
        assert result is None

    def test_non_tcp_ignored(self):
        rule = PortScanRule(self._cfg())
        for port in range(10):
            result = rule.evaluate(_make_pkt(dst_port=port, protocol="UDP"))
        assert result is None

    def test_different_ips_separate_tracking(self):
        rule = PortScanRule(self._cfg())
        for port in range(3):
            rule.evaluate(_make_pkt(src_ip="10.0.0.1", dst_port=port))
        for port in range(3):
            rule.evaluate(_make_pkt(src_ip="10.0.0.2", dst_port=port))
        assert len(rule._port_tracker) == 2

    def test_window_expiry(self):
        rule = PortScanRule(self._cfg(window_seconds=10))
        old_time = time.time() - 20
        for port in range(4):
            rule.evaluate(_make_pkt(timestamp=old_time, dst_port=port))
        result = rule.evaluate(_make_pkt(dst_port=100))
        assert result is None  # Old ports expired, only 1 current

    def test_cleanup(self):
        rule = PortScanRule(self._cfg(window_seconds=1))
        rule.evaluate(_make_pkt(timestamp=time.time() - 5, dst_port=1))
        rule.cleanup()
        assert len(rule._port_tracker) == 0

    def test_alert_includes_port_sample(self):
        rule = PortScanRule(self._cfg())
        for port in range(5):
            result = rule.evaluate(_make_pkt(dst_port=port))
        assert "ports:" in result.message


# ═══════════════════════════════════════════════════════════════════════════
# Rule 2: Cleartext Credentials (expanded protocols)
# ═══════════════════════════════════════════════════════════════════════════

class TestCleartextRule:
    def test_ftp_user_command(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=21, payload=b"USER admin\r\n"))
        assert result is not None
        assert result.rule_name == "CLEARTEXT_CREDS"
        assert "FTP" in result.message

    def test_ftp_pass_command(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=21, payload=b"PASS secret123\r\n"))
        assert result is not None

    def test_http_password_field(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=80, payload=b"POST /login HTTP/1.1\r\n\r\npassword=hunter2"))
        assert result is not None

    def test_telnet_port(self):
        """Telnet (port 23) should now be monitored."""
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=23, payload=b"USER root\r\n"))
        assert result is not None
        assert "Telnet" in result.message

    def test_pop3_port(self):
        """POP3 (port 110) should be monitored."""
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=110, payload=b"USER admin@test.com\r\n"))
        assert result is not None

    def test_https_port_ignored(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=443, payload=b"password=secret"))
        assert result is None

    def test_no_payload(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=80, payload=b""))
        assert result is None

    def test_safe_payload(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=80, payload=b"GET /index.html HTTP/1.1"))
        assert result is None

    def test_rate_limiting(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        rule.evaluate(_make_pkt(dst_port=21, payload=b"USER admin\r\n"))
        result = rule.evaluate(_make_pkt(dst_port=21, payload=b"PASS secret\r\n"))
        assert result is None  # Same (src_ip, dst_port) rate-limited

    def test_short_payload_ignored(self):
        rule = CleartextRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=80, payload=b"ab"))
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# Rule 3: ICMP Flood + Oversized Packet
# ═══════════════════════════════════════════════════════════════════════════

class TestICMPFloodRule:
    def _cfg(self, **overrides):
        cfg = dict(DEFAULT_CONFIG)
        cfg["detection"] = dict(cfg["detection"])
        cfg["detection"]["icmp_flood"] = {
            "enabled": True, "icmp_threshold": 5, "window_seconds": 10,
            "oversized_bytes": 1500, "severity": "MEDIUM",
        }
        cfg["detection"]["icmp_flood"].update(overrides)
        return cfg

    def test_no_alert_below_threshold(self):
        rule = ICMPFloodRule(self._cfg())
        for _ in range(4):
            result = rule.evaluate(_make_pkt(protocol="ICMP", src_port=8, dst_port=0))
        assert result is None

    def test_alert_at_threshold(self):
        rule = ICMPFloodRule(self._cfg())
        for _ in range(5):
            result = rule.evaluate(_make_pkt(protocol="ICMP", src_port=8, dst_port=0))
        assert result is not None
        assert result.rule_name == "ICMP_FLOOD"
        assert "echo requests" in result.message

    def test_non_echo_request_ignored(self):
        rule = ICMPFloodRule(self._cfg())
        for _ in range(10):
            result = rule.evaluate(_make_pkt(protocol="ICMP", src_port=0, dst_port=0))
        assert result is None

    def test_oversized_packet_alert(self):
        """Oversized ICMP packet should trigger even with just 1 packet."""
        rule = ICMPFloodRule(self._cfg())
        result = rule.evaluate(_make_pkt(
            protocol="ICMP", src_port=8, dst_port=0, packet_size=2000
        ))
        assert result is not None
        assert "Oversized" in result.message
        assert result.severity == "HIGH"  # Oversized uses HIGH regardless

    def test_cleanup(self):
        rule = ICMPFloodRule(self._cfg(window_seconds=1))
        rule.evaluate(_make_pkt(protocol="ICMP", src_port=8, dst_port=0, timestamp=time.time() - 5))
        rule.cleanup()
        assert len(rule._icmp_tracker) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Rule 4: SSH Brute Force
# ═══════════════════════════════════════════════════════════════════════════

class TestSSHBruteForceRule:
    def _cfg(self, **overrides):
        cfg = dict(DEFAULT_CONFIG)
        cfg["detection"] = dict(cfg["detection"])
        cfg["detection"]["ssh_brute_force"] = {
            "enabled": True, "attempt_threshold": 5,
            "window_seconds": 60, "target_port": 22, "severity": "HIGH",
        }
        cfg["detection"]["ssh_brute_force"].update(overrides)
        return cfg

    def test_no_alert_below_threshold(self):
        rule = SSHBruteForceRule(self._cfg())
        for _ in range(4):
            result = rule.evaluate(_make_pkt(dst_port=22, tcp_flags="S"))
        assert result is None

    def test_alert_at_threshold(self):
        rule = SSHBruteForceRule(self._cfg())
        for _ in range(5):
            result = rule.evaluate(_make_pkt(dst_port=22, tcp_flags="S"))
        assert result is not None
        assert result.rule_name == "SSH_BRUTE_FORCE"
        assert "SSH brute force" in result.message

    def test_non_ssh_port_ignored(self):
        rule = SSHBruteForceRule(self._cfg())
        for _ in range(10):
            result = rule.evaluate(_make_pkt(dst_port=80, tcp_flags="S"))
        assert result is None

    def test_syn_ack_ignored(self):
        rule = SSHBruteForceRule(self._cfg())
        for _ in range(10):
            result = rule.evaluate(_make_pkt(dst_port=22, tcp_flags="SA"))
        assert result is None

    def test_rate_limiting(self):
        rule = SSHBruteForceRule(self._cfg())
        for _ in range(5):
            rule.evaluate(_make_pkt(dst_port=22, tcp_flags="S"))
        # Second burst should be rate-limited
        result = None
        for _ in range(5):
            result = rule.evaluate(_make_pkt(dst_port=22, tcp_flags="S"))
        assert result is None

    def test_cleanup(self):
        rule = SSHBruteForceRule(self._cfg(window_seconds=1))
        rule.evaluate(_make_pkt(dst_port=22, tcp_flags="S", timestamp=time.time() - 5))
        rule.cleanup()
        assert len(rule._conn_tracker) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Rule 5: HTTP Threat Detection
# ═══════════════════════════════════════════════════════════════════════════

class TestHTTPThreatRule:
    def test_path_traversal(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=80, payload=b"GET /../../etc/passwd HTTP/1.1"
        ))
        assert result is not None
        assert result.rule_name == "HTTP_THREAT"
        assert "PATH_TRAVERSAL" in result.message

    def test_etc_passwd_access(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=80, payload=b"GET /etc/passwd HTTP/1.1"
        ))
        assert result is not None

    def test_sql_injection(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=80, payload=b"GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1"
        ))
        assert result is not None
        assert "SQL_INJECTION" in result.message

    def test_xss_attempt(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=80, payload=b"GET /page?name=<script>alert(1)</script> HTTP/1.1"
        ))
        assert result is not None
        assert "XSS" in result.message

    def test_command_injection(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=80, payload=b"GET /cmd?exec=/bin/bash HTTP/1.1"
        ))
        assert result is not None
        assert "COMMAND_INJECTION" in result.message

    def test_safe_request_ignored(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=80, payload=b"GET /index.html HTTP/1.1\r\nHost: example.com"
        ))
        assert result is None

    def test_non_http_port_ignored(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(
            dst_port=22, payload=b"GET /../../etc/passwd HTTP/1.1"
        ))
        assert result is None

    def test_short_payload_ignored(self):
        rule = HTTPThreatRule(DEFAULT_CONFIG)
        result = rule.evaluate(_make_pkt(dst_port=80, payload=b"GET /"))
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# Analysis Engine (Orchestrator)
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalysisEngine:
    def test_initializes_all_rules(self):
        engine = AnalysisEngine(DEFAULT_CONFIG)
        assert len(engine.rules) == 5
        names = {r.RULE_NAME for r in engine.rules}
        assert names == {"PORT_SCAN", "CLEARTEXT_CREDS", "ICMP_FLOOD", "SSH_BRUTE_FORCE", "HTTP_THREAT"}

    def test_analyze_returns_alerts(self):
        engine = AnalysisEngine(DEFAULT_CONFIG)
        pkt = _make_pkt(dst_port=80, payload=b"GET /../../etc/passwd HTTP/1.1")
        alerts = engine.analyze(pkt)
        assert len(alerts) > 0

    def test_cleanup_all(self):
        engine = AnalysisEngine(DEFAULT_CONFIG)
        engine.cleanup_all()  # Should not raise
