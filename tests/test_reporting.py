"""
Unit tests for the V-IDS Reporting Engine.
Tests alert formatting, colorization, and log output.
"""

import time
import pytest

from src.analysis import Alert
from src.reporting import format_alert, format_alert_colorized, _format_port


def _make_alert(
    severity="HIGH", rule_name="PORT_SCAN",
    src_ip="192.168.1.100", src_port=54321,
    dst_ip="10.0.0.1", dst_port=22,
    message="Test alert", timestamp=None,
):
    return Alert(
        timestamp=timestamp or 1717142400.0,  # Fixed timestamp for deterministic tests
        severity=severity, rule_name=rule_name,
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        message=message,
    )


class TestFormatPort:
    def test_numeric_port(self):
        assert _format_port(80) == "80"

    def test_none_port(self):
        assert _format_port(None) == "N/A"

    def test_zero_port(self):
        assert _format_port(0) == "0"


class TestFormatAlert:
    """Tests for the plain-text alert formatter."""

    def test_basic_format(self):
        alert = _make_alert()
        result = format_alert(alert)
        assert "[HIGH]" in result
        assert "[PORT_SCAN]" in result
        assert "192.168.1.100:54321" in result
        assert "10.0.0.1:22" in result
        assert "Src:" in result
        assert "Dst:" in result

    def test_timestamp_present(self):
        alert = _make_alert(timestamp=1717142400.0)
        result = format_alert(alert)
        # Should contain a date-time string
        assert "[20" in result  # Year starts with 20xx

    def test_icmp_ports_na(self):
        alert = _make_alert(
            rule_name="ICMP_FLOOD", severity="MEDIUM",
            src_port=None, dst_port=None,
        )
        result = format_alert(alert)
        assert "N/A" in result

    def test_critical_severity(self):
        alert = _make_alert(severity="CRITICAL", rule_name="CLEARTEXT_CREDS")
        result = format_alert(alert)
        assert "[CRITICAL]" in result
        assert "[CLEARTEXT_CREDS]" in result


class TestFormatAlertColorized:
    """Tests for the colorized alert formatter."""

    def test_contains_ansi_codes(self):
        alert = _make_alert()
        result = format_alert_colorized(alert)
        assert "\033[" in result  # ANSI escape sequences present

    def test_contains_message(self):
        alert = _make_alert(message="Port scan from 10.0.0.5")
        result = format_alert_colorized(alert)
        assert "Port scan from 10.0.0.5" in result

    def test_all_severity_levels(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            alert = _make_alert(severity=sev)
            result = format_alert_colorized(alert)
            assert sev in result
