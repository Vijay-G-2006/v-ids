"""
Unit tests for the V-IDS Dashboard module.
Tests Flask routes, alert serialization, and SocketIO integration.
"""

import time
import pytest
from unittest.mock import MagicMock, patch

from src.analysis import Alert
from src.reporting import alert_to_dict, ReportingEngine
from src.config_loader import DEFAULT_CONFIG


def _make_alert(severity="HIGH", rule_name="PORT_SCAN", timestamp=None):
    return Alert(
        timestamp=timestamp or 1717142400.0,
        severity=severity, rule_name=rule_name,
        src_ip="192.168.1.100", src_port=54321,
        dst_ip="10.0.0.1", dst_port=22,
        message="Test alert",
    )


class TestAlertToDict:
    """Tests for alert_to_dict serializer."""

    def test_basic_serialization(self):
        alert = _make_alert()
        d = alert_to_dict(alert)
        assert d["severity"] == "HIGH"
        assert d["rule_name"] == "PORT_SCAN"
        assert d["src_ip"] == "192.168.1.100"
        assert d["src_port"] == "54321"
        assert d["dst_ip"] == "10.0.0.1"
        assert d["dst_port"] == "22"
        assert d["message"] == "Test alert"
        assert "timestamp" in d
        assert "timestamp_raw" in d

    def test_none_ports(self):
        alert = Alert(
            timestamp=1717142400.0, severity="MEDIUM", rule_name="ICMP_FLOOD",
            src_ip="10.0.0.1", src_port=None, dst_ip="10.0.0.2", dst_port=None,
            message="ICMP flood",
        )
        d = alert_to_dict(alert)
        assert d["src_port"] == "N/A"
        assert d["dst_port"] == "N/A"


class TestReportingEngineDashboard:
    """Tests for dashboard-related ReportingEngine features."""

    def test_dashboard_callback_called(self):
        config = dict(DEFAULT_CONFIG)
        # Override log file to avoid filesystem issues
        config["logging"] = dict(config["logging"])
        config["logging"]["log_file"] = ""
        config["logging"]["fallback_log_file"] = ""

        reporter = ReportingEngine(config)
        callback = MagicMock()
        reporter.set_dashboard_callback(callback)

        alert = _make_alert()
        reporter.report(alert)

        callback.assert_called_once()
        call_arg = callback.call_args[0][0]
        assert call_arg["severity"] == "HIGH"
        assert call_arg["rule_name"] == "PORT_SCAN"

    def test_alert_history_maintained(self):
        config = dict(DEFAULT_CONFIG)
        config["logging"] = dict(config["logging"])
        config["logging"]["log_file"] = ""
        config["logging"]["fallback_log_file"] = ""
        config["dashboard"] = {"max_alerts_history": 5}

        reporter = ReportingEngine(config)
        for i in range(10):
            alert = _make_alert(timestamp=1717142400.0 + i)
            reporter.report(alert)

        history = reporter.get_alert_history()
        assert len(history) == 5  # Capped at max_alerts_history

    def test_stats_tracking(self):
        config = dict(DEFAULT_CONFIG)
        config["logging"] = dict(config["logging"])
        config["logging"]["log_file"] = ""
        config["logging"]["fallback_log_file"] = ""

        reporter = ReportingEngine(config)
        reporter.report(_make_alert(severity="CRITICAL", rule_name="CLEARTEXT_CREDS"))
        reporter.report(_make_alert(severity="HIGH", rule_name="PORT_SCAN"))
        reporter.report(_make_alert(severity="MEDIUM", rule_name="ICMP_FLOOD"))

        stats = reporter.get_stats()
        assert stats["total_alerts"] == 3
        assert stats["by_severity"]["CRITICAL"] == 1
        assert stats["by_severity"]["HIGH"] == 1
        assert stats["by_severity"]["MEDIUM"] == 1
        assert stats["by_rule"]["CLEARTEXT_CREDS"] == 1
        assert stats["by_rule"]["PORT_SCAN"] == 1
        assert stats["by_rule"]["ICMP_FLOOD"] == 1


class TestDashboardFlaskApp:
    """Tests for the Flask dashboard routes."""

    @pytest.fixture
    def client(self):
        from src.dashboard.app import app, _reporter
        import src.dashboard.app as dash_module
        # Set up mock reporter
        mock_reporter = MagicMock()
        mock_reporter.get_stats.return_value = {"total_alerts": 5, "by_severity": {}, "by_rule": {}}
        mock_reporter.get_alert_history.return_value = []
        mock_reporter.log_file_path = "/var/log/v-ids.log"
        dash_module._reporter = mock_reporter
        dash_module._engine = MagicMock(
            packets_captured=100, packets_processed=95, packets_dropped=5,
            bytes_captured=64000, queue_size=10000, is_running=True,
            _packet_queue=MagicMock(qsize=MagicMock(return_value=50)),
        )
        dash_module._engine.get_pps.return_value = 12.5
        dash_module._engine.get_traffic_samples.return_value = []
        dash_module._config = DEFAULT_CONFIG
        dash_module._start_time = time.time()

        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_index_page(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"V-IDS" in response.data

    def test_api_stats(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.get_json()
        assert "alerts" in data
        assert "engine" in data
        assert "uptime" in data

    def test_api_alerts(self, client):
        response = client.get("/api/alerts")
        assert response.status_code == 200
        data = response.get_json()
        assert "alerts" in data
