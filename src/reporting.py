"""
V-IDS Reporting Engine
=======================
Formats alerts into structured, timestamped log entries and outputs them
to colorized stdout, a persistent log file, and the web dashboard via
a callback mechanism.

Log format (REQ-3.1):
  [TIMESTAMP] [SEVERITY] [RULE_NAME] - Src: <IP:Port> -> Dst: <IP:Port>
"""

import os
import sys
import logging
import threading
from datetime import datetime
from typing import Optional, Callable, List

from src.analysis import Alert

logger = logging.getLogger("v-ids.reporting")

# ── ANSI color codes for terminal output ───────────────────────────────────
COLORS = {
    "CRITICAL": "\033[1;91m",   # Bold bright red
    "HIGH":     "\033[1;93m",   # Bold bright yellow
    "MEDIUM":   "\033[1;96m",   # Bold bright cyan
    "LOW":      "\033[0;32m",   # Green
    "INFO":     "\033[0;37m",   # Light gray
    "RESET":    "\033[0m",
    "DIM":      "\033[2m",
    "BOLD":     "\033[1m",
    "WHITE":    "\033[0;97m",
    "GREEN":    "\033[1;92m",
}

# ── Severity symbols ──────────────────────────────────────────────────────
SEVERITY_ICONS = {
    "CRITICAL": "●",
    "HIGH":     "●",
    "MEDIUM":   "●",
    "LOW":      "●",
    "INFO":     "○",
}


def _format_port(port: Optional[int]) -> str:
    """Format a port number, returning 'N/A' for None."""
    return str(port) if port is not None else "N/A"


def format_alert(alert: Alert) -> str:
    """
    Format an alert into the structured log line per REQ-3.1.

    Format:
      [2026-05-31 10:30:15] [HIGH] [PORT_SCAN] - Src: 192.168.1.50:N/A -> Dst: 192.168.1.1:22
    """
    ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
    src_port = _format_port(alert.src_port)
    dst_port = _format_port(alert.dst_port)

    return (
        f"[{ts}] [{alert.severity}] [{alert.rule_name}] - "
        f"Src: {alert.src_ip}:{src_port} -> Dst: {alert.dst_ip}:{dst_port}"
    )


def format_alert_colorized(alert: Alert) -> str:
    """Format an alert with ANSI colors for clean terminal output."""
    ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
    src_port = _format_port(alert.src_port)
    dst_port = _format_port(alert.dst_port)
    color = COLORS.get(alert.severity, COLORS["INFO"])
    rst = COLORS["RESET"]
    dim = COLORS["DIM"]
    bold = COLORS["BOLD"]
    white = COLORS["WHITE"]
    icon = SEVERITY_ICONS.get(alert.severity, "○")

    sev_padded = f"{alert.severity:<8}"
    rule_padded = f"{alert.rule_name:<16}"

    return (
        f"  {color}{icon}{rst} "
        f"{dim}{ts}{rst}  "
        f"{color}{bold}{sev_padded}{rst} "
        f"{white}{rule_padded}{rst} "
        f"{alert.src_ip}:{src_port} {dim}→{rst} {alert.dst_ip}:{dst_port}\n"
        f"    {dim}{alert.message}{rst}"
    )


def alert_to_dict(alert: Alert) -> dict:
    """Convert an Alert to a JSON-serializable dictionary for the dashboard."""
    ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "timestamp": ts,
        "timestamp_raw": alert.timestamp,
        "severity": alert.severity,
        "rule_name": alert.rule_name,
        "src_ip": alert.src_ip,
        "src_port": _format_port(alert.src_port),
        "dst_ip": alert.dst_ip,
        "dst_port": _format_port(alert.dst_port),
        "message": alert.message,
    }


class ReportingEngine:
    """
    Manages alert output to stdout, log file, and web dashboard.
    Maintains an in-memory alert history for the dashboard.
    """

    def __init__(self, config: dict):
        self.config = config
        log_cfg = config.get("logging", {})
        dash_cfg = config.get("dashboard", {})
        self.colorize = log_cfg.get("colorize_stdout", True)
        self.log_file_path = self._resolve_log_path(log_cfg)
        self._file_handler = None
        self._setup_file_logging()

        # Dashboard callback (set by dashboard module)
        self._dashboard_callback: Optional[Callable] = None

        # Alert history for dashboard
        self._max_history = dash_cfg.get("max_alerts_history", 500)
        self._alert_history: List[dict] = []
        self._history_lock = threading.Lock()

        # Statistics
        self.alert_count = 0
        self.alerts_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self.alerts_by_rule = {}

    def set_dashboard_callback(self, callback: Callable) -> None:
        """Register a callback for pushing alerts to the web dashboard."""
        self._dashboard_callback = callback

    def get_alert_history(self) -> List[dict]:
        """Return the alert history for the dashboard."""
        with self._history_lock:
            return list(self._alert_history)

    def get_stats(self) -> dict:
        """Return current statistics as a dictionary for the dashboard."""
        return {
            "total_alerts": self.alert_count,
            "by_severity": dict(self.alerts_by_severity),
            "by_rule": dict(self.alerts_by_rule),
        }

    def _resolve_log_path(self, log_cfg: dict) -> str:
        """Determine the best writable log file path."""
        primary = log_cfg.get("log_file", "/var/log/v-ids.log")
        fallback = log_cfg.get("fallback_log_file", "./v-ids.log")

        # Try primary path
        try:
            log_dir = os.path.dirname(primary)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            with open(primary, "a") as f:
                pass
            return primary
        except (PermissionError, OSError):
            logger.warning("Cannot write to %s, using fallback: %s", primary, fallback)

        # Try fallback
        try:
            log_dir = os.path.dirname(fallback)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            return fallback
        except (PermissionError, OSError) as e:
            logger.error("Cannot write to fallback %s: %s. Logging to stdout only.", fallback, e)
            return ""

    def _setup_file_logging(self) -> None:
        """Initialize the file handler for persistent logging."""
        if not self.log_file_path:
            return
        try:
            self._file_handler = open(self.log_file_path, "a", encoding="utf-8", buffering=1)
            logger.info("Logging alerts to: %s", self.log_file_path)
        except (PermissionError, OSError) as e:
            logger.error("Failed to open log file %s: %s", self.log_file_path, e)
            self._file_handler = None

    def report(self, alert: Alert) -> None:
        """Output an alert to stdout, log file, and dashboard."""
        self.alert_count += 1
        self.alerts_by_severity[alert.severity] = self.alerts_by_severity.get(alert.severity, 0) + 1
        self.alerts_by_rule[alert.rule_name] = self.alerts_by_rule.get(alert.rule_name, 0) + 1

        # ── Convert to dict for dashboard ───────────────────────────────
        alert_dict = alert_to_dict(alert)

        # ── Store in history ────────────────────────────────────────────
        with self._history_lock:
            self._alert_history.append(alert_dict)
            if len(self._alert_history) > self._max_history:
                self._alert_history = self._alert_history[-self._max_history:]

        # ── Stdout ──────────────────────────────────────────────────────
        if self.colorize:
            print(format_alert_colorized(alert), file=sys.stdout, flush=True)
        else:
            print(format_alert(alert), file=sys.stdout, flush=True)

        # ── File ────────────────────────────────────────────────────────
        if self._file_handler:
            try:
                log_line = format_alert(alert)
                self._file_handler.write(log_line + "\n")
                self._file_handler.flush()
            except (OSError, IOError) as e:
                logger.error("Failed to write alert to log file: %s", e)

        # ── Dashboard (via callback) ────────────────────────────────────
        if self._dashboard_callback:
            try:
                self._dashboard_callback(alert_dict)
            except Exception as e:
                logger.debug("Dashboard callback error: %s", e)

    def print_stats(self) -> None:
        """Print clean shutdown statistics."""
        rst = COLORS["RESET"]
        bold = COLORS["BOLD"]
        dim = COLORS["DIM"]
        green = COLORS["GREEN"]

        print()
        print(f"  {dim}{'─' * 40}{rst}")
        print(f"  {bold}SESSION SUMMARY{rst}")
        print()
        print(f"    Total Alerts    {bold}{self.alert_count}{rst}")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.alerts_by_severity.get(severity, 0)
            if count > 0:
                color = COLORS.get(severity, "")
                icon = SEVERITY_ICONS.get(severity, "○")
                print(f"    {color}{icon} {severity:<12}{rst} {count}")

        if self.alerts_by_rule:
            print()
            print(f"    {dim}By Rule:{rst}")
            for rule, count in sorted(self.alerts_by_rule.items(), key=lambda x: -x[1]):
                print(f"      {rule:<18} {count}")

        print()
        if self.log_file_path:
            print(f"    {dim}Log: {self.log_file_path}{rst}")
        print(f"  {dim}{'─' * 40}{rst}")
        print()

    def shutdown(self) -> None:
        """Close the log file handler."""
        if self._file_handler:
            try:
                self._file_handler.close()
            except Exception:
                pass
            self._file_handler = None
