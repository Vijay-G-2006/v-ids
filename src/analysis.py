"""
V-IDS Analysis Engine
======================
Production-grade threat detection rules based on industry-standard
attack signatures (MITRE ATT&CK, Snort/Suricata patterns).

Rules:
  1. PortScanRule       — T1046: Tracks unique dst ports per source IP
  2. CleartextRule      — T1552.001: Deep payload inspection on cleartext protocols
  3. ICMPFloodRule      — T1498: Volume + oversized packet detection
  4. SSHBruteForceRule  — T1110.001: Rapid connection attempts to port 22
  5. HTTPThreatRule     — T1190: Path traversal, SQL injection, XSS patterns
"""

import time
import re
import logging
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Optional, Set

from src.dissection import PacketInfo

logger = logging.getLogger("v-ids.analysis")


@dataclass
class Alert:
    """Represents a triggered security alert."""
    timestamp: float
    severity: str
    rule_name: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    message: str


class BaseRule(ABC):
    """Abstract base class for all detection rules."""
    RULE_NAME = "BASE"

    def __init__(self, config: dict):
        self.config = config
        self.enabled = True
        self._lock = threading.Lock()

    @abstractmethod
    def evaluate(self, pkt: PacketInfo) -> Optional[Alert]:
        ...

    @abstractmethod
    def cleanup(self) -> None:
        ...


# ═══════════════════════════════════════════════════════════════════════════
# Rule 1: Port Scan Detection (MITRE ATT&CK T1046)
# ═══════════════════════════════════════════════════════════════════════════
class PortScanRule(BaseRule):
    """
    Detects TCP SYN-based port scanning by tracking UNIQUE destination
    ports per source IP within a rolling window.

    Industry basis: Snort GID:122, Suricata flow/port-scan rules.
    Tracks unique ports instead of raw SYN count — scanning 15 different
    ports is suspicious, but 100 SYNs to port 443 is normal HTTPS.
    """
    RULE_NAME = "PORT_SCAN"

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("detection", {}).get("port_scan", {})
        self.enabled = cfg.get("enabled", True)
        self.threshold = cfg.get("unique_ports_threshold", 15)
        self.window = cfg.get("window_seconds", 60)
        self.severity = cfg.get("severity", "HIGH")
        # {src_ip: {dst_port: first_seen_timestamp}}
        self._port_tracker: dict[str, dict[int, float]] = defaultdict(dict)
        self._alerted: dict[str, float] = {}

    def evaluate(self, pkt: PacketInfo) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP":
            return None
        flags = pkt.tcp_flags.upper() if pkt.tcp_flags else ""
        if "S" not in flags or "A" in flags:
            return None
        if pkt.dst_port is None:
            return None

        now = pkt.timestamp
        src = pkt.src_ip
        dst_port = pkt.dst_port

        with self._lock:
            ports = self._port_tracker[src]
            # Record this port if not already tracked
            if dst_port not in ports:
                ports[dst_port] = now

            # Prune ports outside the window
            cutoff = now - self.window
            self._port_tracker[src] = {
                p: t for p, t in ports.items() if t >= cutoff
            }
            unique_count = len(self._port_tracker[src])

            if unique_count >= self.threshold:
                if now - self._alerted.get(src, 0) < self.window:
                    return None
                self._alerted[src] = now
                scanned_sample = sorted(self._port_tracker[src].keys())[:10]
                return Alert(
                    timestamp=now, severity=self.severity, rule_name=self.RULE_NAME,
                    src_ip=src, src_port=pkt.src_port, dst_ip=pkt.dst_ip, dst_port=pkt.dst_port,
                    message=(
                        f"Port scan: {unique_count} unique ports from {src} "
                        f"in {self.window}s (threshold: {self.threshold}) "
                        f"ports: {scanned_sample}..."
                    ),
                )
        return None

    def cleanup(self) -> None:
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            stale = [
                ip for ip, ports in self._port_tracker.items()
                if not ports or max(ports.values()) < cutoff
            ]
            for ip in stale:
                del self._port_tracker[ip]
                self._alerted.pop(ip, None)


# ═══════════════════════════════════════════════════════════════════════════
# Rule 2: Cleartext Credential Detection (MITRE ATT&CK T1552.001)
# ═══════════════════════════════════════════════════════════════════════════
class CleartextRule(BaseRule):
    """
    Detects cleartext credentials across multiple unencrypted protocols.

    Industry basis: Snort SIDs 1000-1100 (FTP rules), ET OPEN rules for
    HTTP credential leakage. Monitors FTP, HTTP, Telnet, POP3, IMAP.
    """
    RULE_NAME = "CLEARTEXT_CREDS"

    # Protocol name by port
    PROTO_NAMES = {
        21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3",
        143: "IMAP", 8080: "HTTP-Alt", 8888: "HTTP-Alt",
    }

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("detection", {}).get("cleartext_creds", {})
        self.enabled = cfg.get("enabled", True)
        self.monitored_ports = set(cfg.get("monitored_ports", [21, 23, 80, 110, 143, 8080]))
        self.patterns = [
            p.lower() for p in cfg.get("patterns", [
                "USER ", "PASS ", "password=", "passwd=", "login=",
                "Authorization: Basic", "username=", "pwd=",
            ])
        ]
        self.severity = cfg.get("severity", "CRITICAL")
        self._alerted: dict[tuple, float] = {}
        self._rate_limit = config.get("logging", {}).get("rate_limit_seconds", 30)

    def evaluate(self, pkt: PacketInfo) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP":
            return None
        if pkt.dst_port not in self.monitored_ports or not pkt.payload:
            return None
        try:
            payload_str = pkt.payload.decode("utf-8", errors="ignore").lower()
        except Exception:
            return None
        if len(payload_str) < 4:
            return None

        matched = None
        for pattern in self.patterns:
            if pattern in payload_str:
                matched = pattern
                break
        if not matched:
            return None

        now = pkt.timestamp
        key = (pkt.src_ip, pkt.dst_port)
        with self._lock:
            if now - self._alerted.get(key, 0) < self._rate_limit:
                return None
            self._alerted[key] = now

        proto_name = self.PROTO_NAMES.get(pkt.dst_port, f"port-{pkt.dst_port}")
        return Alert(
            timestamp=now, severity=self.severity, rule_name=self.RULE_NAME,
            src_ip=pkt.src_ip, src_port=pkt.src_port, dst_ip=pkt.dst_ip, dst_port=pkt.dst_port,
            message=(
                f"Cleartext credentials: pattern '{matched.upper().strip()}' "
                f"in {proto_name} traffic from {pkt.src_ip}:{pkt.src_port}"
            ),
        )

    def cleanup(self) -> None:
        now = time.time()
        with self._lock:
            stale = [k for k, ts in self._alerted.items() if now - ts > self._rate_limit * 2]
            for k in stale:
                del self._alerted[k]


# ═══════════════════════════════════════════════════════════════════════════
# Rule 3: ICMP Flood + Oversized Packet Detection (MITRE ATT&CK T1498)
# ═══════════════════════════════════════════════════════════════════════════
class ICMPFloodRule(BaseRule):
    """
    Detects ICMP Echo Request flooding AND oversized ICMP packets.

    Industry basis: Snort SID:368 (ICMP Ping of Death), SID:480 (ICMP flood).
    Two detection modes:
      1. Volume: >100 echo requests / 10s from a single IP
      2. Oversized: Any ICMP packet >1500 bytes (Ping of Death signature)
    """
    RULE_NAME = "ICMP_FLOOD"
    ICMP_ECHO_REQUEST_TYPE = 8
    OVERSIZED_THRESHOLD = 1500  # Bytes — standard MTU

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("detection", {}).get("icmp_flood", {})
        self.enabled = cfg.get("enabled", True)
        self.threshold = cfg.get("icmp_threshold", 100)
        self.window = cfg.get("window_seconds", 10)
        self.severity = cfg.get("severity", "MEDIUM")
        self.oversized_threshold = cfg.get("oversized_bytes", self.OVERSIZED_THRESHOLD)
        self._icmp_tracker: dict[str, list[float]] = defaultdict(list)
        self._alerted: dict[str, float] = {}
        self._oversized_alerted: dict[str, float] = {}

    def evaluate(self, pkt: PacketInfo) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "ICMP":
            return None

        now = pkt.timestamp
        src = pkt.src_ip

        # Check for oversized ICMP (Ping of Death) — any ICMP type
        if pkt.packet_size > self.oversized_threshold:
            with self._lock:
                if now - self._oversized_alerted.get(src, 0) < 30:
                    return None
                self._oversized_alerted[src] = now
            return Alert(
                timestamp=now, severity="HIGH", rule_name=self.RULE_NAME,
                src_ip=src, src_port=None, dst_ip=pkt.dst_ip, dst_port=None,
                message=(
                    f"Oversized ICMP packet: {pkt.packet_size} bytes from {src} "
                    f"(threshold: {self.oversized_threshold}B) — possible Ping of Death"
                ),
            )

        # Volume-based: only Echo Requests
        if pkt.src_port != self.ICMP_ECHO_REQUEST_TYPE:
            return None

        with self._lock:
            self._icmp_tracker[src].append(now)
            cutoff = now - self.window
            self._icmp_tracker[src] = [t for t in self._icmp_tracker[src] if t >= cutoff]
            count = len(self._icmp_tracker[src])

            if count >= self.threshold:
                if now - self._alerted.get(src, 0) < self.window:
                    return None
                self._alerted[src] = now
                return Alert(
                    timestamp=now, severity=self.severity, rule_name=self.RULE_NAME,
                    src_ip=src, src_port=None, dst_ip=pkt.dst_ip, dst_port=None,
                    message=(
                        f"ICMP flood: {count} echo requests from {src} "
                        f"in {self.window}s (threshold: {self.threshold})"
                    ),
                )
        return None

    def cleanup(self) -> None:
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            stale = [ip for ip, ts in self._icmp_tracker.items() if not ts or ts[-1] < cutoff]
            for ip in stale:
                del self._icmp_tracker[ip]
                self._alerted.pop(ip, None)
            stale_os = [ip for ip, t in self._oversized_alerted.items() if now - t > 60]
            for ip in stale_os:
                del self._oversized_alerted[ip]


# ═══════════════════════════════════════════════════════════════════════════
# Rule 4: SSH Brute Force Detection (MITRE ATT&CK T1110.001)
# ═══════════════════════════════════════════════════════════════════════════
class SSHBruteForceRule(BaseRule):
    """
    Detects SSH brute force attacks by tracking rapid connection
    attempts to port 22 from a single source IP.

    Industry basis: Snort SID:2001219 (ET SCAN SSH brute force),
    fail2ban default SSH jail rules.
    """
    RULE_NAME = "SSH_BRUTE_FORCE"

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("detection", {}).get("ssh_brute_force", {})
        self.enabled = cfg.get("enabled", True)
        self.threshold = cfg.get("attempt_threshold", 10)
        self.window = cfg.get("window_seconds", 60)
        self.severity = cfg.get("severity", "HIGH")
        self.target_port = cfg.get("target_port", 22)
        self._conn_tracker: dict[str, list[float]] = defaultdict(list)
        self._alerted: dict[str, float] = {}

    def evaluate(self, pkt: PacketInfo) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP":
            return None
        flags = pkt.tcp_flags.upper() if pkt.tcp_flags else ""
        if "S" not in flags or "A" in flags:
            return None
        if pkt.dst_port != self.target_port:
            return None

        now = pkt.timestamp
        src = pkt.src_ip
        with self._lock:
            self._conn_tracker[src].append(now)
            cutoff = now - self.window
            self._conn_tracker[src] = [t for t in self._conn_tracker[src] if t >= cutoff]
            count = len(self._conn_tracker[src])

            if count >= self.threshold:
                if now - self._alerted.get(src, 0) < self.window:
                    return None
                self._alerted[src] = now
                return Alert(
                    timestamp=now, severity=self.severity, rule_name=self.RULE_NAME,
                    src_ip=src, src_port=pkt.src_port, dst_ip=pkt.dst_ip, dst_port=pkt.dst_port,
                    message=(
                        f"SSH brute force: {count} connection attempts from {src} "
                        f"to port {self.target_port} in {self.window}s "
                        f"(threshold: {self.threshold})"
                    ),
                )
        return None

    def cleanup(self) -> None:
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            stale = [ip for ip, ts in self._conn_tracker.items() if not ts or ts[-1] < cutoff]
            for ip in stale:
                del self._conn_tracker[ip]
                self._alerted.pop(ip, None)


# ═══════════════════════════════════════════════════════════════════════════
# Rule 5: HTTP Threat Detection (MITRE ATT&CK T1190)
# ═══════════════════════════════════════════════════════════════════════════
class HTTPThreatRule(BaseRule):
    """
    Detects common HTTP-based attack patterns: path traversal,
    SQL injection, and XSS attempts.

    Industry basis: OWASP Top 10, ModSecurity CRS rules,
    Snort SID:1497 (directory traversal), ET OPEN web attack rules.
    """
    RULE_NAME = "HTTP_THREAT"

    # Compiled regex patterns for performance
    ATTACK_PATTERNS = [
        (re.compile(rb'(?:\.\./|\.\.\\){2,}', re.IGNORECASE), "PATH_TRAVERSAL",
         "Directory traversal attempt (../)"),
        (re.compile(rb'/etc/(?:passwd|shadow|hosts)', re.IGNORECASE), "PATH_TRAVERSAL",
         "Sensitive file access attempt (/etc/passwd)"),
        (re.compile(rb"(?:union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|delete\s+from)", re.IGNORECASE), "SQL_INJECTION",
         "SQL injection attempt"),
        (re.compile(rb"(?:'\s*(?:or|and)\s+['\d]|--\s*$|;\s*drop\s)", re.IGNORECASE), "SQL_INJECTION",
         "SQL injection attempt (boolean/comment)"),
        (re.compile(rb'<script[^>]*>|javascript:|on(?:error|load|click)\s*=', re.IGNORECASE), "XSS",
         "Cross-site scripting (XSS) attempt"),
        (re.compile(rb'(?:/proc/self/|/dev/tcp/|/bin/(?:sh|bash|nc))', re.IGNORECASE), "COMMAND_INJECTION",
         "Command injection / RCE attempt"),
    ]

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("detection", {}).get("http_threats", {})
        self.enabled = cfg.get("enabled", True)
        self.severity = cfg.get("severity", "CRITICAL")
        self.http_ports = set(cfg.get("http_ports", [80, 8080, 8443, 8888]))
        self._alerted: dict[tuple, float] = {}
        self._rate_limit = 10  # seconds between same (src, attack_type) alerts

    def evaluate(self, pkt: PacketInfo) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP":
            return None
        if pkt.dst_port not in self.http_ports or not pkt.payload:
            return None
        if len(pkt.payload) < 10:
            return None

        now = pkt.timestamp
        for pattern, attack_type, description in self.ATTACK_PATTERNS:
            if pattern.search(pkt.payload):
                key = (pkt.src_ip, attack_type)
                with self._lock:
                    if now - self._alerted.get(key, 0) < self._rate_limit:
                        return None
                    self._alerted[key] = now

                return Alert(
                    timestamp=now, severity=self.severity, rule_name=self.RULE_NAME,
                    src_ip=pkt.src_ip, src_port=pkt.src_port,
                    dst_ip=pkt.dst_ip, dst_port=pkt.dst_port,
                    message=f"{description} [{attack_type}] from {pkt.src_ip}:{pkt.src_port}",
                )
        return None

    def cleanup(self) -> None:
        now = time.time()
        with self._lock:
            stale = [k for k, ts in self._alerted.items() if now - ts > self._rate_limit * 3]
            for k in stale:
                del self._alerted[k]


# ═══════════════════════════════════════════════════════════════════════════
# Analysis Engine — Orchestrator
# ═══════════════════════════════════════════════════════════════════════════
class AnalysisEngine:
    """Orchestrates all detection rules."""

    def __init__(self, config: dict):
        self.config = config
        self.rules: List[BaseRule] = [
            PortScanRule(config),
            CleartextRule(config),
            ICMPFloodRule(config),
            SSHBruteForceRule(config),
            HTTPThreatRule(config),
        ]
        enabled = [r for r in self.rules if r.enabled]
        logger.info("Analysis engine: %d/%d rules enabled: %s",
                     len(enabled), len(self.rules), ", ".join(r.RULE_NAME for r in enabled))

    def analyze(self, pkt: PacketInfo) -> List[Alert]:
        alerts = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(pkt)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error("Rule %s error: %s", rule.RULE_NAME, e, exc_info=True)
        return alerts

    def cleanup_all(self) -> None:
        for rule in self.rules:
            try:
                rule.cleanup()
            except Exception as e:
                logger.error("Cleanup failed for %s: %s", rule.RULE_NAME, e)
