"""
V-IDS Ingestion Engine
=======================
Captures raw network packets using Scapy's sniff() and pushes them into a
thread-safe queue for async processing. Decouples capture from analysis
to minimize packet drops.

Architecture:
  - Capture thread: scapy.sniff() → queue.Queue
  - Worker thread:  queue.Queue → dissection → analysis → reporting
  - Cleanup timer:  periodic state pruning in the analysis engine
"""

import time
import queue
import logging
import threading
from typing import Optional

from scapy.all import sniff, conf as scapy_conf

from src.dissection import dissect_packet
from src.analysis import AnalysisEngine
from src.reporting import ReportingEngine

logger = logging.getLogger("v-ids.ingestion")


class IngestionEngine:
    """
    Manages packet capture and the processing pipeline.

    Spawns a dedicated capture thread and a worker thread connected
    via a bounded queue. Handles graceful shutdown via threading events.
    """

    def __init__(self, config: dict, analysis: AnalysisEngine, reporter: ReportingEngine):
        self.config = config
        self.analysis = analysis
        self.reporter = reporter

        net_cfg = config.get("network", {})
        eng_cfg = config.get("engine", {})

        self.interface = net_cfg.get("interface", "eth0")
        self.bpf_filter = net_cfg.get("bpf_filter", "")
        self.queue_size = eng_cfg.get("queue_size", 10000)
        self.cleanup_interval = eng_cfg.get("cleanup_interval_seconds", 60)

        # Packet queue connecting capture → worker threads
        self._packet_queue: queue.Queue = queue.Queue(maxsize=self.queue_size)

        # Shutdown signal
        self._stop_event = threading.Event()

        # Thread handles
        self._capture_thread: Optional[threading.Thread] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None

        # Statistics
        self.packets_captured = 0
        self.packets_processed = 0
        self.packets_dropped = 0
        self.bytes_captured = 0
        self._start_time = 0.0

        # Live traffic sample buffer (ring buffer of recent packet summaries)
        self._traffic_buffer: list = []
        self._traffic_lock = threading.Lock()
        self._max_traffic_samples = 50
        self._traffic_callback = None  # Set by dashboard

        # Timeseries data (per-minute snapshots, max 60 minutes)
        self._timeseries: list = []
        self._timeseries_lock = threading.Lock()
        self._ts_minute_pkts = 0
        self._ts_minute_bytes = 0
        self._ts_minute_alerts = 0
        self._last_ts_snapshot = 0.0

    def set_traffic_callback(self, callback):
        """Register a callback for pushing live traffic samples to the dashboard."""
        self._traffic_callback = callback

    def get_traffic_samples(self) -> list:
        """Return the recent traffic samples."""
        with self._traffic_lock:
            return list(self._traffic_buffer)

    def get_pps(self) -> float:
        """Return current packets per second rate."""
        elapsed = time.time() - self._start_time if self._start_time else 1
        return self.packets_processed / max(elapsed, 1)

    def get_timeseries(self) -> list:
        """Return timeseries data for the dashboard chart."""
        with self._timeseries_lock:
            return list(self._timeseries)

    def start(self) -> None:
        """Start the capture, worker, and cleanup threads."""
        self._start_time = time.time()
        logger.info("Starting ingestion engine on interface: %s", self.interface)
        if self.bpf_filter:
            logger.info("BPF filter: %s", self.bpf_filter)

        self._stop_event.clear()

        # Worker thread (must start before capture to consume packets)
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="v-ids-worker", daemon=True
        )
        self._worker_thread.start()

        # Cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, name="v-ids-cleanup", daemon=True
        )
        self._cleanup_thread.start()

        # Capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop, name="v-ids-capture", daemon=True
        )
        self._capture_thread.start()

        logger.info("All engine threads started successfully")

    def stop(self) -> None:
        """Signal all threads to stop and wait for them to finish."""
        logger.info("Stopping ingestion engine...")
        self._stop_event.set()

        # Wait for threads to finish (with timeout)
        for thread in [self._capture_thread, self._worker_thread, self._cleanup_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=5)

        logger.info(
            "Engine stopped. Captured: %d | Processed: %d | Dropped: %d",
            self.packets_captured, self.packets_processed, self.packets_dropped
        )

    def _capture_loop(self) -> None:
        """
        Capture thread: sniffs packets and enqueues them.
        Uses Scapy's sniff() with a callback and stop_filter.
        """
        try:
            logger.info("Capture thread started — listening on %s", self.interface)

            # Suppress Scapy's verbose output
            scapy_conf.verb = 0

            sniff(
                iface=self.interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._enqueue_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=0,  # Don't store packets in memory (we use the queue)
            )
        except PermissionError:
            logger.critical(
                "Permission denied: raw sockets require root/sudo privileges. "
                "Run with: sudo python -m src.main -i %s", self.interface
            )
            self._stop_event.set()
        except OSError as e:
            if "No such device" in str(e):
                logger.critical("Network interface '%s' not found. Check with 'ip link'.", self.interface)
            else:
                logger.critical("Capture error: %s", e)
            self._stop_event.set()
        except Exception as e:
            logger.critical("Unexpected capture error: %s", e, exc_info=True)
            self._stop_event.set()

    def _enqueue_packet(self, packet) -> None:
        """Callback for sniff(): push packet into the processing queue."""
        self.packets_captured += 1
        try:
            self._packet_queue.put_nowait(packet)
        except queue.Full:
            self.packets_dropped += 1
            if self.packets_dropped % 1000 == 1:
                logger.warning(
                    "Queue full — dropped %d packets total. Consider increasing queue_size.",
                    self.packets_dropped
                )

    def _worker_loop(self) -> None:
        """
        Worker thread: dequeues packets and runs the full pipeline:
        dissection → analysis → reporting.
        """
        logger.info("Worker thread started")

        while not self._stop_event.is_set():
            try:
                packet = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                # ── Dissection ──────────────────────────────────────────
                pkt_info = dissect_packet(packet)
                if pkt_info is None:
                    continue

                self.packets_processed += 1
                self.bytes_captured += pkt_info.packet_size

                # ── Push traffic sample ─────────────────────────────────
                sample = {
                    "src": pkt_info.src_ip,
                    "dst": pkt_info.dst_ip,
                    "proto": pkt_info.protocol,
                    "sport": pkt_info.src_port,
                    "dport": pkt_info.dst_port,
                    "size": pkt_info.packet_size,
                    "flags": pkt_info.tcp_flags or "",
                }
                with self._traffic_lock:
                    self._traffic_buffer.append(sample)
                    if len(self._traffic_buffer) > self._max_traffic_samples:
                        self._traffic_buffer = self._traffic_buffer[-self._max_traffic_samples:]

                if self._traffic_callback and self.packets_processed % 3 == 0:
                    try:
                        self._traffic_callback(sample)
                    except Exception:
                        pass

                # Timeseries update (every 60s)
                now = time.time()
                with self._timeseries_lock:
                    if self._last_ts_snapshot == 0.0:
                        self._last_ts_snapshot = now
                    
                    self._ts_minute_pkts += 1
                    self._ts_minute_bytes += pkt_info.packet_size
                    
                    if now - self._last_ts_snapshot >= 60.0:
                        ts_entry = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "packets": self._ts_minute_pkts,
                            "bytes": self._ts_minute_bytes,
                            "alerts": self._ts_minute_alerts,
                        }
                        self._timeseries.append(ts_entry)
                        if len(self._timeseries) > 60:
                            self._timeseries = self._timeseries[-60:]
                        self._ts_minute_pkts = 0
                        self._ts_minute_bytes = 0
                        self._ts_minute_alerts = 0
                        self._last_ts_snapshot = now

                # ── Analysis ────────────────────────────────────────────
                alerts = self.analysis.analyze(pkt_info)

                # ── Reporting ───────────────────────────────────────────
                for alert in alerts:
                    self.reporter.report(alert)
                    with self._timeseries_lock:
                        self._ts_minute_alerts += 1

            except Exception as e:
                logger.error("Error processing packet: %s", e, exc_info=True)

        # Drain remaining packets
        while not self._packet_queue.empty():
            try:
                packet = self._packet_queue.get_nowait()
                pkt_info = dissect_packet(packet)
                if pkt_info:
                    self.packets_processed += 1
                    for alert in self.analysis.analyze(pkt_info):
                        self.reporter.report(alert)
            except queue.Empty:
                break
            except Exception:
                break

        logger.info("Worker thread stopped")

    def _cleanup_loop(self) -> None:
        """Periodically prune stale state from analysis rules."""
        logger.info("Cleanup thread started (interval: %ds)", self.cleanup_interval)

        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.cleanup_interval)
            if not self._stop_event.is_set():
                self.analysis.cleanup_all()
                logger.debug(
                    "State cleanup complete. Queue depth: %d/%d",
                    self._packet_queue.qsize(), self.queue_size
                )

    def wait(self) -> None:
        """Block until the stop event is set (used by main thread)."""
        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

    @property
    def is_running(self) -> bool:
        """Check if the engine is currently running."""
        return not self._stop_event.is_set()
