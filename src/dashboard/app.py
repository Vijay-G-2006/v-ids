"""
V-IDS Dashboard — Flask + SocketIO Web Application
====================================================
Provides a real-time web dashboard for monitoring V-IDS alerts,
network statistics, and rule status.

The dashboard runs on a background thread and communicates with
the reporting engine via callbacks.
"""

import os
import time
import logging
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

logger = logging.getLogger("v-ids.dashboard")

# ── Flask app setup ────────────────────────────────────────────────────────
template_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config["SECRET_KEY"] = "v-ids-dashboard-key"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# References set by start_dashboard()
_reporter = None
_engine = None
_config = None
_start_time = None


def _get_uptime() -> str:
    """Get formatted uptime string."""
    if not _start_time:
        return "0s"
    elapsed = time.time() - _start_time
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    """Return current statistics as JSON."""
    stats = _reporter.get_stats() if _reporter else {}
    engine_stats = {}
    if _engine:
        engine_stats = {
            "packets_captured": _engine.packets_captured,
            "packets_processed": _engine.packets_processed,
            "packets_dropped": _engine.packets_dropped,
            "bytes_captured": _engine.bytes_captured,
            "pps": round(_engine.get_pps(), 1),
            "queue_depth": _engine._packet_queue.qsize() if hasattr(_engine, "_packet_queue") else 0,
            "queue_max": _engine.queue_size,
            "is_running": _engine.is_running,
        }

    dash_cfg = _config.get("dashboard", {}) if _config else {}
    net_cfg = _config.get("network", {}) if _config else {}
    det_cfg = _config.get("detection", {}) if _config else {}

    return jsonify({
        "alerts": stats,
        "engine": engine_stats,
        "uptime": _get_uptime(),
        "interface": net_cfg.get("interface", "unknown"),
        "bpf_filter": net_cfg.get("bpf_filter", ""),
        "rules": {
            "port_scan": det_cfg.get("port_scan", {}),
            "cleartext_creds": det_cfg.get("cleartext_creds", {}),
            "icmp_flood": det_cfg.get("icmp_flood", {}),
            "ssh_brute_force": det_cfg.get("ssh_brute_force", {}),
            "http_threats": det_cfg.get("http_threats", {}),
        },
        "log_file": _reporter.log_file_path if _reporter else "",
    })


@app.route("/api/alerts")
def api_alerts():
    """Return alert history as JSON."""
    history = _reporter.get_alert_history() if _reporter else []
    return jsonify({"alerts": history})


@app.route("/api/traffic")
def api_traffic():
    """Return recent traffic samples as JSON."""
    samples = _engine.get_traffic_samples() if _engine else []
    return jsonify({"packets": samples})
@app.route("/api/timeseries")
def api_timeseries():
    """Return recent timeseries data for traffic graphs."""
    if not _engine:
        return jsonify({"data": []})
    
    return jsonify({
        "data": _engine.get_timeseries()
    })



# ── SocketIO events ───────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    """Send initial data on client connect."""
    logger.debug("Dashboard client connected")


@socketio.on("request_stats")
def handle_request_stats():
    """Client requests a stats refresh."""
    stats = _reporter.get_stats() if _reporter else {}
    engine_stats = {}
    if _engine:
        engine_stats = {
            "packets_captured": _engine.packets_captured,
            "packets_processed": _engine.packets_processed,
            "packets_dropped": _engine.packets_dropped,
        }
    socketio.emit("stats_update", {
        "alerts": stats,
        "engine": engine_stats,
        "uptime": _get_uptime(),
    })


# ── Dashboard callback (called by ReportingEngine) ────────────────────────

def emit_alert(alert_dict: dict):
    """Push an alert to all connected dashboard clients via WebSocket."""
    socketio.emit("new_alert", alert_dict)

    # Also push updated stats
    if _reporter:
        stats = _reporter.get_stats()
        engine_stats = {}
        if _engine:
            engine_stats = {
                "packets_captured": _engine.packets_captured,
                "packets_processed": _engine.packets_processed,
                "packets_dropped": _engine.packets_dropped,
            }
        socketio.emit("stats_update", {
            "alerts": stats,
            "engine": engine_stats,
            "uptime": _get_uptime(),
        })


# ── Start/Stop ─────────────────────────────────────────────────────────────

def start_dashboard(config: dict, reporter, engine):
    """
    Start the dashboard in a background thread.

    Args:
        config: V-IDS configuration dictionary
        reporter: ReportingEngine instance
        engine: IngestionEngine instance
    """
    global _reporter, _engine, _config, _start_time

    _reporter = reporter
    _engine = engine
    _config = config
    _start_time = time.time()

    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "0.0.0.0")
    port = dash_cfg.get("port", 8847)

    # Register the alert callback with the reporting engine
    reporter.set_dashboard_callback(emit_alert)

    # Register the traffic callback with the ingestion engine
    def emit_traffic(sample: dict):
        socketio.emit("traffic_packet", sample)
    engine.set_traffic_callback(emit_traffic)

    def _run_server():
        """Run the Flask-SocketIO server."""
        logger.info("Dashboard starting on http://%s:%d", host, port)
        socketio.run(
            app,
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
            log_output=False,
        )

    thread = threading.Thread(target=_run_server, name="v-ids-dashboard", daemon=True)
    thread.start()

    return thread
