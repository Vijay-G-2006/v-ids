"""
V-IDS — Main Entry Point
==========================
CLI interface, initialization, and orchestration for the V-IDS
intrusion detection system. Auto-detects network interfaces and
launches the real-time web dashboard.

Usage:
  sudo ./run.sh                        # Auto-detect interface
  sudo ./run.sh -i wlp2s0 --verbose    # Specify interface
  sudo ./run.sh --no-dashboard          # Terminal only
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading

from src import __version__
from src.config_loader import load_config, apply_cli_overrides
from src.analysis import AnalysisEngine
from src.reporting import ReportingEngine
from src.ingestion import IngestionEngine

# ── Module-level logger ────────────────────────────────────────────────────
logger = logging.getLogger("v-ids")


# ── ANSI helpers ───────────────────────────────────────────────────────────
C = "\033[1;96m"    # Cyan
G = "\033[1;92m"    # Green
Y = "\033[1;93m"    # Yellow
R = "\033[1;91m"    # Red
B = "\033[1m"       # Bold
D = "\033[2m"       # Dim
W = "\033[0;97m"    # White
RST = "\033[0m"     # Reset


def _divider(char="─", width=56):
    return f"{D}{char * width}{RST}"


def _print_banner():
    """Print a clean, minimal startup banner."""
    print()
    print(f"  {C}V-IDS{RST}  {D}v{__version__}{RST}")
    print(f"  {D}Intrusion Detection System{RST}")
    print()


def _print_status(config: dict):
    """Print a clean configuration summary."""
    det = config.get("detection", {})
    ps = det.get("port_scan", {})
    cc = det.get("cleartext_creds", {})
    ic = det.get("icmp_flood", {})
    sb = det.get("ssh_brute_force", {})
    ht = det.get("http_threats", {})
    dash = config.get("dashboard", {})
    net = config.get("network", {})
    log = config.get("logging", {})
    eng = config.get("engine", {})

    dash_enabled = dash.get("enabled", True)
    dash_port = dash.get("port", 8847)

    def _on_off(cfg, detail=""):
        if cfg.get("enabled", True):
            return f"{G}ON{RST}  {D}{detail}{RST}" if detail else f"{G}ON{RST}"
        return f"{R}OFF{RST}"

    print(_divider())
    print(f"  {B}NETWORK{RST}")
    print(f"    Interface     {W}{net.get('interface', '—')}{RST}")
    bpf = net.get("bpf_filter", "")
    print(f"    BPF Filter    {W}{bpf if bpf else '—'}{RST}")
    print(f"    Queue         {W}{eng.get('queue_size', 10000)}{RST}")
    print()

    print(f"  {B}LOGGING{RST}")
    print(f"    Log File      {W}{log.get('log_file', '—')}{RST}")
    print(f"    Level         {W}{log.get('log_level', 'INFO')}{RST}")
    print()

    # Count active rules
    rules = [ps, cc, ic, sb, ht]
    active = sum(1 for r in rules if r.get("enabled", True))

    print(f"  {B}RULES{RST}  {D}({active}/5 active){RST}")

    ps_detail = ">{} ports / {}s".format(ps.get("unique_ports_threshold", 15), ps.get("window_seconds", 60))
    cc_ports = ", ".join(str(p) for p in cc.get("monitored_ports", [])[:4])
    cc_detail = "ports " + cc_ports + "..."
    ic_detail = ">{} / {}s".format(ic.get("icmp_threshold", 100), ic.get("window_seconds", 10))
    sb_detail = ">{} / {}s".format(sb.get("attempt_threshold", 10), sb.get("window_seconds", 60))

    print(f"    Port Scan     {_on_off(ps, ps_detail)}")
    print(f"    Cleartext     {_on_off(cc, cc_detail)}")
    print(f"    ICMP Flood    {_on_off(ic, ic_detail)}")
    print(f"    SSH Brute     {_on_off(sb, sb_detail)}")
    print(f"    HTTP Threats  {_on_off(ht, 'SQLi XSS traversal RCE')}")
    print()

    print(f"  {B}DASHBOARD{RST}")
    if dash_enabled:
        print(f"    Status        {G}ACTIVE{RST}")
        print(f"    URL           {C}http://localhost:{dash_port}{RST}")
    else:
        print(f"    Status        {D}Disabled{RST}")
    print(_divider())
    print()
    print(f"  {G}▸{RST} {B}V-IDS is monitoring.{RST} Press {B}Ctrl+C{RST} to stop.")
    print()


# ── Interface Detection ──────────────────────────────────────────────────

def detect_interfaces() -> list:
    """
    Detect available network interfaces from /sys/class/net/.
    Returns a list of (name, state, mac) tuples, excluding loopback.
    """
    interfaces = []
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return interfaces

    for iface in sorted(os.listdir(net_dir)):
        if iface == "lo":
            continue
        try:
            state_file = os.path.join(net_dir, iface, "operstate")
            state = "unknown"
            if os.path.isfile(state_file):
                with open(state_file) as f:
                    state = f.read().strip()
            mac_file = os.path.join(net_dir, iface, "address")
            mac = ""
            if os.path.isfile(mac_file):
                with open(mac_file) as f:
                    mac = f.read().strip()
            interfaces.append((iface, state, mac))
        except (OSError, IOError):
            interfaces.append((iface, "unknown", ""))
    return interfaces


def prompt_interface_selection() -> str:
    """
    Display detected interfaces and let the user select one.
    Returns the chosen interface name.
    """
    interfaces = detect_interfaces()
    if not interfaces:
        print(f"\n  {R}ERROR{RST}  No network interfaces found.", file=sys.stderr)
        print(f"         Use: {B}sudo ./run.sh -i <interface>{RST}\n", file=sys.stderr)
        sys.exit(1)

    if len(interfaces) == 1:
        chosen = interfaces[0][0]
        print(f"  {G}▸{RST} Auto-selected: {B}{chosen}{RST}")
        return chosen

    print()
    print(f"  {B}SELECT INTERFACE{RST}")
    print()
    for i, (name, state, mac) in enumerate(interfaces, 1):
        dot = f"{G}●{RST}" if state == "up" else f"{R}●{RST}"
        mac_str = f"{D}{mac}{RST}" if mac and mac != "00:00:00:00:00:00" else ""
        print(f"    {B}{i}{RST}  {dot} {W}{name:<14}{RST}  {state:<8}  {mac_str}")
    print()

    while True:
        try:
            raw = input(f"  {B}Choice [1-{len(interfaces)}]:{RST} ")
            idx = int(raw.strip()) - 1
            if 0 <= idx < len(interfaces):
                chosen = interfaces[idx][0]
                print(f"  {G}▸{RST} Selected: {B}{chosen}{RST}\n")
                return chosen
            print(f"    {R}Enter 1-{len(interfaces)}{RST}")
        except (ValueError, EOFError):
            print(f"    {R}Enter 1-{len(interfaces)}{RST}")
        except KeyboardInterrupt:
            print("\n")
            sys.exit(0)


def _setup_logging(config: dict) -> None:
    """Configure the root logger for the application."""
    log_level = config.get("logging", {}).get("log_level", "INFO")
    level = getattr(logging, log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger("v-ids")
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)

    # Suppress noisy loggers
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("engineio").setLevel(logging.ERROR)
    logging.getLogger("socketio").setLevel(logging.ERROR)


def _check_privileges() -> None:
    """Verify the script is running with sufficient privileges."""
    if os.geteuid() != 0:
        print(f"\n  {R}ERROR{RST}  Root privileges required for raw sockets.", file=sys.stderr)
        print(f"         Run: {B}sudo ./run.sh{RST}\n", file=sys.stderr)
        sys.exit(1)


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="v-ids",
        description="V-IDS — Lightweight Host-Based Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo ./run.sh                         # Auto-detect interface\n"
            "  sudo ./run.sh -i wlp2s0 --verbose     # Specify interface\n"
            "  sudo ./run.sh --no-dashboard           # Terminal only\n"
        ),
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (auto-detect if omitted)")
    parser.add_argument("-l", "--log-file", default=None,
                        help="Alert log file path (default: /var/log/v-ids.log)")
    parser.add_argument("-c", "--config", default="config/default.yaml",
                        help="YAML config file (default: config/default.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Enable debug output")
    parser.add_argument("--no-color", action="store_true", default=False,
                        help="Disable colorized output")
    parser.add_argument("--no-dashboard", action="store_true", default=False,
                        help="Disable web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=None,
                        help="Dashboard port (default: 8847)")
    parser.add_argument("--version", action="version", version=f"v-ids {__version__}")
    return parser.parse_args()


def main():
    """Main entry point for V-IDS."""
    # ── Parse CLI ───────────────────────────────────────────────────────
    args = _parse_args()

    # ── Check privileges ────────────────────────────────────────────────
    _check_privileges()

    # ── Load config ─────────────────────────────────────────────────────
    config = load_config(args.config)
    config = apply_cli_overrides(
        config,
        interface=args.interface,
        log_file=args.log_file,
        verbose=args.verbose,
    )

    if args.no_color:
        config["logging"]["colorize_stdout"] = False
    if args.no_dashboard:
        config["dashboard"]["enabled"] = False
    if args.dashboard_port:
        config["dashboard"]["port"] = args.dashboard_port

    # ── Interface detection ─────────────────────────────────────────────
    if not config["network"]["interface"]:
        config["network"]["interface"] = prompt_interface_selection()

    # ── Setup logging ───────────────────────────────────────────────────
    _setup_logging(config)

    # ── Print banner + status ───────────────────────────────────────────
    _print_banner()
    _print_status(config)

    # ── Initialize engines ──────────────────────────────────────────────
    analysis = AnalysisEngine(config)
    reporter = ReportingEngine(config)
    engine = IngestionEngine(config, analysis, reporter)

    # ── Start dashboard ─────────────────────────────────────────────────
    if config.get("dashboard", {}).get("enabled", True):
        try:
            from src.dashboard.app import start_dashboard
            start_dashboard(config, reporter, engine)
        except ImportError as e:
            logger.warning("Dashboard dependencies not available: %s", e)
        except Exception as e:
            logger.warning("Dashboard failed to start: %s", e)

    # ── Signal handlers for graceful shutdown ───────────────────────────
    def _shutdown_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s — shutting down...", sig_name)
        engine.stop()

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # ── Periodic status ticker ──────────────────────────────────────────
    _ticker_stop = threading.Event()

    def _status_ticker():
        """Print a compact status line every 30 seconds."""
        interval = 30
        last_alert_count = 0
        last_pkt_count = 0
        while not _ticker_stop.is_set():
            _ticker_stop.wait(interval)
            if _ticker_stop.is_set():
                break
            captured = engine.packets_captured
            processed = engine.packets_processed
            dropped = engine.packets_dropped
            bytesc = engine.bytes_captured
            alerts = reporter.alert_count
            new_alerts = alerts - last_alert_count
            pps = (processed - last_pkt_count) / interval
            last_alert_count = alerts
            last_pkt_count = processed
            qd = engine._packet_queue.qsize() if hasattr(engine, '_packet_queue') else 0

            def _fmt(n):
                if n >= 1_000_000:
                    return "{:.1f}M".format(n / 1_000_000)
                if n >= 1_000:
                    return "{:.1f}K".format(n / 1_000)
                return str(n)

            def _fmtb(b):
                if b >= 1_073_741_824:
                    return "{:.1f}GB".format(b / 1_073_741_824)
                if b >= 1_048_576:
                    return "{:.1f}MB".format(b / 1_048_576)
                if b >= 1024:
                    return "{:.1f}KB".format(b / 1024)
                return "{}B".format(b)

            ts = time.strftime("%H:%M:%S")
            alert_str = " (+{})".format(new_alerts) if new_alerts > 0 else ""
            print(
                f"  {D}{ts}{RST}  "
                f"pkts {W}{_fmt(processed)}{RST}  "
                f"{D}{pps:.0f} p/s{RST}  "
                f"{_fmtb(bytesc)}  "
                f"Q:{qd}  "
                f"drop {W}{_fmt(dropped)}{RST}  "
                f"alerts {C}{alerts}{alert_str}{RST}",
                flush=True,
            )

    ticker_thread = threading.Thread(target=_status_ticker, name="v-ids-ticker", daemon=True)
    ticker_thread.start()

    # ── Start the engine ────────────────────────────────────────────────
    try:
        engine.start()
        engine.wait()
    except KeyboardInterrupt:
        pass
    finally:
        _ticker_stop.set()
        engine.stop()
        reporter.print_stats()
        reporter.shutdown()
        logger.info("V-IDS stopped.")


if __name__ == "__main__":
    main()
