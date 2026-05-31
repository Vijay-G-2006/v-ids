# V-IDS Changelog — Development Flow Monitor

> Step-by-step record of all functionality and changes made during development.

---

## [1.0.0] — 2026-05-31

### Step 1: Project Scaffolding
**What was done:**
- Created the project directory structure with `src/`, `tests/`, `config/`, and `scripts/` directories
- Created `requirements.txt` with three dependencies: `scapy>=2.5.0`, `pyyaml>=6.0`, `colorama>=0.4.6`
- Created `setup.py` with package metadata and `console_scripts` entry point for pip-installable usage
- Created `src/__init__.py` with version metadata (`__version__ = "1.0.0"`)

**Why:** Establishes a clean, Pythonic project structure with proper packaging support before any functional code is written.

**Files created:** `requirements.txt`, `setup.py`, `src/__init__.py`, `tests/__init__.py`

---

### Step 2: Configuration System
**What was done:**
- Created `config/default.yaml` with all tunable parameters organized into sections:
  - `network` — interface name, BPF filter
  - `logging` — log file paths (primary + fallback), log level, colorization, rate limiting
  - `detection` — individual rule thresholds (port scan: 20 SYN/10s, cleartext: ports 21/80, ICMP: 50/5s)
  - `engine` — queue size (10000), cleanup interval (60s)
- Created `src/config_loader.py` with:
  - `DEFAULT_CONFIG` — hardcoded fallback so the system runs even without a YAML file
  - `_deep_merge()` — recursive dict merge so user config only needs to override specific values
  - `load_config()` — loads YAML with safe_load, handles missing files and parse errors
  - `apply_cli_overrides()` — layers CLI arguments on top of the config

**Why:** Separates configuration from code. Users can tune thresholds without editing source. Deep merge means partial configs work correctly.

**Files created:** `config/default.yaml`, `src/config_loader.py`

---

### Step 3: Dissection Engine (Protocol Parsing)
**What was done:**
- Created `src/dissection.py` implementing REQ-1.3:
  - `PacketInfo` dataclass — structured representation with fields: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `tcp_flags`, `payload`, `packet_size`, `is_valid`
  - `dissect_packet()` — takes a raw Scapy `Packet`, checks for IP layer, extracts:
    - IPv4 source/dest addresses
    - TCP sport/dport and flags (SYN, ACK, FIN, RST, PSH, URG)
    - UDP sport/dport
    - ICMP type/code (stored in sport/dport fields for consistent downstream access)
    - Raw payload bytes from the `Raw` layer
  - `format_flags()` — converts compact flag strings ("SA") to human-readable ("SYN-ACK")
  - `PROTOCOL_MAP` — maps protocol numbers (1→ICMP, 6→TCP, 17→UDP)
  - Non-IP packets (ARP, pure L2) return `None` and are silently skipped

**Why:** The dissection engine is the foundation — all downstream analysis operates on PacketInfo, not raw Scapy objects. This decoupling makes the analysis rules testable without real packets.

**Files created:** `src/dissection.py`

---

### Step 4: Analysis Engine (Threat Detection Rules)
**What was done:**
- Created `src/analysis.py` implementing REQ-2.1, REQ-2.2, REQ-2.3:
  - `Alert` dataclass — represents a triggered alert with timestamp, severity, rule name, IPs, ports, message
  - `BaseRule` abstract class — defines `evaluate()` and `cleanup()` interface with thread-safe locking
  
  - **PortScanRule (REQ-2.1):**
    - Tracks SYN timestamps per source IP using `defaultdict(list)`
    - Only counts SYN packets without ACK flag (pure SYN, not SYN-ACK)
    - Rolling window pruning: removes timestamps older than `window_seconds` on each evaluation
    - Rate-limits alerts: won't re-alert for the same IP within one window period
    - Severity: HIGH
  
  - **CleartextRule (REQ-2.2):**
    - Inspects TCP payload on monitored ports (21, 80)
    - Case-insensitive pattern matching for: "USER ", "PASS ", "password=", "login=", "Authorization: Basic"
    - Decodes payload as UTF-8 with `errors="ignore"` to handle binary data safely
    - Rate-limits per (src_ip, dst_port) tuple
    - Severity: CRITICAL
  
  - **ICMPFloodRule (REQ-2.3):**
    - Only tracks ICMP Echo Requests (type 8)
    - Same rolling window + rate-limiting pattern as PortScanRule
    - Severity: MEDIUM
  
  - `AnalysisEngine` — orchestrator that:
    - Initializes all three rules
    - Passes each packet through every enabled rule via `analyze()`
    - Catches exceptions from individual rules so one failure doesn't crash the pipeline
    - Provides `cleanup_all()` for periodic state pruning

**Why:** Each rule is isolated, testable, and thread-safe. The BaseRule pattern makes adding new rules easy — just inherit and implement evaluate/cleanup.

**Files created:** `src/analysis.py`

---

### Step 5: Reporting Engine (Logging & Output)
**What was done:**
- Created `src/reporting.py` implementing REQ-3.1 and REQ-3.2:
  - `format_alert()` — produces structured log lines: `[TIMESTAMP] [SEVERITY] [RULE_NAME] - Src: IP:Port -> Dst: IP:Port`
  - `format_alert_colorized()` — same format with ANSI colors and severity icons (🔴🟠🟡🟢⚪)
  - `ReportingEngine` class:
    - **Dual output:** colorized stdout + plain-text file logging
    - **Smart log path resolution:** tries primary path (`/var/log/sentinel-ids.log`), falls back to local path (`./sentinel-ids.log`) if permissions denied
    - **Line-buffered file writing:** `buffering=1` ensures alerts are flushed immediately
    - **Statistics tracking:** counts total alerts and alerts per severity level
    - `print_stats()` — prints a formatted summary table on shutdown
    - `shutdown()` — cleanly closes file handles

**Why:** The dual output approach means the terminal stays informative (with colors) while the log file stays parseable (plain text). Fallback paths mean V-IDS works even without root write access to `/var/log/`.

**Files created:** `src/reporting.py`

---

### Step 6: Ingestion Engine (Packet Capture)
**What was done:**
- Created `src/ingestion.py` implementing REQ-1.1 and REQ-1.2:
  - **Three-thread architecture:**
    1. **Capture thread** — runs `scapy.sniff()` with optional BPF filter, pushes packets into a bounded `queue.Queue`
    2. **Worker thread** — consumes packets from queue, runs: dissection → analysis → reporting pipeline
    3. **Cleanup thread** — periodically calls `analysis.cleanup_all()` to prune stale state
  - **Queue-based decoupling:** capture never blocks on analysis. If the queue fills (default 10000), packets are dropped with a logged warning
  - **Graceful shutdown:** `threading.Event` signal stops all threads cleanly
  - **Error handling:**
    - `PermissionError` → clear "run with sudo" message
    - `OSError("No such device")` → "check interface name" message
    - `queue.Full` → counted as dropped packet, warned every 1000 drops
  - **Statistics:** tracks captured, processed, and dropped packet counts
  - `wait()` — blocks main thread until stop event is set
  - `store=0` in sniff() — packets are not stored in Scapy's memory (we use our own queue)

**Why:** The queue architecture is critical — without it, slow analysis would cause the capture thread to miss packets. The bounded queue also prevents memory exhaustion under flood conditions.

**Files created:** `src/ingestion.py`

---

### Step 7: CLI Entry Point
**What was done:**
- Created `src/main.py` — the main orchestration module:
  - **CLI with argparse:** `-i/--interface` (required), `-l/--log-file`, `-c/--config`, `-v/--verbose`, `--no-color`, `--version`
  - **Privilege check:** verifies `euid == 0` before attempting raw sockets
  - **ASCII banner:** styled startup banner with version number
  - **Status display:** shows active config (interface, BPF filter, log path, rule status with thresholds)
  - **Startup sequence:** parse CLI → check root → load config → setup logging → print banner → init engines → register signals → start capture → wait
  - **Signal handling:** SIGTERM and SIGINT trigger graceful shutdown (stops engine, prints stats, closes files)
  - **Application logging:** separate from alert logging — goes to stderr with timestamp/level/module format

**Why:** The entry point ties everything together. Signal handling ensures clean shutdown even when killed by systemd.

**Files created:** `src/main.py`

---

### Step 8: Daemonization (systemd)
**What was done:**
- Created `sentinel-ids.service` — systemd unit file:
  - `Type=simple` — Python script runs in foreground, systemd manages lifecycle
  - `After=network-online.target` — waits for network before starting
  - `Restart=on-failure` with `RestartSec=5` — auto-restarts on crash
  - Security hardening: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`
  - `ReadWritePaths=/var/log/sentinel-ids.log` — only writable path
  - Journal integration for `journalctl -u sentinel-ids`

**Why:** systemd makes V-IDS a proper managed service — auto-start on boot, auto-restart on crash, log aggregation via journal.

**Files created:** `sentinel-ids.service`

---

### Step 9: Test Suite
**What was done:**
- Created comprehensive unit tests using pytest and mock objects:
  - `tests/test_dissection.py` (12 tests):
    - TCP SYN packet parsing, UDP parsing, ICMP parsing
    - Payload extraction, non-IP packet handling
    - Packet size capture, flag formatting (SYN, SYN-ACK, FIN-ACK, RST)
  - `tests/test_analysis.py` (16 tests):
    - PortScanRule: below threshold, at threshold, SYN-ACK ignored, non-TCP ignored, separate IP tracking, window expiry, cleanup
    - CleartextRule: FTP USER/PASS, HTTP password field, HTTPS ignored, no payload, safe payload, rate limiting
    - ICMPFloodRule: below threshold, at threshold, non-echo ignored, cleanup
    - AnalysisEngine: rule initialization, alert generation, cleanup
  - `tests/test_reporting.py` (9 tests):
    - Port formatting (numeric, None, zero)
    - Plain-text format (structure, timestamp, ICMP N/A, severity labels)
    - Colorized format (ANSI codes, message inclusion, all severity levels)

**Why:** Tests use mock Scapy packets and raw PacketInfo objects — no root required, no network access needed. This makes CI/CD possible.

**Files created:** `tests/test_dissection.py`, `tests/test_analysis.py`, `tests/test_reporting.py`

---

### Step 10: Documentation & Tooling
**What was done:**
- Created `README.md` with:
  - ASCII architecture diagram
  - Feature table with severity icons
  - Quick start guide (install → run → options)
  - Alert format examples
  - Unit test and self-attack test instructions
  - systemd installation guide
  - Full project structure listing
- Created `scripts/test_attack.sh`:
  - Automated self-test script for all three rules
  - Tests: nmap SYN scan, hping3/ping ICMP flood, FTP cleartext login
  - Graceful fallbacks when tools aren't installed
- Created this `CHANGELOG.md` as the development flow monitor

**Files created:** `README.md`, `CHANGELOG.md`, `scripts/test_attack.sh`

---

## [2.0.0] — 2026-05-31

### Step 11: Full V-IDS Rebranding
**What was done:**
- Renamed all "Sentinel" references to "V-IDS" across the entire codebase
- Renamed `sentinel-ids.service` → `v-ids.service`
- Updated log file paths: `/var/log/sentinel-ids.log` → `/var/log/v-ids.log`
- Updated setup.py entry point: `sentinel-ids` → `v-ids`
- Updated banner text, CLI help text, error messages, and descriptions
- Updated `config/default.yaml` with consistent V-IDS naming

**Why:** The project is named V-IDS — all components should reflect that consistently.

**Files modified:** `src/main.py`, `src/config_loader.py`, `src/reporting.py`, `config/default.yaml`, `setup.py`
**Files deleted:** `sentinel-ids.service`
**Files created:** `v-ids.service`

---

### Step 12: Auto-Install Bootstrap Script
**What was done:**
- Created `run.sh` — a single-command bootstrap script that:
  1. Checks root privileges (raw sockets require sudo)
  2. Detects Python 3 and prints version
  3. Creates `.venv/` virtual environment if it doesn't exist
  4. Checks if dependencies are installed (scapy, flask, flask-socketio)
  5. Installs/upgrades all dependencies from `requirements.txt` if needed
  6. Launches V-IDS with all passed CLI arguments via `exec`
- Colorized output with status indicators (✓, ⚠, ✗)
- Skip install if already up-to-date (fast startup on subsequent runs)

**Why:** Eliminates manual setup steps. Users go from `git clone` to running V-IDS with a single `sudo ./run.sh -i eth0` command.

**Files created:** `run.sh`

---

### Step 13: Web Dashboard — Backend
**What was done:**
- Created `src/dashboard/` module with Flask + Flask-SocketIO:
  - `app.py` — Flask application with:
    - **Routes:** `/` (dashboard page), `/api/stats` (JSON stats), `/api/alerts` (JSON alert history)
    - **WebSocket events:** `connect`, `request_stats`, `new_alert` (pushed to clients), `stats_update`
    - `emit_alert()` callback — registered with ReportingEngine to push alerts in real-time
    - `start_dashboard()` — launches Flask in a daemon thread
  - References to `reporter`, `engine`, and `config` set at startup
- Updated `requirements.txt` with: `flask>=3.0.0`, `flask-socketio>=5.3.0`, `gevent>=24.0`, `gevent-websocket>=0.10.1`
- Updated `src/reporting.py`:
  - Added `set_dashboard_callback()` — registers a callable for pushing alerts to the dashboard
  - Added `get_alert_history()` — returns list of serialized alerts for API
  - Added `get_stats()` — returns dict of alert statistics for API
  - Added `alert_to_dict()` — converts Alert dataclass to JSON-serializable dict
  - Added `alerts_by_rule` tracking alongside existing `alerts_by_severity`
  - Thread-safe history with `threading.Lock` and configurable max size

**Why:** The dashboard runs in a separate thread so it doesn't interfere with packet capture. WebSocket push means clients see alerts instantly without polling.

**Files created:** `src/dashboard/__init__.py`, `src/dashboard/app.py`
**Files modified:** `src/reporting.py`, `requirements.txt`

---

### Step 14: Web Dashboard — Frontend
**What was done:**
- Created `src/dashboard/templates/index.html`:
  - **Top navigation bar:** V-IDS logo (shield SVG), status pill (Monitoring/Disconnected), interface name, uptime
  - **Stats row:** 5 metric cards — Total Alerts, Critical, High, Medium, Packets Processed
  - **Two-column layout:**
    - Left: Live Alert Feed with real-time entries (severity badge, rule name, IP routing, timestamp, message)
    - Right: Detection Rules panel, Engine Status panel, Alert Distribution bars
  - Empty state with animated shield icon when no alerts detected
  - Google Fonts: Inter (UI text) + JetBrains Mono (data values)

- Created `src/dashboard/static/css/style.css`:
  - **Dark theme:** `#07080c` base with subtle gradient overlays
  - **Glassmorphism:** `backdrop-filter: blur()` on cards and topbar
  - **Severity color system:** Critical (red), High (orange), Medium (yellow), Low (green)
  - **Micro-animations:** alert slide-in, floating shield, pulsing status dots
  - **Responsive:** 3-column → 2-column → 1-column grid breakpoints
  - Custom scrollbar styling, typography system

- Created `src/dashboard/static/js/dashboard.js`:
  - **WebSocket:** Socket.IO client connects automatically, handles `new_alert` and `stats_update` events
  - **REST fallback:** fetches `/api/stats` every 5 seconds for resilience
  - **Animated counters:** numbers animate smoothly when stats update
  - **Alert feed:** prepends new alerts with slide-in animation, caps at 200 items
  - **Distribution bars:** animated width transitions based on alert counts per rule
  - **Rule status:** dynamically updates ON/OFF badges and thresholds
  - **XSS protection:** `escapeHtml()` sanitizes all injected content

**Why:** A visual dashboard transforms V-IDS from a terminal-only tool to a professional monitoring solution. Real-time WebSocket updates make it feel alive.

**Files created:** `src/dashboard/templates/index.html`, `src/dashboard/static/css/style.css`, `src/dashboard/static/js/dashboard.js`

---

### Step 15: CLI Integration & Dashboard Controls
**What was done:**
- Updated `src/main.py`:
  - Rebranded all text from "Sentinel" to "V-IDS"
  - Added CLI flags: `--no-dashboard`, `--dashboard-port`
  - Dashboard status line added to terminal STATUS_TEMPLATE output
  - Dashboard auto-starts unless `--no-dashboard` is passed
  - Suppressed noisy Flask/engineio/socketio loggers
  - Graceful fallback if dashboard deps missing
- Updated `config/default.yaml` with `dashboard:` section (host, port, max_alerts_history)
- Updated `src/config_loader.py` DEFAULT_CONFIG with dashboard defaults

**Files modified:** `src/main.py`, `config/default.yaml`, `src/config_loader.py`

---

### Step 16: Dashboard Tests
**What was done:**
- Created `tests/test_dashboard.py` (8 tests):
  - `TestAlertToDict`: serialization, None port handling
  - `TestReportingEngineDashboard`: callback invocation, history capping, stats tracking
  - `TestDashboardFlaskApp`: index page 200, `/api/stats` JSON, `/api/alerts` JSON

**Why:** Tests the entire dashboard integration — from alert serialization through Flask routes — without needing a running server or root access.

**Files created:** `tests/test_dashboard.py`

---

### Step 17: Documentation Update
**What was done:**
- Updated `README.md`:
  - Added dashboard section and architecture diagram
  - Updated quick start to use `run.sh`
  - Added dashboard CLI flags documentation
  - Updated project structure with dashboard files
- Updated `CHANGELOG.md` with v2.0.0 entries

**Files modified:** `README.md`, `CHANGELOG.md`

---

## Summary of All Files

| File | Purpose | PRD Requirement |
|---|---|---|
| `run.sh` | Auto-bootstrap & launch script | — |
| `requirements.txt` | Python dependencies | — |
| `setup.py` | Package setup | — |
| `config/default.yaml` | Tunable configuration | All REQ-2.x thresholds |
| `src/__init__.py` | Package metadata | — |
| `src/config_loader.py` | YAML config + CLI overrides | — |
| `src/dissection.py` | Protocol header parsing | REQ-1.3 |
| `src/analysis.py` | Threat detection rules | REQ-2.1, 2.2, 2.3 |
| `src/reporting.py` | Structured logging + dashboard push | REQ-3.1, 3.2 |
| `src/ingestion.py` | Packet capture engine | REQ-1.1, 1.2 |
| `src/main.py` | CLI entry point + dashboard launch | NFR (usability) |
| `src/dashboard/__init__.py` | Dashboard package | — |
| `src/dashboard/app.py` | Flask + SocketIO server | — |
| `src/dashboard/templates/index.html` | Dashboard UI | — |
| `src/dashboard/static/css/style.css` | Dashboard styles | — |
| `src/dashboard/static/js/dashboard.js` | Dashboard client logic | — |
| `v-ids.service` | systemd daemonization | Phase 4 |
| `tests/test_dissection.py` | Dissection unit tests | — |
| `tests/test_analysis.py` | Analysis rule tests | — |
| `tests/test_reporting.py` | Reporting format tests | — |
| `tests/test_dashboard.py` | Dashboard & API tests | — |
| `scripts/test_attack.sh` | Self-test attack script | Section 7 |
| `README.md` | Project documentation | — |
| `CHANGELOG.md` | Development flow log | PRD request |

