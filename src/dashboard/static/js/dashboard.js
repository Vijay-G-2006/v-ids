/**
 * V-IDS Dashboard — Client-Side Logic
 * =====================================
 * Handles WebSocket connections, real-time alert rendering,
 * live traffic feed, stats updates, and UI interactions.
 */

(function () {
    "use strict";

    // ── DOM References ──────────────────────────────────────────
    const DOM = {
        // Status
        statusPill: document.getElementById("statusPill"),
        statusText: document.querySelector(".status-text"),
        interfaceName: document.getElementById("interfaceName"),
        uptimeValue: document.getElementById("uptimeValue"),

        // Stats
        totalAlerts: document.getElementById("totalAlerts"),
        criticalAlerts: document.getElementById("criticalAlerts"),
        highAlerts: document.getElementById("highAlerts"),
        mediumAlerts: document.getElementById("mediumAlerts"),
        packetsProcessed: document.getElementById("packetsProcessed"),
        ppsRate: document.getElementById("ppsRate"),

        // Alert feed
        alertFeed: document.getElementById("alertFeed"),
        emptyState: document.getElementById("emptyState"),
        clearAlerts: document.getElementById("clearAlerts"),

        // Traffic feed
        trafficFeed: document.getElementById("trafficFeed"),
        trafficRate: document.getElementById("trafficRate"),

        // Rules
        rulePortScanThresh: document.getElementById("rulePortScanThresh"),
        rulePortScanWindow: document.getElementById("rulePortScanWindow"),
        ruleCleartextPorts: document.getElementById("ruleCleartextPorts"),
        ruleIcmpThresh: document.getElementById("ruleIcmpThresh"),
        ruleIcmpWindow: document.getElementById("ruleIcmpWindow"),
        ruleSSHThresh: document.getElementById("ruleSSHThresh"),
        ruleSSHWindow: document.getElementById("ruleSSHWindow"),

        // Engine
        engineCaptured: document.getElementById("engineCaptured"),
        engineProcessed: document.getElementById("engineProcessed"),
        engineDropped: document.getElementById("engineDropped"),
        engineBytes: document.getElementById("engineBytes"),
        engineQueue: document.getElementById("engineQueue"),
        engineLogFile: document.getElementById("engineLogFile"),

        // Chart
        trafficChartCtx: document.getElementById("trafficChart"),

        // Distribution
        barPortScan: document.getElementById("barPortScan"),
        barCleartext: document.getElementById("barCleartext"),
        barIcmpFlood: document.getElementById("barIcmpFlood"),
        barSSHBrute: document.getElementById("barSSHBrute"),
        barHTTPThreat: document.getElementById("barHTTPThreat"),
        countPortScan: document.getElementById("countPortScan"),
        countCleartext: document.getElementById("countCleartext"),
        countIcmpFlood: document.getElementById("countIcmpFlood"),
        countSSHBrute: document.getElementById("countSSHBrute"),
        countHTTPThreat: document.getElementById("countHTTPThreat"),
    };

    const MAX_FEED_ITEMS = 200;
    const MAX_TRAFFIC_ITEMS = 40;
    let alertCount = 0;
    let trafficCount = 0;
    let lastBytes = 0;

    // Protocol colors
    const PROTO_COLORS = {
        TCP: "proto-tcp",
        UDP: "proto-udp",
        ICMP: "proto-icmp",
    };

    // ── WebSocket Connection ────────────────────────────────────
    const socket = io();

    socket.on("connect", () => {
        DOM.statusPill.classList.add("active");
        DOM.statusText.textContent = "Monitoring";
        fetchInitialData();
    });

    socket.on("disconnect", () => {
        DOM.statusPill.classList.remove("active");
        DOM.statusText.textContent = "Disconnected";
    });

    socket.on("connect_error", () => {
        DOM.statusPill.classList.remove("active");
        DOM.statusText.textContent = "Error";
    });

    // ── Handle new alerts ──────────────────────────────────────
    socket.on("new_alert", (alert) => {
        addAlertToFeed(alert);
    });

    // ── Handle stats updates ───────────────────────────────────
    socket.on("stats_update", (data) => {
        updateStats(data);
    });

    // ── Handle live traffic ────────────────────────────────────
    socket.on("traffic_packet", (pkt) => {
        addTrafficPacket(pkt);
    });

    // ── Fetch initial data via REST ────────────────────────────
    function fetchInitialData() {
        fetch("/api/stats")
            .then((r) => r.json())
            .then((data) => {
                updateStatsFromAPI(data);
            })
            .catch(console.error);

        fetch("/api/alerts")
            .then((r) => r.json())
            .then((data) => {
                if (data.alerts && data.alerts.length > 0) {
                    data.alerts.forEach((alert) => addAlertToFeed(alert, true));
                }
            })
            .catch(console.error);

        // Load initial traffic samples
        fetch("/api/traffic")
            .then((r) => r.json())
            .then((data) => {
                if (data.packets && data.packets.length > 0) {
                    DOM.trafficFeed.innerHTML = "";
                    data.packets.slice(-20).forEach((pkt) => addTrafficPacket(pkt, true));
                }
            })
            .catch(console.error);

        // Load timeseries data for chart
        fetch("/api/timeseries")
            .then((r) => r.json())
            .then((data) => {
                initChart(data.data || []);
            })
            .catch(console.error);
    }

    // ── Update stats from API response ─────────────────────────
    function updateStatsFromAPI(data) {
        const alerts = data.alerts || {};
        const engine = data.engine || {};

        animateNumber(DOM.totalAlerts, alerts.total_alerts || 0);
        animateNumber(DOM.criticalAlerts, (alerts.by_severity || {}).CRITICAL || 0);
        animateNumber(DOM.highAlerts, (alerts.by_severity || {}).HIGH || 0);
        animateNumber(DOM.mediumAlerts, (alerts.by_severity || {}).MEDIUM || 0);
        animateNumber(DOM.packetsProcessed, engine.packets_processed || 0);

        if (DOM.ppsRate) DOM.ppsRate.textContent = (engine.pps || 0).toFixed(0);

        DOM.interfaceName.textContent = data.interface || "—";
        DOM.uptimeValue.textContent = data.uptime || "—";
        DOM.engineLogFile.textContent = data.log_file || "—";

        // Engine stats
        DOM.engineCaptured.textContent = formatNumber(engine.packets_captured || 0);
        DOM.engineProcessed.textContent = formatNumber(engine.packets_processed || 0);
        DOM.engineDropped.textContent = formatNumber(engine.packets_dropped || 0);
        if (DOM.engineBytes) DOM.engineBytes.textContent = formatBytes(engine.bytes_captured || 0);
        if (DOM.engineQueue) {
            const depth = engine.queue_depth || 0;
            const max = engine.queue_max || 10000;
            DOM.engineQueue.textContent = `${formatNumber(depth)} / ${formatNumber(max)}`;
        }

        // Traffic rate
        if (DOM.trafficRate && engine.bytes_captured) {
            const bytesDiff = (engine.bytes_captured || 0) - lastBytes;
            lastBytes = engine.bytes_captured || 0;
            DOM.trafficRate.textContent = formatBytes(Math.max(bytesDiff / 5, 0)) + "/s";
        }

        // Rules config
        if (data.rules) {
            const ps = data.rules.port_scan || {};
            const cc = data.rules.cleartext_creds || {};
            const ic = data.rules.icmp_flood || {};
            const sb = data.rules.ssh_brute_force || {};
            const ht = data.rules.http_threats || {};

            DOM.rulePortScanThresh.textContent = ps.unique_ports_threshold || 15;
            DOM.rulePortScanWindow.textContent = ps.window_seconds || 60;
            DOM.ruleCleartextPorts.textContent = (cc.monitored_ports || [21, 23, 80, 110, 143, 8080]).join(", ");
            DOM.ruleIcmpThresh.textContent = ic.icmp_threshold || 100;
            DOM.ruleIcmpWindow.textContent = ic.window_seconds || 10;
            if (DOM.ruleSSHThresh) DOM.ruleSSHThresh.textContent = sb.attempt_threshold || 10;
            if (DOM.ruleSSHWindow) DOM.ruleSSHWindow.textContent = sb.window_seconds || 60;

            updateRuleStatus("rulePortScan", ps.enabled !== false);
            updateRuleStatus("ruleCleartext", cc.enabled !== false);
            updateRuleStatus("ruleIcmpFlood", ic.enabled !== false);
            updateRuleStatus("ruleSSHBrute", sb.enabled !== false);
            updateRuleStatus("ruleHTTPThreat", ht.enabled !== false);
        }

        // Distribution
        updateDistribution(alerts.by_rule || {});
    }

    // ── Update stats from WebSocket push ───────────────────────
    function updateStats(data) {
        const alerts = data.alerts || {};
        const engine = data.engine || {};

        animateNumber(DOM.totalAlerts, alerts.total_alerts || 0);
        animateNumber(DOM.criticalAlerts, (alerts.by_severity || {}).CRITICAL || 0);
        animateNumber(DOM.highAlerts, (alerts.by_severity || {}).HIGH || 0);
        animateNumber(DOM.mediumAlerts, (alerts.by_severity || {}).MEDIUM || 0);
        animateNumber(DOM.packetsProcessed, engine.packets_processed || 0);

        if (DOM.ppsRate) DOM.ppsRate.textContent = (engine.pps || 0).toFixed(0);

        DOM.uptimeValue.textContent = data.uptime || "—";
        DOM.engineCaptured.textContent = formatNumber(engine.packets_captured || 0);
        DOM.engineProcessed.textContent = formatNumber(engine.packets_processed || 0);
        DOM.engineDropped.textContent = formatNumber(engine.packets_dropped || 0);
        if (DOM.engineBytes) DOM.engineBytes.textContent = formatBytes(engine.bytes_captured || 0);

        updateDistribution(alerts.by_rule || {});
    }

    // ── Add alert to the live feed ─────────────────────────────
    function addAlertToFeed(alert, isHistory) {
        if (DOM.emptyState) {
            DOM.emptyState.style.display = "none";
        }

        alertCount++;
        const sevClass = alert.severity.toLowerCase();
        const el = document.createElement("div");
        el.className = `alert-item sev-${sevClass}`;

        if (isHistory) {
            el.style.animation = "none";
        }

        el.innerHTML = `
            <span class="alert-sev-badge ${sevClass}">${alert.severity}</span>
            <div class="alert-body">
                <div class="alert-top-row">
                    <span class="alert-rule">${escapeHtml(alert.rule_name)}</span>
                    <span class="alert-time">${escapeHtml(alert.timestamp)}</span>
                </div>
                <div class="alert-route">${escapeHtml(alert.src_ip)}:${escapeHtml(alert.src_port)} → ${escapeHtml(alert.dst_ip)}:${escapeHtml(alert.dst_port)}</div>
                <div class="alert-message">${escapeHtml(alert.message)}</div>
            </div>
        `;

        DOM.alertFeed.insertBefore(el, DOM.alertFeed.firstChild);

        while (DOM.alertFeed.children.length > MAX_FEED_ITEMS) {
            DOM.alertFeed.removeChild(DOM.alertFeed.lastChild);
        }
    }

    // ── Add traffic packet to live feed ────────────────────────
    function addTrafficPacket(pkt, isHistory) {
        // Remove the "Waiting..." placeholder
        const empty = DOM.trafficFeed.querySelector(".traffic-empty");
        if (empty) empty.remove();

        trafficCount++;
        const protoClass = PROTO_COLORS[pkt.proto] || "proto-other";
        const el = document.createElement("div");
        el.className = `traffic-row ${isHistory ? "" : "traffic-new"}`;

        const sport = pkt.sport != null ? pkt.sport : "—";
        const dport = pkt.dport != null ? pkt.dport : "—";
        const flags = pkt.flags ? ` [${pkt.flags}]` : "";

        el.innerHTML = `
            <span class="traffic-proto ${protoClass}">${escapeHtml(pkt.proto)}</span>
            <span class="traffic-src">${escapeHtml(pkt.src)}:${sport}</span>
            <span class="traffic-arrow">→</span>
            <span class="traffic-dst">${escapeHtml(pkt.dst)}:${dport}</span>
            <span class="traffic-size">${pkt.size}B${flags}</span>
        `;

        DOM.trafficFeed.appendChild(el);

        // Auto-scroll to bottom
        DOM.trafficFeed.scrollTop = DOM.trafficFeed.scrollHeight;

        // Trim old entries
        while (DOM.trafficFeed.children.length > MAX_TRAFFIC_ITEMS) {
            DOM.trafficFeed.removeChild(DOM.trafficFeed.firstChild);
        }
    }

    // ── Update distribution bars ───────────────────────────────
    function updateDistribution(byRule) {
        const portScan = byRule.PORT_SCAN || 0;
        const cleartext = byRule.CLEARTEXT_CREDS || 0;
        const icmpFlood = byRule.ICMP_FLOOD || 0;
        const sshBrute = byRule.SSH_BRUTE_FORCE || 0;
        const httpThreat = byRule.HTTP_THREAT || 0;
        const total = Math.max(portScan + cleartext + icmpFlood + sshBrute + httpThreat, 1);

        DOM.barPortScan.style.width = `${(portScan / total) * 100}%`;
        DOM.barCleartext.style.width = `${(cleartext / total) * 100}%`;
        DOM.barIcmpFlood.style.width = `${(icmpFlood / total) * 100}%`;
        if (DOM.barSSHBrute) DOM.barSSHBrute.style.width = `${(sshBrute / total) * 100}%`;
        if (DOM.barHTTPThreat) DOM.barHTTPThreat.style.width = `${(httpThreat / total) * 100}%`;

        DOM.countPortScan.textContent = portScan;
        DOM.countCleartext.textContent = cleartext;
        DOM.countIcmpFlood.textContent = icmpFlood;
        if (DOM.countSSHBrute) DOM.countSSHBrute.textContent = sshBrute;
        if (DOM.countHTTPThreat) DOM.countHTTPThreat.textContent = httpThreat;
    }

    // ── Update rule status badge ───────────────────────────────
    function updateRuleStatus(ruleId, enabled) {
        const el = document.getElementById(ruleId);
        if (!el) return;
        const badge = el.querySelector(".rule-status");
        if (badge) {
            badge.textContent = enabled ? "ON" : "OFF";
            badge.className = `rule-status ${enabled ? "on" : "off"}`;
        }
    }

    // ── Clear alert feed ───────────────────────────────────────
    DOM.clearAlerts.addEventListener("click", () => {
        DOM.alertFeed.innerHTML = "";
        alertCount = 0;
        const newEmpty = document.createElement("div");
        newEmpty.className = "empty-state";
        newEmpty.id = "emptyState";
        newEmpty.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="empty-icon">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <p class="empty-title">Feed Cleared</p>
            <p class="empty-subtitle">New alerts will appear here in real-time.</p>
        `;
        DOM.alertFeed.appendChild(newEmpty);
    });

    // ── Periodic stats refresh ─────────────────────────────────
    setInterval(() => {
        fetch("/api/stats")
            .then((r) => r.json())
            .then(updateStatsFromAPI)
            .catch(() => {});
            
        fetch("/api/timeseries")
            .then((r) => r.json())
            .then((data) => {
                updateChart(data.data || []);
            })
            .catch(() => {});
    }, 5000);

    // ── Chart Logic ────────────────────────────────────────────
    let trafficChart = null;

    function initChart(data) {
        if (!DOM.trafficChartCtx) return;
        
        const labels = data.map(d => d.timestamp);
        const packets = data.map(d => d.packets);
        const alerts = data.map(d => d.alerts);

        trafficChart = new Chart(DOM.trafficChartCtx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Packets/min',
                        data: packets,
                        borderColor: '#638cff',
                        backgroundColor: 'rgba(99, 140, 255, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Alerts/min',
                        data: alerts,
                        borderColor: '#ff4d6a',
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.4,
                        borderDash: [5, 5],
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(14, 17, 24, 0.9)',
                        titleColor: '#8b8fa4',
                        bodyColor: '#e8eaed',
                        borderColor: 'rgba(255, 255, 255, 0.1)',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        display: false,
                        grid: { display: false }
                    },
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#555970',
                            font: { size: 10, family: "'JetBrains Mono', monospace" }
                        }
                    },
                    y1: {
                        type: 'linear',
                        display: false,
                        position: 'right',
                        grid: { display: false },
                        min: 0
                    }
                }
            }
        });
    }

    function updateChart(data) {
        if (!trafficChart) return;
        trafficChart.data.labels = data.map(d => d.timestamp);
        trafficChart.data.datasets[0].data = data.map(d => d.packets);
        trafficChart.data.datasets[1].data = data.map(d => d.alerts);
        trafficChart.update('none'); // Update without animation for smooth flow
    }

    // ── Utilities ──────────────────────────────────────────────
    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
        if (n >= 1000) return (n / 1000).toFixed(1) + "K";
        return String(n);
    }

    function formatBytes(bytes) {
        if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + " GB";
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
        if (bytes >= 1024) return (bytes / 1024).toFixed(1) + " KB";
        return bytes + " B";
    }

    function animateNumber(el, target) {
        if (!el) return;
        const current = parseInt(el.textContent.replace(/[^0-9]/g, ""), 10) || 0;
        if (current === target) return;

        const diff = target - current;
        const steps = Math.min(Math.abs(diff), 20);
        const stepSize = diff / steps;
        let i = 0;

        const timer = setInterval(() => {
            i++;
            const val = i === steps ? target : Math.round(current + stepSize * i);
            el.textContent = formatNumber(val);
            if (i >= steps) clearInterval(timer);
        }, 30);
    }

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.textContent = String(str);
        return div.innerHTML;
    }
})();
