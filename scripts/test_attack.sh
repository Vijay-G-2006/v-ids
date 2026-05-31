#!/usr/bin/env bash
# ============================================================
# V-IDS Self-Test Attack Script
# ============================================================
# Run these from a second machine/VM targeting your host.
# Requires: nmap, hping3, ftp client
#
# Usage:
#   chmod +x scripts/test_attack.sh
#   sudo ./scripts/test_attack.sh <target-ip>
# ============================================================

set -euo pipefail

TARGET_IP="${1:-}"

if [[ -z "$TARGET_IP" ]]; then
    echo "Usage: sudo $0 <target-ip>"
    echo ""
    echo "Examples:"
    echo "  sudo $0 192.168.1.10"
    echo "  sudo $0 10.0.0.5"
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo "  V-IDS Self-Test Suite"
echo "  Target: $TARGET_IP"
echo "════════════════════════════════════════════════════════"
echo ""

# ── Test 1: SYN Port Scan ──────────────────────────────────
echo "[TEST 1/3] SYN Port Scan (nmap)"
echo "  Sending TCP SYN scan to ports 1-1000..."
echo "  Expected: HIGH severity PORT_SCAN alert"
echo ""

if command -v nmap &> /dev/null; then
    sudo nmap -sS -p 1-1000 "$TARGET_IP" --min-rate 1000 -T4 2>/dev/null | tail -5
    echo ""
    echo "  ✅ SYN scan complete. Check V-IDS output for PORT_SCAN alert."
else
    echo "  ⚠️  nmap not found. Install with: sudo apt install nmap"
fi

echo ""
sleep 2

# ── Test 2: ICMP Flood ─────────────────────────────────────
echo "[TEST 2/3] ICMP Flood (hping3)"
echo "  Sending 100 ICMP echo requests in rapid succession..."
echo "  Expected: MEDIUM severity ICMP_FLOOD alert"
echo ""

if command -v hping3 &> /dev/null; then
    sudo hping3 --icmp -c 100 --fast "$TARGET_IP" 2>/dev/null | tail -3
    echo ""
    echo "  ✅ ICMP flood complete. Check V-IDS output for ICMP_FLOOD alert."
elif command -v ping &> /dev/null; then
    echo "  hping3 not found, using ping flood..."
    sudo ping -f -c 100 "$TARGET_IP" 2>/dev/null | tail -3
    echo ""
    echo "  ✅ Ping flood complete. Check V-IDS output for ICMP_FLOOD alert."
else
    echo "  ⚠️  Neither hping3 nor ping found."
fi

echo ""
sleep 2

# ── Test 3: Cleartext FTP ──────────────────────────────────
echo "[TEST 3/3] Cleartext FTP Credentials"
echo "  Attempting FTP login to $TARGET_IP..."
echo "  Expected: CRITICAL severity CLEARTEXT_CREDS alert"
echo ""
echo "  NOTE: You need an FTP server running on the target."
echo "  Quick setup: sudo apt install vsftpd && sudo systemctl start vsftpd"
echo ""

if command -v ftp &> /dev/null; then
    echo "  Sending FTP login attempt..."
    (echo "USER testuser"; echo "PASS testpassword123"; echo "QUIT") | ftp -n "$TARGET_IP" 21 2>/dev/null || true
    echo ""
    echo "  ✅ FTP test complete. Check V-IDS output for CLEARTEXT_CREDS alert."
else
    echo "  ⚠️  ftp client not found. Install with: sudo apt install ftp"
    echo "  Manual test: telnet $TARGET_IP 21, then type 'USER admin' and 'PASS secret'"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  All tests complete!"
echo "  Check your V-IDS terminal/log for triggered alerts."
echo "════════════════════════════════════════════════════════"
