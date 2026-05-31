#!/usr/bin/env bash
# ============================================================
# V-IDS — Universal Bootstrap & Run Script
# ============================================================
# Detects Linux distribution, installs system dependencies,
# sets up Python virtual environment, installs pip packages,
# and launches V-IDS.
#
# Supported: Debian/Ubuntu, Arch, Fedora/RHEL/CentOS, openSUSE, Alpine
#
# Usage:
#   sudo ./run.sh                      # Auto-detect interface
#   sudo ./run.sh -i eth0 --verbose    # Specify interface
#   sudo ./run.sh --no-dashboard       # Terminal only
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"

# ── Colors ──────────────────────────────────────────────────
RED='\033[1;91m'
GREEN='\033[1;92m'
CYAN='\033[1;96m'
YELLOW='\033[1;93m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

_log()  { echo -e "${CYAN}[V-IDS]${RESET} $*"; }
_ok()   { echo -e "${GREEN}  ✓${RESET} $*"; }
_warn() { echo -e "${YELLOW}  ⚠${RESET} $*"; }
_err()  { echo -e "${RED}  ✗${RESET} $*"; }

# ── Check root ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _err "V-IDS requires root privileges for raw socket access."
    echo -e "    Run with: ${BOLD}sudo ./run.sh${RESET}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════
# OS Detection & System Dependency Installation
# ═══════════════════════════════════════════════════════════════

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID}"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

install_system_deps() {
    local distro="$1"
    _log "Detected distribution: ${BOLD}${distro}${RESET}"

    case "${distro}" in
        ubuntu|debian|linuxmint|pop|zorin|elementary|kali)
            _log "Installing system packages via apt..."
            apt-get update -qq 2>/dev/null
            apt-get install -y -qq python3 python3-venv python3-pip python3-dev \
                libffi-dev gcc 2>/dev/null
            _ok "System packages installed (apt)"
            ;;
        arch|manjaro|endeavouros|garuda|artix)
            _log "Installing system packages via pacman..."
            pacman -Sy --noconfirm --needed python python-pip python-virtualenv \
                libffi gcc 2>/dev/null
            _ok "System packages installed (pacman)"
            ;;
        fedora)
            _log "Installing system packages via dnf..."
            dnf install -y -q python3 python3-pip python3-venv python3-devel \
                libffi-devel gcc 2>/dev/null
            _ok "System packages installed (dnf)"
            ;;
        centos|rhel|rocky|almalinux|ol)
            _log "Installing system packages via dnf/yum..."
            if command -v dnf &>/dev/null; then
                dnf install -y -q python3 python3-pip python3-devel \
                    libffi-devel gcc 2>/dev/null
            else
                yum install -y -q python3 python3-pip python3-devel \
                    libffi-devel gcc 2>/dev/null
            fi
            _ok "System packages installed"
            ;;
        opensuse*|sles)
            _log "Installing system packages via zypper..."
            zypper -n install -y python3 python3-pip python3-virtualenv \
                python3-devel libffi-devel gcc 2>/dev/null
            _ok "System packages installed (zypper)"
            ;;
        alpine)
            _log "Installing system packages via apk..."
            apk add --no-cache python3 py3-pip py3-virtualenv \
                python3-dev libffi-dev gcc musl-dev 2>/dev/null
            _ok "System packages installed (apk)"
            ;;
        void)
            _log "Installing system packages via xbps..."
            xbps-install -Sy python3 python3-pip python3-virtualenv \
                python3-devel libffi-devel gcc 2>/dev/null
            _ok "System packages installed (xbps)"
            ;;
        *)
            _warn "Unknown distribution: ${distro}"
            _warn "Please ensure python3, python3-venv, and pip are installed."
            ;;
    esac
}

# ── Detect Python ───────────────────────────────────────────
find_python() {
    for candidate in python3 python; do
        if command -v "${candidate}" &>/dev/null; then
            local ver
            ver=$("${candidate}" --version 2>&1 | awk '{print $2}')
            local major
            major=$(echo "${ver}" | cut -d. -f1)
            if [[ "${major}" -ge 3 ]]; then
                echo "${candidate}"
                return 0
            fi
        fi
    done
    return 1
}

# ═══════════════════════════════════════════════════════════════
# Setup
# ═══════════════════════════════════════════════════════════════

echo ""
echo -e "  ${BOLD}V-IDS${RESET}  ${DIM}Bootstrap${RESET}"
echo ""

# ── Step 1: Check if Python 3 exists ─────────────────────────
PYTHON_BIN=$(find_python 2>/dev/null || true)

if [[ -z "${PYTHON_BIN}" ]]; then
    _log "Python 3 not found. Installing..."
    DISTRO=$(detect_distro)
    install_system_deps "${DISTRO}"
    PYTHON_BIN=$(find_python 2>/dev/null || true)
    if [[ -z "${PYTHON_BIN}" ]]; then
        _err "Failed to install Python 3."
        exit 1
    fi
else
    PYTHON_VERSION=$("${PYTHON_BIN}" --version 2>&1 | awk '{print $2}')
    _ok "Python ${PYTHON_VERSION}"
fi

# ── Step 2: Check for venv module ────────────────────────────
if ! "${PYTHON_BIN}" -m venv --help &>/dev/null 2>&1; then
    _warn "venv module missing, installing..."
    DISTRO=$(detect_distro)
    install_system_deps "${DISTRO}"
fi

# ── Step 3: Create virtual environment ───────────────────────
if [[ ! -d "${VENV_DIR}" ]]; then
    _log "Creating venv..."
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    _ok "Virtual environment ready"
else
    _ok "Virtual environment"
fi

# ── Step 4: Activate venv ────────────────────────────────────
source "${VENV_DIR}/bin/activate"

# ── Step 5: Install/upgrade pip packages ─────────────────────
NEEDS_INSTALL=false

if ! python3 -c "import scapy" &>/dev/null 2>&1 \
   || ! python3 -c "import flask" &>/dev/null 2>&1 \
   || ! python3 -c "import flask_socketio" &>/dev/null 2>&1; then
    NEEDS_INSTALL=true
fi

if [[ "${NEEDS_INSTALL}" == "true" ]]; then
    _log "Installing packages..."
    pip install --quiet --upgrade pip 2>/dev/null
    pip install --quiet -r "${REQUIREMENTS}" 2>&1 | while IFS= read -r line; do
        [[ -n "$line" ]] && echo -e "    ${DIM}${line}${RESET}"
    done
    _ok "Dependencies installed"
else
    _ok "Dependencies"
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# Launch
# ═══════════════════════════════════════════════════════════════

exec python3 -m src.main "$@"

