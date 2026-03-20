#!/usr/bin/env bash
# install.sh — SOC Exporter installer
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --uninstall
#
# Requirements: Python 3.8+, pip3, systemd

set -euo pipefail

INSTALL_BIN="/usr/local/bin/soc-exporter"
SERVICE_FILE="/etc/systemd/system/soc-exporter.service"
SERVICE_SRC="$(dirname "$0")/soc-exporter.service"
CONFIG_DIR="/etc/soc-exporter"
CONFIG_FILE="${CONFIG_DIR}/config.json"
DATA_DIR="/var/lib/soc-exporter"
LOG_DIR="/var/log/soc-exporter"
SYSTEM_USER="soc-exporter"
SYSTEM_GROUP="soc-exporter"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || { error "Must be run as root."; exit 1; }

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
  info "Stopping and disabling service…"
  systemctl stop soc-exporter 2>/dev/null || true
  systemctl disable soc-exporter 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload

  info "Removing binary…"
  pip3 uninstall -y soc-exporter 2>/dev/null || true
  rm -f "$INSTALL_BIN"

  warn "Config/data preserved:"
  warn "  ${CONFIG_DIR}  — remove manually to purge credentials"
  warn "  ${DATA_DIR}    — remove manually to purge event buffer"
  warn "  ${LOG_DIR}     — remove manually to purge logs"
  info "Uninstall complete."
  exit 0
fi

# ---------------------------------------------------------------------------
# Python check
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
  error "python3 not found. Install python3 and retry."
  exit 1
fi

PY_VER=$(python3 -c 'import sys; print(sys.version_info >= (3, 8))')
[[ "$PY_VER" == "True" ]] || { error "Python 3.8+ required."; exit 1; }

if ! command -v pip3 &>/dev/null; then
  warn "pip3 not found — bootstrapping via ensurepip…"
  python3 -m ensurepip --upgrade || { error "Cannot install pip."; exit 1; }
fi

# ---------------------------------------------------------------------------
# System user + group
# ---------------------------------------------------------------------------
if ! getent group "$SYSTEM_GROUP" &>/dev/null; then
  info "Creating system group: $SYSTEM_GROUP"
  groupadd --system "$SYSTEM_GROUP"
fi

if ! id "$SYSTEM_USER" &>/dev/null; then
  info "Creating system user: $SYSTEM_USER"
  useradd \
    --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --gid "$SYSTEM_GROUP" \
    "$SYSTEM_USER"
fi

# Grant access to Wazuh alerts (ossec group)
if getent group ossec &>/dev/null; then
  if ! id -nG "$SYSTEM_USER" | grep -qw ossec; then
    usermod -aG ossec "$SYSTEM_USER"
    info "Added ${SYSTEM_USER} to 'ossec' group for alerts access."
  else
    info "${SYSTEM_USER} is already in 'ossec' group."
  fi
else
  warn "Group 'ossec' not found — you may need to grant read access to alerts manually."
fi

# ---------------------------------------------------------------------------
# Directories with strict permissions
# ---------------------------------------------------------------------------
info "Creating and securing directories…"

# Config dir: root:soc-exporter 750 — only service can read
mkdir -p "$CONFIG_DIR"
chown root:"$SYSTEM_GROUP" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# Data dir: soc-exporter owns it (SQLite writes)
mkdir -p "$DATA_DIR"
chown "$SYSTEM_USER":"$SYSTEM_GROUP" "$DATA_DIR"
chmod 750 "$DATA_DIR"

# Log dir: soc-exporter owns it
mkdir -p "$LOG_DIR"
chown "$SYSTEM_USER":"$SYSTEM_GROUP" "$LOG_DIR"
chmod 750 "$LOG_DIR"

# ---------------------------------------------------------------------------
# If config already exists, enforce 600
# ---------------------------------------------------------------------------
if [[ -f "$CONFIG_FILE" ]]; then
  info "Enforcing mode 600 on existing config…"
  chown root:"$SYSTEM_GROUP" "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
fi

# ---------------------------------------------------------------------------
# Install Python package
# ---------------------------------------------------------------------------
info "Installing soc-exporter Python package…"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
pip3 install --quiet --upgrade "$SCRIPT_DIR"

# Resolve installed binary path and expose at /usr/local/bin
INSTALLED_BIN="$(python3 -c "import sysconfig; print(sysconfig.get_path('scripts'))")/soc-exporter"
if [[ -f "$INSTALLED_BIN" ]]; then
  ln -sf "$INSTALLED_BIN" "$INSTALL_BIN"
elif [[ ! -f "$INSTALL_BIN" ]]; then
  warn "Could not locate installed binary at ${INSTALLED_BIN}."
  warn "Ensure ${INSTALL_BIN} is in PATH after manual installation."
fi

# ---------------------------------------------------------------------------
# systemd service
# ---------------------------------------------------------------------------
info "Installing systemd service…"
[[ -f "$SERVICE_SRC" ]] || { error "Service file not found: ${SERVICE_SRC}"; exit 1; }

cp "$SERVICE_SRC" "$SERVICE_FILE"
chown root:root "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable soc-exporter

# ---------------------------------------------------------------------------
# Post-install permission audit
# ---------------------------------------------------------------------------
info "Running permission audit…"
AUDIT_PASS=true

_check_mode() {
  local path="$1" expected="$2" label="$3"
  if [[ -e "$path" ]]; then
    local actual
    actual=$(stat -c "%a" "$path")
    if [[ "$actual" == "$expected" ]]; then
      echo -e "  ${GREEN}OK${NC}  ${label} (${actual})"
    else
      echo -e "  ${YELLOW}WARN${NC} ${label}: expected ${expected}, got ${actual}"
      AUDIT_PASS=false
    fi
  else
    echo -e "  ${YELLOW}--${NC}  ${label}: not present yet (will be created on init)"
  fi
}

_check_mode "$CONFIG_DIR"  "750" "/etc/soc-exporter (dir)"
_check_mode "$CONFIG_FILE" "600" "/etc/soc-exporter/config.json"
_check_mode "$DATA_DIR"    "750" "/var/lib/soc-exporter (dir)"
_check_mode "$LOG_DIR"     "750" "/var/log/soc-exporter (dir)"

$AUDIT_PASS || warn "Some permissions are non-ideal — review above."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "  Next steps:"
echo "    1. Register: soc-exporter init"
echo "    2. Start:    systemctl start soc-exporter"
echo "    3. Check:    soc-exporter status"
echo ""
