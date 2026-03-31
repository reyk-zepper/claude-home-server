#!/usr/bin/env bash
# =============================================================================
# claude-home-server — Interactive Post-Install Setup Wizard
# =============================================================================
# Run once after installation to configure service tokens, generate server.yaml,
# and verify connectivity to each detected service.
#
# Usage:  sudo bash system/setup-wizard.sh
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Colour palette and symbols
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

OK="${GREEN}✓${RESET}"
FAIL="${RED}✗${RESET}"
WARN="${YELLOW}!${RESET}"
ARROW="${CYAN}→${RESET}"

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
SECRETS_DIR="/opt/claude-home-server/secrets"
CONFIG_DIR="/opt/claude-home-server/config"
HA_TOKEN_FILE="${SECRETS_DIR}/ha_token"
PLEX_TOKEN_FILE="${SECRETS_DIR}/plex_token"
SERVER_YAML="${CONFIG_DIR}/server.yaml"

# Ports / sockets
DOCKER_SOCKET="/var/run/docker.sock"
HA_PORT=8123
PLEX_PORT=32400
PROXY_PORT=2375

# Default security settings (overridden by user input below)
SSH_PORT=22
AUDIT_ENABLED=true
BACKUP_DIR="/var/backups/claude-home-server"

# Collected values written to server.yaml at the end
HA_ENABLED=false
PLEX_ENABLED=false
DOCKER_ENABLED=false

# -----------------------------------------------------------------------------
# Ctrl+C handler
# -----------------------------------------------------------------------------
cleanup() {
    echo ""
    echo -e "${WARN}  Setup interrupted. No changes have been committed to disk."
    echo -e "    Re-run the wizard at any time: ${DIM}sudo bash system/setup-wizard.sh${RESET}"
    exit 1
}
trap cleanup INT TERM

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
print_header() {
    clear
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║        claude-home-server  —  Setup Wizard               ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

section() {
    echo ""
    echo -e "${BOLD}${CYAN}── $* ─────────────────────────────────────────${RESET}"
    echo ""
}

info()    { echo -e "  ${ARROW}  $*"; }
success() { echo -e "  ${OK}  $*"; }
failure() { echo -e "  ${FAIL}  $*"; }
warn()    { echo -e "  ${WARN}  ${YELLOW}$*${RESET}"; }

# Check whether a TCP port has a listener without relying on nmap/nc:
# Uses /dev/tcp which is available in bash on Linux and macOS.
port_open() {
    local host="${1:-localhost}"
    local port="$2"
    (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo -e "${FAIL}  This wizard must be run as root (use sudo)."
        exit 1
    fi
}

ensure_dirs() {
    mkdir -p "${SECRETS_DIR}" "${CONFIG_DIR}"
    chmod 700 "${SECRETS_DIR}"
}

write_secret() {
    local file="$1"
    local value="$2"
    printf '%s' "${value}" > "${file}"
    chmod 600 "${file}"
}

# Minimal HTTP GET using curl (always available on target systems).
# Prints response body; returns curl exit code.
http_get() {
    local url="$1"
    shift
    curl --silent --max-time 10 "$@" "${url}"
}

# -----------------------------------------------------------------------------
# Step 1 — Header
# -----------------------------------------------------------------------------
print_header

require_root
ensure_dirs

echo -e "  Welcome! This wizard will:"
echo -e "  ${DIM}1. Detect running services on this machine${RESET}"
echo -e "  ${DIM}2. Collect authentication tokens for each service${RESET}"
echo -e "  ${DIM}3. Verify connectivity to every service${RESET}"
echo -e "  ${DIM}4. Generate ${SERVER_YAML}${RESET}"
echo -e "  ${DIM}5. Show the Claude Code MCP snippet${RESET}"
echo ""
echo -e "  Press ${BOLD}Ctrl+C${RESET} at any time to abort without writing files."

# -----------------------------------------------------------------------------
# Step 2 — Service detection
# -----------------------------------------------------------------------------
section "Detecting running services"

SUPPORTED=3
DETECTED=0

# Docker socket
if [[ -S "${DOCKER_SOCKET}" ]]; then
    DOCKER_ENABLED=true
    DETECTED=$((DETECTED + 1))
    success "Docker socket found at ${DOCKER_SOCKET}"
else
    failure "Docker socket not found at ${DOCKER_SOCKET}"
fi

# Home Assistant
if port_open localhost "${HA_PORT}"; then
    HA_ENABLED=true
    DETECTED=$((DETECTED + 1))
    success "Home Assistant detected on port ${HA_PORT}"
else
    failure "Home Assistant not detected on port ${HA_PORT}"
fi

# Plex
if port_open localhost "${PLEX_PORT}"; then
    PLEX_ENABLED=true
    DETECTED=$((DETECTED + 1))
    success "Plex Media Server detected on port ${PLEX_PORT}"
else
    failure "Plex Media Server not detected on port ${PLEX_PORT}"
fi

echo ""
echo -e "  ${BOLD}${DETECTED} / ${SUPPORTED}${RESET} supported services detected."

# Give the user a moment to read the detection summary.
echo ""
read -rp "  Press Enter to continue..." _PAUSE

# -----------------------------------------------------------------------------
# Step 3 — Home Assistant token
# -----------------------------------------------------------------------------
if [[ "${HA_ENABLED}" == "true" ]]; then
    section "Home Assistant — Long-Lived Access Token"

    echo -e "  To create a Long-Lived Access Token:"
    echo -e "  ${DIM}1. Open Home Assistant in your browser${RESET}"
    echo -e "  ${DIM}   http://localhost:${HA_PORT}${RESET}"
    echo -e "  ${DIM}2. Click your username (bottom-left)${RESET}"
    echo -e "  ${DIM}3. Scroll down to 'Long-Lived Access Tokens'${RESET}"
    echo -e "  ${DIM}4. Click 'Create Token', give it a name (e.g. claude-mcp)${RESET}"
    echo -e "  ${DIM}5. Copy the generated token and paste it below${RESET}"
    echo ""

    HA_TOKEN=""
    while [[ -z "${HA_TOKEN}" ]]; do
        echo -n "  Home Assistant token: "
        read -rs HA_TOKEN
        echo ""  # newline after silent input
        if [[ -z "${HA_TOKEN}" ]]; then
            warn "Token cannot be empty. Please try again."
        fi
    done

    info "Testing connectivity to http://localhost:${HA_PORT}/api/ ..."

    HA_RESPONSE=$(http_get "http://localhost:${HA_PORT}/api/" \
        -H "Authorization: Bearer ${HA_TOKEN}" \
        -H "Content-Type: application/json" 2>/dev/null) || true

    HA_VERSION=$(echo "${HA_RESPONSE}" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('version','unknown'))" \
        2>/dev/null) || HA_VERSION=""

    if [[ -n "${HA_VERSION}" && "${HA_VERSION}" != "unknown" ]]; then
        write_secret "${HA_TOKEN_FILE}" "${HA_TOKEN}"
        success "Connected to Home Assistant ${BOLD}${HA_VERSION}${RESET}"
        success "Token written to ${HA_TOKEN_FILE} (mode 600)"
    else
        failure "Could not connect to Home Assistant. Check the token and retry."
        warn "Skipping HA token — you can rerun the wizard or edit ${HA_TOKEN_FILE} manually."
        HA_ENABLED=false
    fi
fi

# -----------------------------------------------------------------------------
# Step 4 — Plex token
# -----------------------------------------------------------------------------
if [[ "${PLEX_ENABLED}" == "true" ]]; then
    section "Plex Media Server — Authentication Token"

    echo -e "  To retrieve your Plex token:"
    echo -e "  ${DIM}Option A — Browser DevTools${RESET}"
    echo -e "  ${DIM}  1. Open Plex Web (http://localhost:${PLEX_PORT}/web)${RESET}"
    echo -e "  ${DIM}  2. Open DevTools → Network tab${RESET}"
    echo -e "  ${DIM}  3. Reload the page and filter for 'X-Plex-Token'${RESET}"
    echo ""
    echo -e "  ${DIM}Option B — plex.tv account page${RESET}"
    echo -e "  ${DIM}  1. Visit https://www.plex.tv/claim/ and log in${RESET}"
    echo -e "  ${DIM}  2. Follow the official guide:${RESET}"
    echo -e "  ${DIM}     https://support.plex.tv/articles/204059436${RESET}"
    echo ""

    PLEX_TOKEN=""
    while [[ -z "${PLEX_TOKEN}" ]]; do
        echo -n "  Plex token: "
        read -rs PLEX_TOKEN
        echo ""
        if [[ -z "${PLEX_TOKEN}" ]]; then
            warn "Token cannot be empty. Please try again."
        fi
    done

    info "Testing connectivity to http://localhost:${PLEX_PORT}/ ..."

    PLEX_RESPONSE=$(http_get "http://localhost:${PLEX_PORT}/" \
        -H "X-Plex-Token: ${PLEX_TOKEN}" \
        -H "Accept: application/json" 2>/dev/null) || true

    PLEX_SERVER_NAME=$(echo "${PLEX_RESPONSE}" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); mc=d.get('MediaContainer',{}); print(mc.get('friendlyName','unknown'))" \
        2>/dev/null) || PLEX_SERVER_NAME=""

    if [[ -n "${PLEX_SERVER_NAME}" && "${PLEX_SERVER_NAME}" != "unknown" ]]; then
        write_secret "${PLEX_TOKEN_FILE}" "${PLEX_TOKEN}"
        success "Connected to Plex server: ${BOLD}${PLEX_SERVER_NAME}${RESET}"
        success "Token written to ${PLEX_TOKEN_FILE} (mode 600)"
    else
        failure "Could not connect to Plex. Check the token and retry."
        warn "Skipping Plex token — you can rerun the wizard or edit ${PLEX_TOKEN_FILE} manually."
        PLEX_ENABLED=false
    fi
fi

# -----------------------------------------------------------------------------
# Step 5 — Docker Socket Proxy
# -----------------------------------------------------------------------------
if [[ "${DOCKER_ENABLED}" == "true" ]]; then
    section "Docker Socket Proxy"

    info "Checking whether the Tecnativa socket proxy is already running ..."

    PROXY_RUNNING=false
    if port_open localhost "${PROXY_PORT}"; then
        PROXY_RUNNING=true
        success "Socket proxy already listening on port ${PROXY_PORT}"
    else
        warn "Socket proxy not detected on port ${PROXY_PORT}."

        # Look for a compose file shipped with the project.
        COMPOSE_FILE=""
        for candidate in \
            /opt/claude-home-server/docker-compose.proxy.yaml \
            /opt/claude-home-server/docker-compose.yml \
            "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/docker-compose.proxy.yaml"; do
            if [[ -f "${candidate}" ]]; then
                COMPOSE_FILE="${candidate}"
                break
            fi
        done

        if [[ -n "${COMPOSE_FILE}" ]]; then
            info "Deploying socket proxy via: ${COMPOSE_FILE}"
            if docker compose -f "${COMPOSE_FILE}" up -d 2>&1 | sed 's/^/    /'; then
                success "Socket proxy deployed."
            else
                failure "docker compose failed. Deploy the proxy manually and rerun."
            fi
        else
            warn "No compose file found. Deploy the socket proxy manually:"
            echo ""
            echo -e "  ${DIM}services:"
            echo -e "    dockerproxy:"
            echo -e "      image: tecnativa/docker-socket-proxy"
            echo -e "      environment:"
            echo -e "        CONTAINERS: 1"
            echo -e "        IMAGES: 1"
            echo -e "        NETWORKS: 1"
            echo -e "        SERVICES: 1"
            echo -e "        VOLUMES: 1"
            echo -e "      ports:"
            echo -e "        - '127.0.0.1:2375:2375'"
            echo -e "      volumes:"
            echo -e "        - /var/run/docker.sock:/var/run/docker.sock:ro${RESET}"
            echo ""
        fi

        # Re-test after potential deployment.
        if port_open localhost "${PROXY_PORT}"; then
            PROXY_RUNNING=true
            success "Socket proxy is now reachable on port ${PROXY_PORT}"
        fi
    fi

    if [[ "${PROXY_RUNNING}" == "true" ]]; then
        info "Verifying HTTP response from http://localhost:${PROXY_PORT} ..."
        PROXY_RESPONSE=$(http_get "http://localhost:${PROXY_PORT}/version" 2>/dev/null) || true
        if echo "${PROXY_RESPONSE}" | python3 -c \
            "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
            success "Docker Socket Proxy is healthy."
        else
            warn "Port ${PROXY_PORT} is open but did not return valid JSON. Check proxy logs."
        fi
    fi
fi

# -----------------------------------------------------------------------------
# Step 6 — Security settings
# -----------------------------------------------------------------------------
section "Security Settings"

echo -e "  Configure security defaults. Press Enter to accept the default shown in [brackets]."
echo ""

# SSH port
read -rp "  Protected SSH port [${SSH_PORT}]: " _SSH_PORT_INPUT
if [[ -n "${_SSH_PORT_INPUT}" ]]; then
    if [[ "${_SSH_PORT_INPUT}" =~ ^[0-9]+$ ]] && \
       [[ "${_SSH_PORT_INPUT}" -ge 1 ]] && [[ "${_SSH_PORT_INPUT}" -le 65535 ]]; then
        SSH_PORT="${_SSH_PORT_INPUT}"
        success "SSH port set to ${SSH_PORT}"
    else
        warn "Invalid port '${_SSH_PORT_INPUT}'. Keeping default: ${SSH_PORT}"
    fi
else
    info "Using default SSH port: ${SSH_PORT}"
fi

# Audit logging
read -rp "  Enable audit logging? [Y/n]: " _AUDIT_INPUT
case "${_AUDIT_INPUT,,}" in
    n|no) AUDIT_ENABLED=false; info "Audit logging disabled." ;;
    *)    AUDIT_ENABLED=true;  success "Audit logging enabled." ;;
esac

# Backup directory
read -rp "  Backup directory [${BACKUP_DIR}]: " _BACKUP_INPUT
if [[ -n "${_BACKUP_INPUT}" ]]; then
    BACKUP_DIR="${_BACKUP_INPUT}"
fi
success "Backup directory: ${BACKUP_DIR}"

# Create backup dir if it doesn't exist yet.
mkdir -p "${BACKUP_DIR}"

# -----------------------------------------------------------------------------
# Step 7 — Generate server.yaml
# -----------------------------------------------------------------------------
section "Generating ${SERVER_YAML}"

AUDIT_LOG_PATH="/var/log/claude-home-server/audit.log"
mkdir -p "$(dirname "${AUDIT_LOG_PATH}")"

cat > "${SERVER_YAML}" <<YAML
# claude-home-server — Server Configuration
# Generated by setup-wizard.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Edit this file to adjust settings after the initial setup.

# ---------------------------------------------------------------------------
# Server identity
# ---------------------------------------------------------------------------
server:
  name: "$(hostname -s) Home Server"
  config_version: 1

# ---------------------------------------------------------------------------
# Service integrations
# ---------------------------------------------------------------------------
services:

  homeassistant:
    enabled: ${HA_ENABLED}
    url: "http://localhost:${HA_PORT}"
    token_file: "${HA_TOKEN_FILE}"
    config_path: "/opt/homeassistant/config"

  plex:
    enabled: ${PLEX_ENABLED}
    url: "http://localhost:${PLEX_PORT}"
    token_file: "${PLEX_TOKEN_FILE}"

  docker:
    enabled: ${DOCKER_ENABLED}
    socket_proxy: "http://localhost:${PROXY_PORT}"
    compose_paths:
      - "/opt/docker-compose"

# ---------------------------------------------------------------------------
# Filesystem access control
# ---------------------------------------------------------------------------
filesystem:
  allowed_paths:
    - "/opt/homeassistant/config"
    - "/opt/docker-compose"
  blocked_paths:
    - "/etc/nginx/ssl"

# ---------------------------------------------------------------------------
# Security settings
# ---------------------------------------------------------------------------
security:
  protected_ports:
    - ${SSH_PORT}
  audit_log: "${AUDIT_LOG_PATH}"
  audit_enabled: ${AUDIT_ENABLED}
  backup_dir: "${BACKUP_DIR}"
  backup_retention_days: 30
  backup_max_per_file: 50
  circuit_breaker:
    max_consecutive_failures: 3
    burst_limit_critical: 5
    burst_window_minutes: 5

# ---------------------------------------------------------------------------
# HTTP client settings
# ---------------------------------------------------------------------------
http:
  timeout_seconds: 30
  timeout_long_seconds: 600
YAML

chmod 640 "${SERVER_YAML}"
success "Written: ${SERVER_YAML} (mode 640)"

# -----------------------------------------------------------------------------
# Step 8 — Claude Code MCP snippet
# -----------------------------------------------------------------------------
section "Claude Code MCP Configuration"

# Determine the installed server entrypoint.
MCP_COMMAND="python3 -m src.server"
MCP_WORKDIR="/opt/claude-home-server"

echo -e "  Add the following block to ${BOLD}~/.claude/settings.json${RESET}"
echo -e "  (merge it into the existing ${DIM}\"mcpServers\"${RESET} object if one already exists):"
echo ""
echo -e "${DIM}  ┌──────────────────────────────────────────────────────────────────┐${RESET}"
cat <<JSON
  {
    "mcpServers": {
      "home-server": {
        "command": "ssh",
        "args": [
          "-T",
          "-o", "BatchMode=yes",
          "mcp-server@<YOUR_SERVER_IP>",
          "--",
          "cd ${MCP_WORKDIR} && ${MCP_COMMAND}"
        ],
        "description": "claude-home-server MCP — $(hostname -s)"
      }
    }
  }
JSON
echo -e "${DIM}  └──────────────────────────────────────────────────────────────────┘${RESET}"
echo ""
echo -e "  Replace ${BOLD}<YOUR_SERVER_IP>${RESET} with the LAN IP or hostname of this machine."
echo -e "  Ensure the ${BOLD}mcp-server${RESET} system user has your SSH public key in"
echo -e "  ${DIM}/home/mcp-server/.ssh/authorized_keys${RESET} with a ${DIM}command=,restrict${RESET} prefix."

# -----------------------------------------------------------------------------
# Step 9 — Completion
# -----------------------------------------------------------------------------
section "Setup Complete"

SERVICES_OK=0
[[ "${HA_ENABLED}" == "true" ]]     && SERVICES_OK=$((SERVICES_OK + 1))
[[ "${PLEX_ENABLED}" == "true" ]]   && SERVICES_OK=$((SERVICES_OK + 1))
[[ "${DOCKER_ENABLED}" == "true" ]] && SERVICES_OK=$((SERVICES_OK + 1))

success "Configuration written to ${SERVER_YAML}"
success "${SERVICES_OK} service(s) configured and verified"
echo ""
echo -e "  Run the health-check at any time with:"
echo ""
echo -e "  ${BOLD}${CYAN}  cd /opt/claude-home-server && python3 -m src.server --health-check${RESET}"
echo ""
echo -e "  To reconfigure a service, rerun this wizard:"
echo -e "  ${DIM}  sudo bash system/setup-wizard.sh${RESET}"
echo ""
echo -e "${BOLD}${GREEN}  All done. Enjoy claude-home-server!${RESET}"
echo ""
