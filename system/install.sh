#!/usr/bin/env bash
# =============================================================================
# claude-home-server — Installer
# =============================================================================
# Idempotent installation script for Ubuntu 22.04+ / Debian 12+
#
# Usage:
#   sudo bash install.sh              # fresh install (default)
#   sudo bash install.sh --upgrade    # upgrade an existing installation
#   sudo bash install.sh --repair     # repair broken installation in-place
#   sudo bash install.sh --uninstall  # remove everything
#
# Source: https://github.com/reyk-zepper/claude-home-server
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

readonly INSTALL_DIR="/opt/claude-home-server"
readonly MCP_USER="mcp-server"
readonly MCP_GROUP="mcp-server"
readonly LOG_DIR="/var/log/claude-home-server"
readonly BACKUP_DIR="/var/backups/claude-home-server"
readonly AUDIT_LOG="${LOG_DIR}/audit.log"
readonly VENV_DIR="${INSTALL_DIR}/.venv"
readonly SUDOERS_FILE="/etc/sudoers.d/mcp-server"
readonly WRAPPER_DEST="/usr/local/bin"
readonly SERVICE_NAME="claude-home-server"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly APPARMOR_PROFILE="/etc/apparmor.d/claude-home-server"
readonly DOCKER_PROXY_COMPOSE="${INSTALL_DIR}/system/docker-socket-proxy/docker-compose.yaml"
readonly GITHUB_REPO="reyk-zepper/claude-home-server"
readonly MIN_PYTHON="3.11"

# Script self-location (resolved even when run via curl|bash with a temp path)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Colour output helpers
# ---------------------------------------------------------------------------

# Detect whether the terminal supports colour
if [[ -t 1 ]] && command -v tput &>/dev/null && tput colors &>/dev/null && [[ "$(tput colors)" -ge 8 ]]; then
    _BOLD="$(tput bold)"
    _RESET="$(tput sgr0)"
    _RED="$(tput setaf 1)"
    _GREEN="$(tput setaf 2)"
    _YELLOW="$(tput setaf 3)"
    _CYAN="$(tput setaf 6)"
    _WHITE="$(tput setaf 7)"
else
    _BOLD="" _RESET="" _RED="" _GREEN="" _YELLOW="" _CYAN="" _WHITE=""
fi

step()    { echo "${_BOLD}${_CYAN}==> ${_WHITE}${*}${_RESET}"; }
ok()      { echo "${_GREEN}    [ok]${_RESET} ${*}"; }
warn()    { echo "${_YELLOW}   [warn]${_RESET} ${*}" >&2; }
err()     { echo "${_RED}  [error]${_RESET} ${*}" >&2; }
die()     { err "${*}"; exit 1; }
info()    { echo "         ${*}"; }
blank()   { echo ""; }

# ---------------------------------------------------------------------------
# Mode flags
# ---------------------------------------------------------------------------

MODE="install"   # install | upgrade | repair | uninstall

for arg in "${@}"; do
    case "${arg}" in
        --upgrade)   MODE="upgrade"   ;;
        --repair)    MODE="repair"    ;;
        --uninstall) MODE="uninstall" ;;
        --help|-h)
            cat <<EOF
${_BOLD}claude-home-server installer${_RESET}

Usage:
  sudo bash install.sh [OPTIONS]

Options:
  (no flag)     Fresh installation
  --upgrade     Upgrade an existing installation to the current source tree
  --repair      Re-run all setup steps non-destructively on an existing install
  --uninstall   Remove claude-home-server completely from this system
  --help        Show this help

EOF
            exit 0
            ;;
        *)
            die "Unknown option: ${arg}  (use --help for usage)"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Step counter — printed alongside each major step for progress tracking
# ---------------------------------------------------------------------------

_STEP_N=0
step_n() {
    (( _STEP_N++ )) || true
    step "[${_STEP_N}] ${*}"
}

# ---------------------------------------------------------------------------
# Error trap — print a friendly message on unexpected failure
# ---------------------------------------------------------------------------

_LAST_STEP=""
trap '_on_error' ERR

_on_error() {
    local exit_code=$?
    blank
    err "Installation failed (exit code ${exit_code})"
    [[ -n "${_LAST_STEP}" ]] && err "Last step: ${_LAST_STEP}"
    err "Review the output above for details."
    err "Run with --repair to retry individual steps."
    exit "${exit_code}"
}

# Update _LAST_STEP before each numbered step so the error trap can report it
track() { _LAST_STEP="${*}"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

preflight_checks() {
    step_n "Pre-flight checks"
    track "preflight_checks"

    # Must be root
    if [[ "${EUID}" -ne 0 ]]; then
        die "This installer must be run as root. Re-run with: sudo bash system/install.sh"
    fi
    ok "Running as root"

    # OS compatibility
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        case "${ID:-unknown}" in
            ubuntu)
                local major="${VERSION_ID%%.*}"
                if [[ "${major}" -lt 22 ]]; then
                    die "Ubuntu 22.04 or later is required (detected: ${VERSION_ID})"
                fi
                ;;
            debian)
                local major="${VERSION_ID%%.*}"
                if [[ "${major}" -lt 12 ]]; then
                    die "Debian 12 or later is required (detected: ${VERSION_ID})"
                fi
                ;;
            *)
                warn "Untested distribution: ${ID} ${VERSION_ID:-unknown}. Proceeding anyway."
                ;;
        esac
        ok "OS check passed (${PRETTY_NAME:-${ID} ${VERSION_ID:-unknown}})"
    else
        warn "/etc/os-release not found — cannot verify OS compatibility"
    fi

    # Required commands
    local missing=()
    for cmd in python3 pip3 docker useradd visudo chattr; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing[*]}"
    fi
    ok "Required commands present"

    # Optional: rsync (preferred for deploy; cp fallback is used if absent)
    if command -v rsync &>/dev/null; then
        ok "rsync available (will be used for source deployment)"
    else
        warn "rsync not found — falling back to cp for source deployment (consider: apt install rsync)"
    fi

    # Python version
    local pyver
    pyver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"; then
        ok "Python ${pyver} (>= ${MIN_PYTHON} required)"
    else
        die "Python ${MIN_PYTHON}+ required, found ${pyver}"
    fi

    # Docker daemon
    if ! docker info &>/dev/null; then
        die "Docker daemon is not running. Start it with: systemctl start docker"
    fi
    ok "Docker daemon is running"

    # Detect existing installation
    if [[ -d "${INSTALL_DIR}" ]]; then
        if [[ "${MODE}" == "install" ]]; then
            blank
            warn "An existing installation was found at ${INSTALL_DIR}."
            warn "Use --upgrade to upgrade or --repair to fix a broken install."
            blank
            read -r -p "Continue anyway and overwrite? [y/N] " _confirm
            if [[ "${_confirm}" != "y" && "${_confirm}" != "Y" ]]; then
                info "Aborting. No changes were made."
                exit 0
            fi
        else
            ok "Existing installation detected at ${INSTALL_DIR} (mode: ${MODE})"
        fi
    else
        if [[ "${MODE}" == "upgrade" || "${MODE}" == "repair" ]]; then
            die "No existing installation found at ${INSTALL_DIR}. Run without --upgrade/--repair first."
        fi
    fi

    blank
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

run_uninstall() {
    step_n "Stopping and disabling systemd service"
    track "uninstall: systemd"
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        ok "Service stopped"
    fi
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
        ok "Service disabled"
    fi
    if [[ -f "${SERVICE_FILE}" ]]; then
        rm -f "${SERVICE_FILE}"
        systemctl daemon-reload
        ok "Service unit file removed"
    fi

    step_n "Removing Docker Socket Proxy"
    track "uninstall: docker-socket-proxy"
    if [[ -f "${DOCKER_PROXY_COMPOSE}" ]]; then
        docker compose -f "${DOCKER_PROXY_COMPOSE}" down --remove-orphans 2>/dev/null || true
        ok "Docker Socket Proxy stopped"
    else
        info "No docker-compose file found — skipping"
    fi

    step_n "Removing AppArmor profile"
    track "uninstall: apparmor"
    if [[ -f "${APPARMOR_PROFILE}" ]] && command -v apparmor_parser &>/dev/null; then
        apparmor_parser -R "${APPARMOR_PROFILE}" 2>/dev/null || true
        rm -f "${APPARMOR_PROFILE}"
        ok "AppArmor profile removed"
    fi

    step_n "Removing wrapper scripts"
    track "uninstall: wrapper scripts"
    if [[ -d "${SCRIPT_DIR}/sudoers/wrapper-scripts" ]]; then
        while IFS= read -r -d '' script; do
            local name
            name="$(basename "${script}")"
            if [[ -f "${WRAPPER_DEST}/${name}" ]]; then
                rm -f "${WRAPPER_DEST}/${name}"
                ok "Removed ${WRAPPER_DEST}/${name}"
            fi
        done < <(find "${SCRIPT_DIR}/sudoers/wrapper-scripts" -type f -print0)
    fi

    step_n "Removing sudoers file"
    track "uninstall: sudoers"
    if [[ -f "${SUDOERS_FILE}" ]]; then
        rm -f "${SUDOERS_FILE}"
        ok "Removed ${SUDOERS_FILE}"
    fi

    step_n "Removing audit log (append-only bit must be removed first)"
    track "uninstall: audit log"
    if [[ -f "${AUDIT_LOG}" ]]; then
        chattr -a "${AUDIT_LOG}" 2>/dev/null || true
        rm -f "${AUDIT_LOG}"
        ok "Audit log removed"
    fi

    step_n "Removing installation directory and log directory"
    track "uninstall: directories"
    if [[ -d "${INSTALL_DIR}" ]]; then
        rm -rf "${INSTALL_DIR}"
        ok "Removed ${INSTALL_DIR}"
    fi
    if [[ -d "${LOG_DIR}" ]]; then
        rm -rf "${LOG_DIR}"
        ok "Removed ${LOG_DIR}"
    fi
    # Preserve BACKUP_DIR intentionally — user data

    step_n "Removing system user"
    track "uninstall: system user"
    if id "${MCP_USER}" &>/dev/null; then
        userdel "${MCP_USER}"
        ok "User '${MCP_USER}' removed"
    fi

    blank
    ok "claude-home-server has been uninstalled."
    info "Backup files in ${BACKUP_DIR} were preserved."
    blank
}

# ---------------------------------------------------------------------------
# Step 1: System user
# ---------------------------------------------------------------------------

install_system_user() {
    step_n "Creating system user '${MCP_USER}'"
    track "install_system_user"

    if id "${MCP_USER}" &>/dev/null; then
        ok "User '${MCP_USER}' already exists — skipping"
        return
    fi

    useradd \
        --system \
        --shell /bin/sh \
        --home-dir "${INSTALL_DIR}" \
        --no-create-home \
        --comment "claude-home-server MCP daemon" \
        "${MCP_USER}"

    ok "User '${MCP_USER}' created"
}

# ---------------------------------------------------------------------------
# Step 2: Directory structure
# ---------------------------------------------------------------------------

create_directories() {
    step_n "Creating directory structure"
    track "create_directories"

    # Main install dir
    if [[ ! -d "${INSTALL_DIR}" ]]; then
        mkdir -p "${INSTALL_DIR}"
    fi

    # Subdirectories
    local dirs=(
        "${INSTALL_DIR}/config"
        "${INSTALL_DIR}/secrets"
        "${INSTALL_DIR}/backups"
        "${INSTALL_DIR}/system"
        "${LOG_DIR}"
        "${BACKUP_DIR}"
    )

    for d in "${dirs[@]}"; do
        if [[ ! -d "${d}" ]]; then
            mkdir -p "${d}"
            ok "Created ${d}"
        else
            ok "${d} already exists"
        fi
    done

    # Permissions
    chown -R "${MCP_USER}:${MCP_GROUP}" "${INSTALL_DIR}"
    chmod 755 "${INSTALL_DIR}"
    chmod 750 "${INSTALL_DIR}/config"
    chmod 700 "${INSTALL_DIR}/secrets"    # only mcp-server can read secrets
    chmod 750 "${INSTALL_DIR}/backups"
    chmod 755 "${LOG_DIR}"
    chmod 750 "${BACKUP_DIR}"

    chown "${MCP_USER}:${MCP_GROUP}" "${LOG_DIR}"
    chown "${MCP_USER}:${MCP_GROUP}" "${BACKUP_DIR}"

    ok "Directory permissions set"
}

# ---------------------------------------------------------------------------
# Step 3: Copy repo content into INSTALL_DIR (upgrade/repair aware)
# ---------------------------------------------------------------------------

deploy_source() {
    step_n "Deploying source files to ${INSTALL_DIR}"
    track "deploy_source"

    # In a fresh-from-git install the script is run from within the repo.
    # We copy the repo tree into INSTALL_DIR, excluding .git and dev artefacts.
    if [[ "${REPO_ROOT}" == "${INSTALL_DIR}" ]]; then
        ok "Already running from ${INSTALL_DIR} — no copy needed"
        return
    fi

    if command -v rsync &>/dev/null; then
        rsync -a \
            --exclude='.git' \
            --exclude='.venv' \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='.coverage' \
            --exclude='htmlcov' \
            --exclude='dist' \
            --exclude='*.egg-info' \
            "${REPO_ROOT}/" "${INSTALL_DIR}/"
    else
        # rsync not available: fall back to cp
        # Remove stale pyc/cache dirs first so they don't accumulate
        find "${INSTALL_DIR}" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
        find "${INSTALL_DIR}" -name '*.pyc' -delete 2>/dev/null || true
        cp -a "${REPO_ROOT}/." "${INSTALL_DIR}/"
        # Remove artefacts that cp cannot filter
        rm -rf "${INSTALL_DIR}/.git" "${INSTALL_DIR}/.venv" \
               "${INSTALL_DIR}/.coverage" "${INSTALL_DIR}/htmlcov" \
               "${INSTALL_DIR}/dist" 2>/dev/null || true
        find "${INSTALL_DIR}" -name '*.egg-info' -type d -exec rm -rf {} + 2>/dev/null || true
    fi

    chown -R "${MCP_USER}:${MCP_GROUP}" "${INSTALL_DIR}"
    ok "Source deployed"
}

# ---------------------------------------------------------------------------
# Step 4: SSH authorised key
# ---------------------------------------------------------------------------

install_ssh_key() {
    step_n "Installing SSH authorised key for '${MCP_USER}'"
    track "install_ssh_key"

    local ssh_dir="${INSTALL_DIR}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    # Create .ssh dir
    if [[ ! -d "${ssh_dir}" ]]; then
        mkdir -p "${ssh_dir}"
        chown "${MCP_USER}:${MCP_GROUP}" "${ssh_dir}"
        chmod 700 "${ssh_dir}"
    fi

    blank
    info "Paste the SSH public key that Claude Code will use to connect as '${MCP_USER}'."
    info "It will be restricted with: command=\"/opt/claude-home-server/run.sh\",restrict"
    info "(Leave blank to skip — you can add it later to ${auth_keys})"
    blank
    read -r -p "  SSH public key: " _pubkey

    if [[ -z "${_pubkey}" ]]; then
        warn "No SSH key provided — skipping. Add it manually to ${auth_keys}."
        return
    fi

    # Basic sanity check
    if ! echo "${_pubkey}" | grep -qE '^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2)[[:space:]]'; then
        warn "Input does not look like a valid SSH public key — skipping."
        warn "Add it manually to ${auth_keys} in the format:"
        warn "  command=\"/opt/claude-home-server/run.sh\",restrict <key-type> <key-data>"
        return
    fi

    # Prepend the forced-command restriction
    local restricted_entry='command="/opt/claude-home-server/run.sh",restrict '"${_pubkey}"

    # Check for duplicate
    if [[ -f "${auth_keys}" ]] && grep -qF "${_pubkey}" "${auth_keys}" 2>/dev/null; then
        ok "Key already present in ${auth_keys} — skipping"
        return
    fi

    echo "${restricted_entry}" >> "${auth_keys}"
    chown "${MCP_USER}:${MCP_GROUP}" "${auth_keys}"
    chmod 600 "${auth_keys}"

    ok "Key installed in ${auth_keys}"
}

# ---------------------------------------------------------------------------
# Step 5: sudoers file
# ---------------------------------------------------------------------------

install_sudoers() {
    step_n "Installing sudoers.d file"
    track "install_sudoers"

    local src="${INSTALL_DIR}/system/sudoers/mcp-server"

    if [[ ! -f "${src}" ]]; then
        warn "Sudoers source not found at ${src} — skipping."
        warn "Create it before running --repair."
        return
    fi

    # Validate before installing
    if ! visudo -cf "${src}" &>/dev/null; then
        err "Sudoers file failed visudo validation: ${src}"
        visudo -cf "${src}"   # re-run to print the error message
        die "Aborting to avoid breaking sudo."
    fi

    install -m 440 -o root -g root "${src}" "${SUDOERS_FILE}"
    ok "Sudoers file installed and validated: ${SUDOERS_FILE}"
}

# ---------------------------------------------------------------------------
# Step 6: Wrapper scripts
# ---------------------------------------------------------------------------

install_wrapper_scripts() {
    step_n "Installing wrapper scripts to ${WRAPPER_DEST}"
    track "install_wrapper_scripts"

    local src_dir="${INSTALL_DIR}/system/sudoers/wrapper-scripts"

    if [[ ! -d "${src_dir}" ]]; then
        warn "Wrapper scripts directory not found at ${src_dir} — skipping."
        return
    fi

    local count=0
    while IFS= read -r -d '' script; do
        local name
        name="$(basename "${script}")"
        install -m 755 -o root -g root "${script}" "${WRAPPER_DEST}/${name}"
        ok "Installed ${WRAPPER_DEST}/${name}"
        (( count++ )) || true
    done < <(find "${src_dir}" -maxdepth 1 -type f -print0)

    if [[ ${count} -eq 0 ]]; then
        info "No wrapper scripts found in ${src_dir}"
    else
        ok "${count} wrapper script(s) installed"
    fi
}

# ---------------------------------------------------------------------------
# Step 7: Docker Socket Proxy
# ---------------------------------------------------------------------------

deploy_docker_proxy() {
    step_n "Deploying Docker Socket Proxy"
    track "deploy_docker_proxy"

    if [[ ! -f "${DOCKER_PROXY_COMPOSE}" ]]; then
        warn "docker-compose.yaml not found at ${DOCKER_PROXY_COMPOSE} — skipping."
        return
    fi

    docker compose -f "${DOCKER_PROXY_COMPOSE}" up -d --remove-orphans
    ok "Docker Socket Proxy started"
}

# ---------------------------------------------------------------------------
# Step 8: Python virtual environment
# ---------------------------------------------------------------------------

install_python_venv() {
    step_n "Creating Python virtual environment"
    track "install_python_venv"

    local req_file="${INSTALL_DIR}/requirements.txt"

    if [[ ! -f "${req_file}" ]]; then
        die "requirements.txt not found at ${req_file}"
    fi

    if [[ "${MODE}" == "upgrade" && -d "${VENV_DIR}" ]]; then
        info "Upgrading existing venv at ${VENV_DIR}"
    elif [[ ! -d "${VENV_DIR}" ]]; then
        info "Creating new venv at ${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
        ok "Venv created"
    else
        ok "Venv already exists at ${VENV_DIR}"
    fi

    # Always upgrade pip and install/upgrade dependencies
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
    "${VENV_DIR}/bin/pip" install --quiet -r "${req_file}"

    # Install the package itself in editable mode
    if [[ -f "${INSTALL_DIR}/pyproject.toml" ]]; then
        "${VENV_DIR}/bin/pip" install --quiet -e "${INSTALL_DIR}"
        ok "Package installed from ${INSTALL_DIR}/pyproject.toml"
    fi

    chown -R "${MCP_USER}:${MCP_GROUP}" "${VENV_DIR}"
    ok "Python dependencies installed"
}

# ---------------------------------------------------------------------------
# Step 9: run.sh wrapper
# ---------------------------------------------------------------------------

install_run_script() {
    step_n "Installing run.sh wrapper"
    track "install_run_script"

    local run_script="${INSTALL_DIR}/run.sh"

    if [[ -f "${run_script}" && "${MODE}" != "upgrade" ]]; then
        ok "run.sh already exists — skipping (use --upgrade to overwrite)"
        return
    fi

    cat > "${run_script}" <<'RUNSH'
#!/bin/sh
# claude-home-server — SSH stdio entry point
# This script is the ForceCommand target in authorized_keys.
# It activates the venv and launches the MCP server in stdio mode.
set -e
INSTALL_DIR="/opt/claude-home-server"
exec "${INSTALL_DIR}/.venv/bin/python" -m src.server
RUNSH

    chmod 755 "${run_script}"
    chown "${MCP_USER}:${MCP_GROUP}" "${run_script}"
    ok "run.sh installed at ${run_script}"
}

# ---------------------------------------------------------------------------
# Step 10: Config example files
# ---------------------------------------------------------------------------

deploy_example_configs() {
    step_n "Deploying example configuration files"
    track "deploy_example_configs"

    local config_dir="${INSTALL_DIR}/config"

    # Only copy if the destination does not exist (idempotent)
    for example in "${INSTALL_DIR}/config/"*.yaml; do
        # config/ contains the live files; check for example counterpart
        [[ -f "${example}" ]] || continue
        ok "Config already exists: ${example}"
    done

    # Ensure server.yaml and permissions.yaml are present
    for conf in server.yaml permissions.yaml; do
        local target="${config_dir}/${conf}"
        if [[ ! -f "${target}" ]]; then
            # The repo ships these files directly in config/ — they double as
            # examples. Nothing to copy if they're already in place after
            # deploy_source().
            warn "Config not found: ${target}. The repo should provide it."
        else
            ok "${target} is in place"
        fi
    done

    # Lock down config directory: root owns it, mcp-server group can read
    chown -R "root:${MCP_GROUP}" "${config_dir}"
    chmod 750 "${config_dir}"
    # Individual config files: root:mcp-server 640
    find "${config_dir}" -maxdepth 1 -name '*.yaml' -exec chmod 640 {} \;

    # permissions.yaml must be root-owned so the MCP process cannot modify it
    if [[ -f "${config_dir}/permissions.yaml" ]]; then
        chown "root:${MCP_GROUP}" "${config_dir}/permissions.yaml"
        chmod 640 "${config_dir}/permissions.yaml"
        ok "permissions.yaml locked (root:mcp-server 640)"
    fi
}

# ---------------------------------------------------------------------------
# Step 11: Audit log
# ---------------------------------------------------------------------------

setup_audit_log() {
    step_n "Setting up audit log"
    track "setup_audit_log"

    # Create the log file if it doesn't exist
    if [[ ! -f "${AUDIT_LOG}" ]]; then
        touch "${AUDIT_LOG}"
        ok "Created ${AUDIT_LOG}"
    else
        ok "${AUDIT_LOG} already exists"
    fi

    chown "${MCP_USER}:${MCP_GROUP}" "${AUDIT_LOG}"
    chmod 640 "${AUDIT_LOG}"

    # Apply append-only attribute so even root (via the MCP process) cannot
    # truncate or delete the log while the attribute is set.
    # This requires an ext4/xfs filesystem; silently skip on unsupported FS.
    if chattr +a "${AUDIT_LOG}" 2>/dev/null; then
        ok "chattr +a applied — audit log is append-only"
    else
        warn "chattr +a not supported on this filesystem — audit log is not append-only"
        warn "Consider mounting ${LOG_DIR} on an ext4/xfs filesystem."
    fi
}

# ---------------------------------------------------------------------------
# Step 12: systemd service (optional)
# ---------------------------------------------------------------------------

install_systemd_service() {
    step_n "Installing systemd service (optional)"
    track "install_systemd_service"

    blank
    info "The MCP server normally starts on-demand when Claude Code opens an"
    info "SSH session. A persistent systemd service is only needed for testing"
    info "or if you run a non-SSH transport."
    blank
    read -r -p "  Install systemd service '${SERVICE_NAME}'? [y/N] " _confirm

    if [[ "${_confirm}" != "y" && "${_confirm}" != "Y" ]]; then
        info "Skipping systemd service installation."
        return
    fi

    local src="${INSTALL_DIR}/system/systemd/${SERVICE_NAME}.service"

    if [[ ! -f "${src}" ]]; then
        die "Service unit file not found at ${src}"
    fi

    install -m 644 -o root -g root "${src}" "${SERVICE_FILE}"
    systemctl daemon-reload

    read -r -p "  Enable ${SERVICE_NAME} to start on boot? [y/N] " _enable
    if [[ "${_enable}" == "y" || "${_enable}" == "Y" ]]; then
        systemctl enable "${SERVICE_NAME}"
        ok "Service enabled"
    fi

    ok "systemd service installed: ${SERVICE_FILE}"
}

# ---------------------------------------------------------------------------
# Step 13: AppArmor profile (optional)
# ---------------------------------------------------------------------------

install_apparmor_profile() {
    step_n "Installing AppArmor profile (optional)"
    track "install_apparmor_profile"

    if ! command -v apparmor_parser &>/dev/null; then
        info "AppArmor not available on this system — skipping."
        return
    fi

    blank
    read -r -p "  Install AppArmor confinement profile? [y/N] " _confirm
    if [[ "${_confirm}" != "y" && "${_confirm}" != "Y" ]]; then
        info "Skipping AppArmor profile installation."
        return
    fi

    local src="${INSTALL_DIR}/system/apparmor/mcp-server-profile"

    if [[ ! -f "${src}" ]]; then
        warn "AppArmor profile not found at ${src} — skipping."
        warn "Generate one with: aa-genprof /opt/claude-home-server/run.sh"
        return
    fi

    install -m 644 -o root -g root "${src}" "${APPARMOR_PROFILE}"
    # Load in complain mode — profile header also sets flags=(complain).
    # Switch to enforce mode manually after auditing denials in the journal:
    #   sudo aa-enforce /etc/apparmor.d/claude-home-server
    apparmor_parser -C -r "${APPARMOR_PROFILE}"
    ok "AppArmor profile installed in complain mode: ${APPARMOR_PROFILE}"
    info "To enforce after auditing: sudo aa-enforce ${APPARMOR_PROFILE}"
}

# ---------------------------------------------------------------------------
# Step 14: Setup wizard
# ---------------------------------------------------------------------------

run_setup_wizard() {
    step_n "Launching setup wizard"
    track "run_setup_wizard"

    local wizard="${INSTALL_DIR}/system/setup-wizard.sh"

    blank
    echo "${_BOLD}${_CYAN}============================================================${_RESET}"
    echo "${_BOLD}  Installation steps complete — starting setup wizard${_RESET}"
    echo "${_BOLD}${_CYAN}============================================================${_RESET}"
    blank

    if [[ ! -f "${wizard}" ]]; then
        warn "Setup wizard not found at ${wizard}."
        warn "Run it manually later: sudo bash ${wizard}"
        _print_manual_next_steps
        return
    fi

    blank
    read -r -p "  Run the interactive setup wizard now? [Y/n] " _confirm
    if [[ "${_confirm}" == "n" || "${_confirm}" == "N" ]]; then
        info "Skipping wizard. Run it later with:"
        info "  sudo bash ${wizard}"
        _print_manual_next_steps
        return
    fi

    blank
    # Hand off to the wizard; use exec so it inherits the current terminal.
    # If the wizard itself exits non-zero, the error trap will fire — use ||
    # to handle a deliberate Ctrl+C gracefully.
    bash "${wizard}" || {
        blank
        warn "Setup wizard exited with an error or was interrupted."
        warn "Re-run at any time: sudo bash ${wizard}"
    }
}

_print_manual_next_steps() {
    blank
    info "Next steps:"
    blank
    info "  1. Run the setup wizard:         sudo bash ${INSTALL_DIR}/system/setup-wizard.sh"
    info "  2. Review configuration:         ${INSTALL_DIR}/config/server.yaml"
    info "  3. Review permissions:           ${INSTALL_DIR}/config/permissions.yaml"
    info "  4. Add secret token files to:    ${INSTALL_DIR}/secrets/  (chmod 600)"
    blank
    info "  Claude Code SSH config (on the CLIENT machine):"
    blank
    echo "     ${_BOLD}Host homeserver-mcp${_RESET}"
    echo "       HostName <your-server-ip>"
    echo "       User ${MCP_USER}"
    echo "       IdentityFile ~/.ssh/id_ed25519_mcp"
    blank
    info "  Claude Code MCP configuration:"
    blank
    echo "     {\"mcpServers\": {\"home-server\": {\"command\": \"ssh\", \"args\": [\"homeserver-mcp\"]}}}"
    blank
    info "  Documentation: https://github.com/${GITHUB_REPO}"
    blank
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

print_banner() {
    blank
    echo "${_BOLD}${_CYAN}============================================================${_RESET}"
    echo "${_BOLD}  claude-home-server installer  (mode: ${MODE})${_RESET}"
    echo "${_BOLD}${_CYAN}============================================================${_RESET}"
    blank
}

main() {
    print_banner

    if [[ "${MODE}" == "uninstall" ]]; then
        blank
        warn "This will remove claude-home-server completely."
        warn "Backup files in ${BACKUP_DIR} will be preserved."
        blank
        read -r -p "  Type 'yes' to confirm uninstall: " _confirm
        if [[ "${_confirm}" != "yes" ]]; then
            info "Aborting. No changes were made."
            exit 0
        fi
        blank
        preflight_checks
        run_uninstall
        exit 0
    fi

    # All other modes: install / upgrade / repair
    preflight_checks
    install_system_user
    create_directories
    deploy_source
    install_ssh_key
    install_sudoers
    install_wrapper_scripts
    deploy_docker_proxy
    install_python_venv
    install_run_script
    deploy_example_configs
    setup_audit_log
    install_systemd_service
    install_apparmor_profile
    run_setup_wizard
}

main "${@}"
