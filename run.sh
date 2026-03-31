#!/bin/bash
# run.sh — claude-home-server entry point
#
# Used in two ways:
#
#   1. SSH forced command (primary transport):
#      In /home/mcp-server/.ssh/authorized_keys set:
#        command="/opt/claude-home-server/run.sh",restrict ssh-ed25519 AAAA...
#      Claude Code connects with:
#        claude mcp add homeserver --transport ssh -- ssh mcp@<host>
#      The SSH daemon exec's this script and wires stdin/stdout to the channel.
#
#   2. Systemd unit (daemon / test mode):
#      The unit file at system/systemd/claude-home-server.service calls this
#      script directly as ExecStart. Useful for smoke-testing the server without
#      an active SSH session.
#
# The script resolves the install directory, activates the virtual environment,
# exports required env vars, and then replaces itself with the server process
# (exec — no wrapper process stays alive).

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve install directory
# When deployed, the server lives at INSTALL_DIR. During local development the
# script may be invoked directly from the repository checkout — fall back to
# the directory containing this script in that case.
# ---------------------------------------------------------------------------
INSTALL_DIR="${INSTALL_DIR:-/opt/claude-home-server}"
if [[ ! -d "${INSTALL_DIR}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    INSTALL_DIR="${SCRIPT_DIR}"
fi

# ---------------------------------------------------------------------------
# Activate virtual environment
# ---------------------------------------------------------------------------
VENV_DIR="${INSTALL_DIR}/.venv"
if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
    echo "ERROR: virtual environment not found at ${VENV_DIR}" >&2
    echo "Run the installer first: sudo bash install.sh" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

# ---------------------------------------------------------------------------
# Required environment variables
# The MCP server reads these to locate its runtime configuration and the
# permissions policy. Both files are mandatory — bail early if they are absent.
# ---------------------------------------------------------------------------
export CONFIG_PATH="${CONFIG_PATH:-${INSTALL_DIR}/config/server.yaml}"
export PERMISSIONS_PATH="${PERMISSIONS_PATH:-${INSTALL_DIR}/config/permissions.yaml}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "ERROR: config file not found: ${CONFIG_PATH}" >&2
    exit 1
fi
if [[ ! -f "${PERMISSIONS_PATH}" ]]; then
    echo "ERROR: permissions file not found: ${PERMISSIONS_PATH}" >&2
    exit 1
fi

# Point the Docker SDK at the socket proxy instead of the raw socket.
# Override via env if the proxy runs on a non-default port.
export DOCKER_HOST="${DOCKER_HOST:-tcp://127.0.0.1:2375}"

# Keep Python output unbuffered so log lines reach the SSH client immediately
# without waiting for a full buffer to fill.
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

# ---------------------------------------------------------------------------
# Launch the server
# exec replaces this shell process so there is no wrapper in the process tree.
# The console-script entry point (installed by pip/setuptools) is preferred
# when available; fall back to the module invocation for editable installs and
# development checkouts.
# ---------------------------------------------------------------------------
ENTRY_POINT="${INSTALL_DIR}/.venv/bin/claude-home-server"
if [[ -x "${ENTRY_POINT}" ]]; then
    exec "${ENTRY_POINT}"
else
    exec python -m src.server
fi
