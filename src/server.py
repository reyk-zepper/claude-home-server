"""MCP server entry point for claude-home-server.

Creates and configures the FastMCP application, mounts all active modules,
and exposes a ``main()`` function called by the ``claude-home-server`` console
script defined in ``pyproject.toml``.

Transport: stdio over SSH — no HTTP port is exposed.  Claude Code connects
with:

    ssh mcp-server@<host> /opt/claude-home-server/run.sh

and the MCP process communicates over stdin/stdout for the duration of the
session.
"""

from __future__ import annotations

import logging

import structlog
from fastmcp import FastMCP

from src.audit import AuditLogger
from src.config import load_config, load_permissions
from src.modules.discovery import DiscoveryModule
from src.modules.docker import DockerModule
from src.modules.filesystem import FilesystemModule
from src.modules.system import SystemModule
from src.permissions import PermissionEngine

# ---------------------------------------------------------------------------
# Logging bootstrap — runs once at import time so structlog is configured
# before any module is imported.
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

_log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def create_server() -> FastMCP:
    """Build and return a fully configured ``FastMCP`` instance.

    Loads configuration and permissions from disk, wires up cross-cutting
    services (permission engine, audit logger), instantiates every active
    module, and mounts their sub-servers onto the root MCP application.

    Returns:
        A ready-to-run ``FastMCP`` application.
    """
    config = load_config()
    permissions_config = load_permissions()

    _log.info(
        "starting_server",
        server_name=config.server.get("name", "Home Server"),
        config_version=config.server.get("config_version", 1),
    )

    mcp = FastMCP("claude-home-server")

    permission_engine = PermissionEngine(permissions_config.overrides)
    audit_logger = AuditLogger(config.security.audit_log)

    # Mount discovery module — always active; provides discover() and
    # health_check() tools used during every session.
    discovery = DiscoveryModule(config, permission_engine, audit_logger)
    mcp.mount(discovery.create_server())

    # System module — OS info, service management, package install, firewall.
    system = SystemModule(config, permission_engine, audit_logger)
    mcp.mount(system.create_server())

    # Docker module — container lifecycle, compose, images, prune.
    docker = DockerModule(config, permission_engine, audit_logger)
    mcp.mount(docker.create_server())

    # Filesystem module — read/write/search/diff/backup with PathValidator.
    filesystem = FilesystemModule(config, permission_engine, audit_logger)
    mcp.mount(filesystem.create_server())

    # Future modules (HomeAssistant, Plex) are mounted here as they are
    # implemented:
    #
    #   from src.modules.homeassistant import HomeAssistantModule
    #   ha = HomeAssistantModule(config, permission_engine, audit_logger)
    #   mcp.mount(ha.create_server())
    #
    #   from src.modules.plex import PlexModule
    #   plex = PlexModule(config, permission_engine, audit_logger)
    #   mcp.mount(plex.create_server())

    _log.info("server_ready")
    return mcp


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server.

    Called by the ``claude-home-server`` console script.  Runs the FastMCP
    application in stdio transport mode — the process reads JSON-RPC messages
    from stdin and writes responses to stdout until the SSH session is closed.
    """
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
