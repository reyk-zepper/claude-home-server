"""Configuration models and loaders for claude-home-server.

All configuration is loaded from YAML files and validated via Pydantic v2.
Missing config files return safe defaults rather than raising errors.
Secret files are read separately and validated for correct permissions.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Service-level models
# ---------------------------------------------------------------------------


class HomeAssistantConfig(BaseModel):
    """Connection settings for the Home Assistant service."""

    enabled: bool = False
    url: str = "http://localhost:8123"
    token_file: str = ""
    config_path: str = ""


class PlexConfig(BaseModel):
    """Connection settings for the Plex Media Server service."""

    enabled: bool = False
    url: str = "http://localhost:32400"
    token_file: str = ""


class DockerConfig(BaseModel):
    """Connection settings for Docker, accessed via a read-only socket proxy."""

    enabled: bool = False
    socket_proxy: str = "http://localhost:2375"
    compose_paths: list[str] = Field(default_factory=list)


class ServicesConfig(BaseModel):
    """Container for all optional service integrations."""

    homeassistant: HomeAssistantConfig = Field(default_factory=HomeAssistantConfig)
    plex: PlexConfig = Field(default_factory=PlexConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)


# ---------------------------------------------------------------------------
# Filesystem / security models
# ---------------------------------------------------------------------------


class FilesystemConfig(BaseModel):
    """Filesystem access control.

    ``allowed_paths`` and ``blocked_paths`` are applied on top of the
    hardcoded blocklist in ``safety.path_validator``.
    """

    allowed_paths: list[str] = Field(default_factory=list)
    blocked_paths: list[str] = Field(default_factory=list)


class CircuitBreakerConfig(BaseModel):
    """Thresholds that govern automatic failure-stopping behaviour."""

    max_consecutive_failures: int = 3
    burst_limit_critical: int = 5
    burst_window_minutes: int = 5


class SecurityConfig(BaseModel):
    """Security-relevant settings: audit log, backups, and circuit breaker."""

    protected_ports: list[int] = Field(default_factory=lambda: [22])
    audit_log: str = "/var/log/claude-home-server/audit.log"
    backup_dir: str = "/var/backups/claude-home-server"
    backup_retention_days: int = 30
    backup_max_per_file: int = 50
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)


class HttpConfig(BaseModel):
    """HTTP client timeouts used for upstream API calls."""

    timeout_seconds: int = 30
    timeout_long_seconds: int = 600


# ---------------------------------------------------------------------------
# Root configuration model
# ---------------------------------------------------------------------------


class ServerConfig(BaseModel):
    """Root configuration model for the MCP server.

    Loaded from ``config/server.yaml``.  All fields have safe defaults so the
    server can start without a config file during development or first run.
    """

    server: dict[str, Any] = Field(
        default_factory=lambda: {"name": "Home Server", "config_version": 1}
    )
    services: ServicesConfig = Field(default_factory=ServicesConfig)
    filesystem: FilesystemConfig = Field(default_factory=FilesystemConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)


# ---------------------------------------------------------------------------
# Permissions model
# ---------------------------------------------------------------------------


class PermissionsConfig(BaseModel):
    """User-supplied overrides for the default tool risk levels.

    Keys are tool names (e.g. ``"docker_restart"``); values are risk level
    strings: ``"read"``, ``"moderate"``, ``"elevated"``, or ``"critical"``.

    Loaded from ``config/permissions.yaml`` (owner root:mcp-server, mode 640
    so the MCP process can read but not modify its own permission policy).
    """

    overrides: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def load_config(
    config_path: str | Path | None = None,
) -> ServerConfig:
    """Load and validate server configuration from a YAML file.

    Returns a ``ServerConfig`` populated entirely from defaults if the file
    does not exist.  This enables the server to start in a zero-config state
    and is safe because all write operations require explicit config before
    they can act on real services.

    Args:
        config_path: Path to the YAML config file.  Falls back to the
            ``CONFIG_PATH`` environment variable, then ``config/server.yaml``.

    Returns:
        A fully validated ``ServerConfig`` instance.

    Raises:
        yaml.YAMLError: If the file exists but contains invalid YAML.
        pydantic.ValidationError: If the YAML structure does not match the
            expected schema.
    """
    resolved = config_path or os.environ.get("CONFIG_PATH", "config/server.yaml")
    path = Path(resolved)
    if not path.exists():
        logger.info("Config file not found at %s — using defaults", path)
        return ServerConfig()

    with path.open("r", encoding="utf-8") as fh:
        raw: Any = yaml.safe_load(fh)

    if raw is None:
        logger.info("Config file %s is empty — using defaults", path)
        return ServerConfig()

    return ServerConfig.model_validate(raw)


def load_permissions(
    config_path: str | Path | None = None,
) -> PermissionsConfig:
    """Load permissions overrides from a YAML file.

    Returns an empty ``PermissionsConfig`` (no overrides) if the file does not
    exist, preserving all default risk-level assignments.

    Args:
        config_path: Path to the permissions YAML file.  Falls back to the
            ``PERMISSIONS_PATH`` environment variable, then
            ``config/permissions.yaml``.

    Returns:
        A validated ``PermissionsConfig`` instance.

    Raises:
        yaml.YAMLError: If the file exists but contains invalid YAML.
        pydantic.ValidationError: If the YAML structure does not match the
            expected schema.
    """
    resolved = config_path or os.environ.get("PERMISSIONS_PATH", "config/permissions.yaml")
    path = Path(resolved)
    if not path.exists():
        logger.debug("Permissions file not found at %s — no overrides active", path)
        return PermissionsConfig()

    with path.open("r", encoding="utf-8") as fh:
        raw: Any = yaml.safe_load(fh)

    if raw is None:
        return PermissionsConfig()

    return PermissionsConfig.model_validate(raw)


def load_secret(token_file: str) -> str:
    """Read a secret token from a file on disk.

    Validates that the file exists, is non-empty, and warns if its Unix
    permissions are wider than ``0o600`` (i.e. readable by anyone other than
    the owning user).  Does **not** raise on a permissions issue — the
    operator may have intentional group-readable secrets — but always logs a
    clear warning so the problem is visible in the audit trail.

    Args:
        token_file: Absolute or relative path to the secret file.

    Returns:
        The stripped token string.

    Raises:
        FileNotFoundError: If ``token_file`` does not exist.
        ValueError: If ``token_file`` exists but is empty after stripping
            whitespace.
    """
    path = Path(token_file)

    if not path.exists():
        raise FileNotFoundError(
            f"Secret file not found: {token_file!r}.  "
            "Create the file and restrict its permissions to 600."
        )

    # Permission check — warn but do not block.
    try:
        file_stat = path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        if mode & ~0o600:
            logger.warning(
                "Secret file %r has permissions %s — expected 0o600.  "
                "Other users or groups may be able to read it.",
                token_file,
                oct(mode),
            )
        # Also warn if the file is owned by root but we are running as a
        # different user; stat() succeeded so we can at least read it, but
        # the ownership is worth flagging.
        if file_stat.st_uid == 0 and os.getuid() != 0:
            logger.warning(
                "Secret file %r is owned by root but the process is running as UID %d.",
                token_file,
                os.getuid(),
            )
    except OSError as exc:
        # Unexpected — we already confirmed path.exists(), so treat as a
        # non-fatal warning rather than aborting.
        logger.warning("Could not stat secret file %r: %s", token_file, exc)

    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError(
            f"Secret file {token_file!r} exists but is empty.  "
            "Write the token to the file before enabling this service."
        )

    return token
