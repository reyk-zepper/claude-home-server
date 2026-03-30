"""Pydantic v2 input models for all MCP tool boundaries.

Every tool parameter set is represented as a Pydantic model so that type
coercion, length limits, and format validation are enforced once at the MCP
boundary rather than scattered across individual tool handlers.

Models are named ``<ToolName>Input`` and exported from this module.  Import
them with ``from src.safety.input_sanitizer import FileReadInput`` or via the
package-level ``from src.safety import *``.
"""
from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Shared size constants — used both in models and in tool handlers
# ---------------------------------------------------------------------------

MAX_PATH_LENGTH: int = 4096
MAX_CONTAINER_NAME_LENGTH: int = 128
MAX_ENTITY_ID_LENGTH: int = 256
MAX_OUTPUT_LINES: int = 10_000
MAX_CONTENT_LENGTH: int = 1_000_000  # 1 MB

# Systemd service names: alphanumeric plus @, ., _, - and an optional suffix
# separated by "@" or "." (slice/template units).  We allow the full set of
# characters allowed by systemd without trying to encode every template rule.
_SAFE_SERVICE_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9@._-]+$")

# Container names follow Docker's rules: start with alphanum, then allow
# alphanum, underscore, dot, hyphen.
_SAFE_CONTAINER_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")

# Home Assistant entity IDs: <domain>.<object_id>
_SAFE_ENTITY_ID_RE: re.Pattern[str] = re.compile(
    r"^[a-z_]+\.[a-z0-9_]+$"
)

# HA automation / scene / script IDs returned by the API are numeric strings
# or UUIDs.  We accept alphanum plus dash.
_SAFE_HA_ITEM_ID_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+$")

# Package names for apt: lowercase alphanum, plus, dot, hyphen (Debian policy).
_SAFE_PACKAGE_RE: re.Pattern[str] = re.compile(r"^[a-z0-9][a-z0-9+\-.]+$")

# UFW rule targets: IPv4/IPv6 addresses/ranges, port numbers, and a limited
# set of keywords.  We keep this very restrictive.
_SAFE_UFW_RULE_RE: re.Pattern[str] = re.compile(
    r"^[a-zA-Z0-9.:/\-\s]+$"
)

# Glob characters that are safe (used to block regex patterns in fs_search).
_DANGEROUS_REGEX_CHARS: frozenset[str] = frozenset("()[]{}+^$|\\")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _no_null_bytes(v: str) -> str:
    """Reject strings that contain null bytes.

    Args:
        v: The string to check.

    Returns:
        The original string if clean.

    Raises:
        ValueError: If *v* contains null bytes.
    """
    if "\x00" in v:
        raise ValueError("Value must not contain null bytes")
    return v


# ---------------------------------------------------------------------------
# Discovery & System tools
# ---------------------------------------------------------------------------


class DiscoverInput(BaseModel):
    """Input for the ``discover(scope)`` tool."""

    scope: Literal[
        "system",
        "services",
        "ports",
        "storage",
        "network",
        "docker",
        "crontabs",
        "all",
    ] = "all"


class SystemQueryInput(BaseModel):
    """Input for ``system_query(scope, target)``."""

    scope: Literal["info", "processes", "services", "updates", "firewall"]
    target: Optional[str] = Field(None, max_length=256)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: Optional[str]) -> Optional[str]:
        """Reject null bytes in optional target field.

        Args:
            v: Target string or None.

        Returns:
            Validated string or None.
        """
        if v is not None:
            return _no_null_bytes(v)
        return v


class SystemLogsInput(BaseModel):
    """Input for ``system_logs(source, lines)``."""

    source: str = Field(..., max_length=256)
    lines: int = Field(100, ge=1, le=MAX_OUTPUT_LINES)

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        """Only allow safe log source identifiers.

        Args:
            v: Log source string.

        Returns:
            Validated source string.
        """
        _no_null_bytes(v)
        # Journald unit names and syslog identifiers follow similar rules to
        # service names.  Reject anything suspicious.
        if not re.match(r"^[a-zA-Z0-9@._/\-]+$", v):
            raise ValueError(
                "Log source must contain only alphanumeric characters, "
                "@, ., _, /, -"
            )
        return v


class SystemServiceInput(BaseModel):
    """Input for ``system_service_restart(name)``."""

    name: str = Field(..., max_length=256)

    @field_validator("name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        """Only alphanumeric, hyphen, dot, @, underscore for systemd names.

        Args:
            v: Service name string.

        Returns:
            Validated service name.
        """
        if not _SAFE_SERVICE_RE.match(v):
            raise ValueError(
                "Invalid service name: only [a-zA-Z0-9@._-] allowed"
            )
        return v


class SystemServiceToggleInput(BaseModel):
    """Input for ``system_service_toggle(name, enabled)``."""

    name: str = Field(..., max_length=256)
    enabled: bool
    dry_run: bool = False

    @field_validator("name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        """Validate systemd service name characters.

        Args:
            v: Service name.

        Returns:
            Validated name.
        """
        if not _SAFE_SERVICE_RE.match(v):
            raise ValueError("Invalid service name")
        return v


class SystemPackageInstallInput(BaseModel):
    """Input for ``system_package_install(name)``."""

    name: str = Field(..., max_length=256)
    dry_run: bool = False

    @field_validator("name")
    @classmethod
    def validate_package_name(cls, v: str) -> str:
        """Enforce Debian package naming policy.

        Args:
            v: Package name.

        Returns:
            Validated package name.
        """
        if not _SAFE_PACKAGE_RE.match(v):
            raise ValueError(
                "Invalid package name: must follow Debian naming policy "
                "(lowercase, alphanum, +, ., -)"
            )
        return v


class SystemFirewallEditInput(BaseModel):
    """Input for ``system_firewall_edit(rule)``."""

    rule: str = Field(..., max_length=256)
    dry_run: bool = False

    @field_validator("rule")
    @classmethod
    def validate_rule(cls, v: str) -> str:
        """Only allow safe UFW rule syntax.

        Args:
            v: UFW rule string.

        Returns:
            Validated rule string.
        """
        _no_null_bytes(v)
        if not _SAFE_UFW_RULE_RE.match(v):
            raise ValueError(
                "Invalid firewall rule: only alphanumeric characters, "
                "., :, /, -, and spaces allowed"
            )
        return v


class SystemRebootInput(BaseModel):
    """Input for ``system_reboot``."""

    dry_run: bool = False


class SystemUpdateApplyInput(BaseModel):
    """Input for ``system_update_apply``."""

    dry_run: bool = False


# ---------------------------------------------------------------------------
# Docker tools
# ---------------------------------------------------------------------------


class DockerInfoInput(BaseModel):
    """Input for ``docker_info(resource, target, include_stats)``."""

    resource: Literal["containers", "images", "networks", "volumes"]
    target: Optional[str] = Field(None, max_length=MAX_CONTAINER_NAME_LENGTH)
    include_stats: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: Optional[str]) -> Optional[str]:
        """Validate optional container name target.

        Args:
            v: Container name or None.

        Returns:
            Validated name or None.
        """
        if v is not None and not _SAFE_CONTAINER_RE.match(v):
            raise ValueError("Invalid container/resource name")
        return v


class DockerLogsInput(BaseModel):
    """Input for ``docker_logs(container, lines)``."""

    container: str = Field(..., max_length=MAX_CONTAINER_NAME_LENGTH)
    lines: int = Field(100, ge=1, le=MAX_OUTPUT_LINES)

    @field_validator("container")
    @classmethod
    def validate_container_name(cls, v: str) -> str:
        """Only allow safe container name characters.

        Args:
            v: Container name.

        Returns:
            Validated container name.

        Raises:
            ValueError: For invalid characters.
        """
        if not _SAFE_CONTAINER_RE.match(v):
            raise ValueError(
                "Invalid container name: only alphanumeric, underscore, "
                "dot, hyphen allowed"
            )
        return v


class DockerActionInput(BaseModel):
    """Input for single-container actions: start, stop, restart, remove."""

    container: str = Field(..., max_length=MAX_CONTAINER_NAME_LENGTH)
    dry_run: bool = False

    @field_validator("container")
    @classmethod
    def validate_container_name(cls, v: str) -> str:
        """Validate container name.

        Args:
            v: Container name.

        Returns:
            Validated container name.
        """
        if not _SAFE_CONTAINER_RE.match(v):
            raise ValueError("Invalid container name")
        return v


class DockerComposePathInput(BaseModel):
    """Input for compose file operations that only require a path."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)
    dry_run: bool = False

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Reject null bytes in compose file path.

        Args:
            v: File path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


class DockerComposeEditInput(BaseModel):
    """Input for ``docker_compose_edit(path, content)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)
    content: str = Field(..., max_length=MAX_CONTENT_LENGTH)
    dry_run: bool = False

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Reject null bytes in path.

        Args:
            v: File path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


class DockerPruneInput(BaseModel):
    """Input for ``docker_prune(type)``."""

    type: Literal["images", "volumes", "networks", "all"]
    dry_run: bool = False


# ---------------------------------------------------------------------------
# Filesystem tools
# ---------------------------------------------------------------------------


class FileReadInput(BaseModel):
    """Input for ``fs_read(path)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)

    @field_validator("path")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        """Reject paths with null bytes.

        Args:
            v: File path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


class FileListInput(BaseModel):
    """Input for ``fs_list(path)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)

    @field_validator("path")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        """Reject paths with null bytes.

        Args:
            v: Directory path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


class FileWriteInput(BaseModel):
    """Input for ``fs_write(path, content)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)
    content: str = Field(..., max_length=MAX_CONTENT_LENGTH)
    dry_run: bool = False

    @field_validator("path")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        """Reject paths with null bytes.

        Args:
            v: File path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


class FileSearchInput(BaseModel):
    """Input for ``fs_search(path, pattern)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)
    pattern: str = Field(..., max_length=256)  # Glob only, no regex

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Reject null bytes in search root path.

        Args:
            v: Search root path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)

    @field_validator("pattern")
    @classmethod
    def validate_glob_pattern(cls, v: str) -> str:
        """Only allow glob patterns, not regex.

        Blocks regex-specific characters to prevent ReDoS and to keep the
        interface surface small.

        Args:
            v: Glob pattern string.

        Returns:
            Validated glob pattern.

        Raises:
            ValueError: If the pattern contains regex metacharacters.
        """
        if any(c in _DANGEROUS_REGEX_CHARS for c in v):
            raise ValueError(
                "Only glob patterns allowed (* and ?), not regex metacharacters"
            )
        return v


class FileDiffInput(BaseModel):
    """Input for ``fs_diff(path)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)

    @field_validator("path")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        """Reject null bytes.

        Args:
            v: File path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


class FileBackupRestoreInput(BaseModel):
    """Input for ``fs_backup_restore(backup_path)``."""

    backup_path: str = Field(..., max_length=MAX_PATH_LENGTH)
    dry_run: bool = False

    @field_validator("backup_path")
    @classmethod
    def validate_no_null_bytes(cls, v: str) -> str:
        """Reject null bytes.

        Args:
            v: Backup file path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


# ---------------------------------------------------------------------------
# Home Assistant tools
# ---------------------------------------------------------------------------


class HaQueryInput(BaseModel):
    """Input for ``ha_query(scope, entity_id)``."""

    scope: Literal["status", "entities", "entity", "history"]
    entity_id: Optional[str] = Field(None, max_length=MAX_ENTITY_ID_LENGTH)

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate HA entity ID format (<domain>.<object_id>).

        Args:
            v: Entity ID or None.

        Returns:
            Validated entity ID or None.
        """
        if v is not None and not _SAFE_ENTITY_ID_RE.match(v):
            raise ValueError(
                "Invalid entity_id: expected format 'domain.object_id' "
                "with only [a-z0-9_] characters"
            )
        return v


class HaConfigQueryInput(BaseModel):
    """Input for ``ha_config_query(type, item_id)``."""

    type: Literal["automations", "scenes", "scripts"]
    item_id: Optional[str] = Field(None, max_length=MAX_ENTITY_ID_LENGTH)

    @field_validator("item_id")
    @classmethod
    def validate_item_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate HA config item ID.

        Args:
            v: Item ID or None.

        Returns:
            Validated ID or None.
        """
        if v is not None and not _SAFE_HA_ITEM_ID_RE.match(v):
            raise ValueError("Invalid item_id: only alphanumeric, -, _ allowed")
        return v


class HaLogsInput(BaseModel):
    """Input for ``ha_logs(lines)``."""

    lines: int = Field(100, ge=1, le=MAX_OUTPUT_LINES)


class HaToggleEntityInput(BaseModel):
    """Input for ``ha_toggle_entity(id)``."""

    entity_id: str = Field(..., max_length=MAX_ENTITY_ID_LENGTH)

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: str) -> str:
        """Validate HA entity ID.

        Args:
            v: Entity ID string.

        Returns:
            Validated entity ID.
        """
        if not _SAFE_ENTITY_ID_RE.match(v):
            raise ValueError("Invalid entity_id format")
        return v


class HaCallServiceInput(BaseModel):
    """Input for ``ha_call_service(domain, service, data)``."""

    domain: str = Field(..., max_length=64)
    service: str = Field(..., max_length=128)
    data: dict[str, object] = Field(default_factory=dict)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate HA domain name (lowercase alphanum + underscore).

        Args:
            v: Domain string.

        Returns:
            Validated domain.
        """
        if not re.match(r"^[a-z][a-z0-9_]*$", v):
            raise ValueError("Invalid HA domain name")
        return v

    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        """Validate HA service name.

        Args:
            v: Service name.

        Returns:
            Validated service name.
        """
        if not re.match(r"^[a-z][a-z0-9_]*$", v):
            raise ValueError("Invalid HA service name")
        return v


class HaAutomationItemInput(BaseModel):
    """Input for automation trigger/activate/delete by ID."""

    item_id: str = Field(..., max_length=MAX_ENTITY_ID_LENGTH)

    @field_validator("item_id")
    @classmethod
    def validate_item_id(cls, v: str) -> str:
        """Validate automation/scene/script item ID.

        Args:
            v: Item ID string.

        Returns:
            Validated ID.
        """
        if not _SAFE_HA_ITEM_ID_RE.match(v):
            raise ValueError("Invalid item_id")
        return v


class HaCreateAutomationInput(BaseModel):
    """Input for ``ha_create_automation(yaml)``."""

    yaml_content: str = Field(..., max_length=MAX_CONTENT_LENGTH)
    dry_run: bool = False


class HaEditAutomationInput(BaseModel):
    """Input for ``ha_edit_automation(id, yaml)``."""

    item_id: str = Field(..., max_length=MAX_ENTITY_ID_LENGTH)
    yaml_content: str = Field(..., max_length=MAX_CONTENT_LENGTH)
    dry_run: bool = False

    @field_validator("item_id")
    @classmethod
    def validate_item_id(cls, v: str) -> str:
        """Validate automation ID.

        Args:
            v: Automation ID.

        Returns:
            Validated ID.
        """
        if not _SAFE_HA_ITEM_ID_RE.match(v):
            raise ValueError("Invalid item_id")
        return v


class HaEditConfigInput(BaseModel):
    """Input for ``ha_edit_config(path, content)``."""

    path: str = Field(..., max_length=MAX_PATH_LENGTH)
    content: str = Field(..., max_length=MAX_CONTENT_LENGTH)
    dry_run: bool = False

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Reject null bytes in config path.

        Args:
            v: Config file path.

        Returns:
            Validated path.
        """
        return _no_null_bytes(v)


# ---------------------------------------------------------------------------
# Plex tools
# ---------------------------------------------------------------------------


class PlexLibraryInput(BaseModel):
    """Input for Plex library operations (scan, optimize, empty_trash)."""

    library_id: str = Field(..., max_length=64)

    @field_validator("library_id")
    @classmethod
    def validate_library_id(cls, v: str) -> str:
        """Plex library IDs are numeric strings.

        Args:
            v: Library ID string.

        Returns:
            Validated library ID.
        """
        if not re.match(r"^\d+$", v):
            raise ValueError("Library ID must be a numeric string")
        return v


class PlexUserManageInput(BaseModel):
    """Input for ``plex_manage_user(id, permissions)``."""

    user_id: str = Field(..., max_length=64)
    permissions: dict[str, object] = Field(default_factory=dict)
    dry_run: bool = False

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        """Validate Plex user ID (numeric or alphanum).

        Args:
            v: User ID string.

        Returns:
            Validated user ID.
        """
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Invalid user ID")
        return v


class PlexSettingsInput(BaseModel):
    """Input for ``plex_settings(key, value)``."""

    key: str = Field(..., max_length=128)
    value: str = Field(..., max_length=1024)
    dry_run: bool = False

    @field_validator("key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        """Validate Plex settings key (alphanum + underscore).

        Args:
            v: Settings key string.

        Returns:
            Validated key.
        """
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", v):
            raise ValueError("Invalid settings key")
        return v


# ---------------------------------------------------------------------------
# Service name helper (reusable across tools)
# ---------------------------------------------------------------------------


class ServiceNameInput(BaseModel):
    """Reusable model for any tool that takes a single service name."""

    name: str = Field(..., max_length=256)

    @field_validator("name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        """Only alphanumeric, hyphen, dot, @, underscore for systemd service names.

        Args:
            v: Service name.

        Returns:
            Validated service name.
        """
        if not _SAFE_SERVICE_RE.match(v):
            raise ValueError("Invalid service name")
        return v
