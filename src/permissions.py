"""Permission engine for claude-home-server.

Maps every tool to a risk level and provides auto-approve / backup-required
decisions.  User-supplied overrides (loaded from config/permissions.yaml) take
precedence over the built-in defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Ordered risk tiers for MCP tools.

    The string values are stored in audit logs and config files, so they must
    remain stable across releases.
    """

    READ = "read"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Default risk-level registry — single source of truth for all known tools
# ---------------------------------------------------------------------------

DEFAULT_TOOL_LEVELS: dict[str, RiskLevel] = {
    # --- Discovery ----------------------------------------------------------
    "discover": RiskLevel.READ,
    "health_check": RiskLevel.READ,
    # --- System -------------------------------------------------------------
    "system_query": RiskLevel.READ,
    "system_logs": RiskLevel.READ,
    "system_auth_logs": RiskLevel.READ,
    "system_sessions": RiskLevel.READ,
    "system_disk_health": RiskLevel.READ,
    "system_failed_services": RiskLevel.READ,
    "system_service_restart": RiskLevel.MODERATE,
    "system_service_toggle": RiskLevel.ELEVATED,
    "system_update_apply": RiskLevel.CRITICAL,
    "system_package_install": RiskLevel.CRITICAL,
    "system_firewall_edit": RiskLevel.CRITICAL,
    "system_reboot": RiskLevel.CRITICAL,
    # --- Docker -------------------------------------------------------------
    "docker_info": RiskLevel.READ,
    "docker_logs": RiskLevel.READ,
    "docker_compose_validate": RiskLevel.READ,
    "docker_start": RiskLevel.MODERATE,
    "docker_stop": RiskLevel.MODERATE,
    "docker_restart": RiskLevel.MODERATE,
    "docker_compose_edit": RiskLevel.CRITICAL,
    "docker_compose_up": RiskLevel.CRITICAL,
    "docker_compose_down": RiskLevel.CRITICAL,
    "docker_compose_pull": RiskLevel.CRITICAL,
    "docker_prune": RiskLevel.CRITICAL,
    "docker_remove": RiskLevel.CRITICAL,
    # --- Home Assistant -----------------------------------------------------
    "ha_query": RiskLevel.READ,
    "ha_config_query": RiskLevel.READ,
    "ha_logs": RiskLevel.READ,
    "ha_check_config": RiskLevel.READ,
    "ha_toggle_entity": RiskLevel.MODERATE,
    "ha_call_service": RiskLevel.MODERATE,
    "ha_trigger_automation": RiskLevel.MODERATE,
    "ha_activate_scene": RiskLevel.MODERATE,
    "ha_create_automation": RiskLevel.ELEVATED,
    "ha_edit_automation": RiskLevel.ELEVATED,
    "ha_delete_automation": RiskLevel.ELEVATED,
    "ha_restart": RiskLevel.ELEVATED,
    "ha_edit_config": RiskLevel.CRITICAL,
    # --- Plex ---------------------------------------------------------------
    "plex_status": RiskLevel.READ,
    "plex_libraries": RiskLevel.READ,
    "plex_sessions": RiskLevel.READ,
    "plex_users": RiskLevel.READ,
    "plex_scan_library": RiskLevel.MODERATE,
    "plex_optimize": RiskLevel.MODERATE,
    "plex_empty_trash": RiskLevel.MODERATE,
    "plex_manage_user": RiskLevel.ELEVATED,
    "plex_settings": RiskLevel.ELEVATED,
    # --- Filesystem ---------------------------------------------------------
    "fs_read": RiskLevel.READ,
    "fs_list": RiskLevel.READ,
    "fs_search": RiskLevel.READ,
    "fs_diff": RiskLevel.READ,
    "fs_backup_list": RiskLevel.READ,
    "fs_write": RiskLevel.CRITICAL,
    "fs_backup_restore": RiskLevel.CRITICAL,
}

# Tiers that are approved without an explicit human confirmation step
_AUTO_APPROVE_LEVELS: frozenset[RiskLevel] = frozenset(
    {RiskLevel.READ, RiskLevel.MODERATE}
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PermissionResult:
    """Full permission decision for a single tool invocation.

    Attributes:
        tool_name: The name of the requested tool.
        risk_level: Effective risk level (after applying any override).
        auto_approve: True when the tool may execute without human confirmation.
        requires_backup: True when a pre-action file backup must be created.
        is_override: True when the effective level differs from the built-in
            default due to a user-supplied override entry.
    """

    tool_name: str
    risk_level: RiskLevel
    auto_approve: bool
    requires_backup: bool
    is_override: bool


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PermissionEngine:
    """Manages tool risk levels with optional user-override support.

    Args:
        overrides: Mapping of tool name → risk-level string (e.g.
            ``{"docker_restart": "read"}``).  Invalid level strings raise
            ``ValueError`` at construction time so misconfigured deployments
            fail fast.

    Example::

        engine = PermissionEngine(overrides={"docker_restart": "read"})
        result = engine.check_permission("docker_restart")
        assert result.auto_approve is True
        assert result.is_override is True
    """

    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        self._overrides: dict[str, RiskLevel] = {}
        if overrides:
            for tool, raw_level in overrides.items():
                # ValueError propagates to caller — fail fast on bad config
                self._overrides[tool] = RiskLevel(raw_level)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_risk_level(self, tool_name: str) -> RiskLevel:
        """Return the effective risk level for *tool_name*.

        Override values take precedence over the built-in registry.
        Unknown tools that appear in neither the registry nor the overrides
        table default to ``CRITICAL`` — the safest possible assumption.

        Args:
            tool_name: The tool identifier to look up.

        Returns:
            The effective ``RiskLevel`` for the tool.
        """
        if tool_name in self._overrides:
            return self._overrides[tool_name]
        return DEFAULT_TOOL_LEVELS.get(tool_name, RiskLevel.CRITICAL)

    def check_permission(self, tool_name: str) -> PermissionResult:
        """Return a fully populated ``PermissionResult`` for *tool_name*.

        Args:
            tool_name: The tool identifier to evaluate.

        Returns:
            A frozen ``PermissionResult`` with all decision fields set.
        """
        level = self.get_risk_level(tool_name)
        return PermissionResult(
            tool_name=tool_name,
            risk_level=level,
            auto_approve=level in _AUTO_APPROVE_LEVELS,
            requires_backup=level == RiskLevel.CRITICAL,
            is_override=tool_name in self._overrides,
        )

    def is_auto_approve(self, tool_name: str) -> bool:
        """Return ``True`` if *tool_name* may execute without confirmation.

        Convenience wrapper around :meth:`check_permission`.

        Args:
            tool_name: The tool identifier to evaluate.

        Returns:
            ``True`` for READ and MODERATE risk levels.
        """
        return self.get_risk_level(tool_name) in _AUTO_APPROVE_LEVELS

    def requires_backup(self, tool_name: str) -> bool:
        """Return ``True`` if *tool_name* requires a pre-action file backup.

        Only CRITICAL-level tools require a backup.

        Args:
            tool_name: The tool identifier to evaluate.

        Returns:
            ``True`` when a backup must be created before execution.
        """
        return self.get_risk_level(tool_name) == RiskLevel.CRITICAL
