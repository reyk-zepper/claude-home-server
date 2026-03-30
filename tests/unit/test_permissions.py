"""Unit tests for PermissionEngine and related types.

Covers:
* Default risk-level assignments for known tools
* Unknown-tool fallback to CRITICAL
* Override mechanics and the ``is_override`` flag
* Invalid override values raising ``ValueError`` at construction
* Auto-approve rules (READ + MODERATE pass, ELEVATED + CRITICAL do not)
* Backup-required rule (CRITICAL only)
* ``PermissionResult`` field completeness
* All entries in ``DEFAULT_TOOL_LEVELS`` map to valid ``RiskLevel`` values
"""

from __future__ import annotations

import pytest

from src.permissions import (
    DEFAULT_TOOL_LEVELS,
    PermissionEngine,
    PermissionResult,
    RiskLevel,
)


class TestRiskLevelEnum:
    """Basic sanity checks on the RiskLevel enum itself."""

    def test_all_four_levels_exist(self) -> None:
        levels = {r.value for r in RiskLevel}
        assert levels == {"read", "moderate", "elevated", "critical"}

    def test_risk_level_is_string_enum(self) -> None:
        assert isinstance(RiskLevel.READ, str)
        assert RiskLevel.READ == "read"


class TestPermissionEngineDefaults:
    """Tests that rely solely on the built-in DEFAULT_TOOL_LEVELS registry."""

    def test_default_read_tools_are_read(self) -> None:
        engine = PermissionEngine()
        for tool in ["discover", "health_check", "system_query", "docker_info", "fs_read"]:
            assert engine.get_risk_level(tool) == RiskLevel.READ, (
                f"Expected {tool!r} to be READ"
            )

    def test_default_moderate_tools_are_moderate(self) -> None:
        engine = PermissionEngine()
        for tool in [
            "system_service_restart",
            "docker_start",
            "docker_stop",
            "docker_restart",
            "ha_toggle_entity",
            "ha_call_service",
            "plex_scan_library",
        ]:
            assert engine.get_risk_level(tool) == RiskLevel.MODERATE, (
                f"Expected {tool!r} to be MODERATE"
            )

    def test_default_elevated_tools_are_elevated(self) -> None:
        engine = PermissionEngine()
        for tool in [
            "system_service_toggle",
            "ha_create_automation",
            "ha_edit_automation",
            "ha_delete_automation",
            "ha_restart",
            "plex_manage_user",
            "plex_settings",
        ]:
            assert engine.get_risk_level(tool) == RiskLevel.ELEVATED, (
                f"Expected {tool!r} to be ELEVATED"
            )

    def test_default_critical_tools_are_critical(self) -> None:
        engine = PermissionEngine()
        for tool in [
            "system_reboot",
            "docker_compose_edit",
            "fs_write",
            "ha_edit_config",
            "system_update_apply",
            "system_package_install",
            "system_firewall_edit",
            "docker_compose_up",
            "docker_compose_down",
            "docker_compose_pull",
            "docker_prune",
            "docker_remove",
            "fs_backup_restore",
        ]:
            assert engine.get_risk_level(tool) == RiskLevel.CRITICAL, (
                f"Expected {tool!r} to be CRITICAL"
            )

    def test_unknown_tool_defaults_to_critical(self) -> None:
        engine = PermissionEngine()
        assert engine.get_risk_level("totally_unknown_tool_xyz") == RiskLevel.CRITICAL

    def test_all_default_tools_have_valid_levels(self) -> None:
        """Every entry in DEFAULT_TOOL_LEVELS must map to a valid RiskLevel."""
        valid_levels = set(RiskLevel)
        for tool, level in DEFAULT_TOOL_LEVELS.items():
            assert level in valid_levels, (
                f"Tool {tool!r} has invalid level {level!r}"
            )


class TestPermissionEngineOverrides:
    """Tests for the user-supplied override mechanism."""

    def test_override_changes_level(self) -> None:
        engine = PermissionEngine(overrides={"docker_restart": "read"})
        assert engine.get_risk_level("docker_restart") == RiskLevel.READ

    def test_override_takes_precedence_over_default(self) -> None:
        # fs_write is CRITICAL by default; downgrade to MODERATE via override
        engine = PermissionEngine(overrides={"fs_write": "moderate"})
        assert engine.get_risk_level("fs_write") == RiskLevel.MODERATE

    def test_override_can_upgrade_level(self) -> None:
        # discover is READ by default; escalate to ELEVATED via override
        engine = PermissionEngine(overrides={"discover": "elevated"})
        assert engine.get_risk_level("discover") == RiskLevel.ELEVATED

    def test_override_for_unknown_tool(self) -> None:
        engine = PermissionEngine(overrides={"new_tool": "moderate"})
        assert engine.get_risk_level("new_tool") == RiskLevel.MODERATE

    def test_invalid_override_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            PermissionEngine(overrides={"docker_restart": "super_critical"})

    def test_invalid_override_empty_string_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            PermissionEngine(overrides={"docker_restart": ""})

    def test_none_overrides_uses_defaults(self) -> None:
        engine = PermissionEngine(overrides=None)
        assert engine.get_risk_level("fs_write") == RiskLevel.CRITICAL

    def test_empty_overrides_dict_uses_defaults(self) -> None:
        engine = PermissionEngine(overrides={})
        assert engine.get_risk_level("fs_write") == RiskLevel.CRITICAL

    def test_multiple_overrides_applied_independently(self) -> None:
        engine = PermissionEngine(
            overrides={"docker_restart": "read", "ha_edit_config": "moderate"}
        )
        assert engine.get_risk_level("docker_restart") == RiskLevel.READ
        assert engine.get_risk_level("ha_edit_config") == RiskLevel.MODERATE
        # Unmodified tool still returns its default
        assert engine.get_risk_level("fs_write") == RiskLevel.CRITICAL


class TestAutoApprove:
    """Tests for the auto-approve decision logic."""

    def test_auto_approve_read_tools(self) -> None:
        engine = PermissionEngine()
        for tool in ["discover", "health_check", "fs_read", "ha_query", "docker_info"]:
            assert engine.is_auto_approve(tool) is True, (
                f"READ tool {tool!r} should be auto-approved"
            )

    def test_auto_approve_moderate_tools(self) -> None:
        engine = PermissionEngine()
        for tool in ["docker_restart", "ha_toggle_entity", "plex_scan_library"]:
            assert engine.is_auto_approve(tool) is True, (
                f"MODERATE tool {tool!r} should be auto-approved"
            )

    def test_no_auto_approve_elevated_tools(self) -> None:
        engine = PermissionEngine()
        for tool in ["system_service_toggle", "ha_create_automation", "plex_settings"]:
            assert engine.is_auto_approve(tool) is False, (
                f"ELEVATED tool {tool!r} must NOT be auto-approved"
            )

    def test_no_auto_approve_critical_tools(self) -> None:
        engine = PermissionEngine()
        for tool in ["system_reboot", "fs_write", "ha_edit_config", "docker_compose_edit"]:
            assert engine.is_auto_approve(tool) is False, (
                f"CRITICAL tool {tool!r} must NOT be auto-approved"
            )

    def test_no_auto_approve_unknown_tool(self) -> None:
        engine = PermissionEngine()
        assert engine.is_auto_approve("unknown_tool_xyz") is False

    def test_auto_approve_respects_override(self) -> None:
        # Override a CRITICAL tool down to READ — it should become auto-approved
        engine = PermissionEngine(overrides={"system_reboot": "read"})
        assert engine.is_auto_approve("system_reboot") is True

    def test_no_auto_approve_when_overridden_to_elevated(self) -> None:
        # Override a READ tool up to ELEVATED — it should no longer be auto-approved
        engine = PermissionEngine(overrides={"discover": "elevated"})
        assert engine.is_auto_approve("discover") is False


class TestRequiresBackup:
    """Tests for the backup-required decision logic."""

    def test_requires_backup_only_critical(self) -> None:
        engine = PermissionEngine()
        for tool, level in DEFAULT_TOOL_LEVELS.items():
            expected = level == RiskLevel.CRITICAL
            assert engine.requires_backup(tool) is expected, (
                f"Tool {tool!r} (level={level.value}): requires_backup mismatch"
            )

    def test_no_backup_for_read(self) -> None:
        engine = PermissionEngine()
        assert engine.requires_backup("fs_read") is False

    def test_no_backup_for_moderate(self) -> None:
        engine = PermissionEngine()
        assert engine.requires_backup("docker_restart") is False

    def test_no_backup_for_elevated(self) -> None:
        engine = PermissionEngine()
        assert engine.requires_backup("ha_create_automation") is False

    def test_backup_required_for_critical(self) -> None:
        engine = PermissionEngine()
        assert engine.requires_backup("fs_write") is True
        assert engine.requires_backup("system_reboot") is True

    def test_backup_required_unknown_tool(self) -> None:
        engine = PermissionEngine()
        # Unknown tools default to CRITICAL, so backup is required
        assert engine.requires_backup("some_new_tool") is True

    def test_backup_required_respects_override_to_non_critical(self) -> None:
        engine = PermissionEngine(overrides={"fs_write": "elevated"})
        assert engine.requires_backup("fs_write") is False

    def test_backup_required_respects_override_to_critical(self) -> None:
        engine = PermissionEngine(overrides={"discover": "critical"})
        assert engine.requires_backup("discover") is True


class TestPermissionResult:
    """Tests for the PermissionResult dataclass returned by check_permission."""

    def test_permission_result_fields(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("docker_restart")
        assert isinstance(result, PermissionResult)
        assert result.tool_name == "docker_restart"
        assert result.risk_level == RiskLevel.MODERATE
        assert result.auto_approve is True
        assert result.requires_backup is False
        assert result.is_override is False

    def test_permission_result_critical_tool(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("fs_write")
        assert result.tool_name == "fs_write"
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.auto_approve is False
        assert result.requires_backup is True
        assert result.is_override is False

    def test_permission_result_unknown_tool_is_critical(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("unknown_tool_xyz")
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.auto_approve is False
        assert result.requires_backup is True
        assert result.is_override is False

    def test_is_override_flag_true_when_overridden(self) -> None:
        engine = PermissionEngine(overrides={"docker_restart": "read"})
        result = engine.check_permission("docker_restart")
        assert result.is_override is True
        assert result.risk_level == RiskLevel.READ

    def test_is_override_flag_false_for_non_overridden_tool(self) -> None:
        engine = PermissionEngine(overrides={"docker_restart": "read"})
        # fs_write was NOT overridden
        result = engine.check_permission("fs_write")
        assert result.is_override is False

    def test_is_override_true_for_overridden_unknown_tool(self) -> None:
        engine = PermissionEngine(overrides={"brand_new_tool": "moderate"})
        result = engine.check_permission("brand_new_tool")
        assert result.is_override is True
        assert result.risk_level == RiskLevel.MODERATE

    def test_permission_result_is_frozen(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("fs_read")
        with pytest.raises((AttributeError, TypeError)):
            result.tool_name = "something_else"  # type: ignore[misc]

    def test_check_permission_returns_correct_type(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("ha_query")
        assert type(result) is PermissionResult

    def test_permission_result_read_tool(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("ha_query")
        assert result.tool_name == "ha_query"
        assert result.risk_level == RiskLevel.READ
        assert result.auto_approve is True
        assert result.requires_backup is False
        assert result.is_override is False

    def test_permission_result_elevated_tool(self) -> None:
        engine = PermissionEngine()
        result = engine.check_permission("ha_create_automation")
        assert result.tool_name == "ha_create_automation"
        assert result.risk_level == RiskLevel.ELEVATED
        assert result.auto_approve is False
        assert result.requires_backup is False
        assert result.is_override is False
