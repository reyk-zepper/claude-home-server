"""Home Assistant management module for claude-home-server.

Provides 13 MCP tools split across four risk tiers:

**Read tools** (safe, non-mutating):
* ``ha_query``        — query HA status, entities, entity state, or history.
* ``ha_config_query`` — list or inspect automations, scenes, or scripts.
* ``ha_logs``         — retrieve recent HA error log lines.
* ``ha_check_config`` — trigger HA's built-in config-check endpoint.

**Moderate tools** (state-changing but reversible):
* ``ha_toggle_entity``      — toggle a HA entity on/off.
* ``ha_call_service``       — call any HA service with arbitrary data.
* ``ha_trigger_automation`` — manually trigger an automation by ID.
* ``ha_activate_scene``     — activate a scene by ID.

**Elevated tools** (significant but recoverable):
* ``ha_create_automation`` — create a new automation from YAML.
* ``ha_edit_automation``   — update an existing automation from YAML.
* ``ha_delete_automation`` — permanently delete an automation.
* ``ha_restart``           — restart the Home Assistant process.

**Critical tools** (high-impact, direct config-file mutation):
* ``ha_edit_config`` — edit a raw HA config file (backup created first).

Security notes
--------------
* All HTTP requests use :func:`~src.config.load_secret` for token loading —
  the token is never passed via MCP tool parameters.
* Every mutation tool validates its YAML content with
  :class:`~src.safety.ha_config_validator.HAConfigValidator` before sending
  anything to the HA API.
* ``ha_edit_config`` additionally validates the target path via
  :class:`~src.safety.path_validator.PathValidator` (allowlist = HA config
  path + filesystem.allowed_paths) and creates a backup via
  :class:`~src.utils.backup.BackupManager` before writing.
* All tools check ``config.services.homeassistant.enabled`` first.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any

import pydantic
import yaml

from src.config import load_secret
from src.modules.base import BaseModule
from src.safety.ha_config_validator import HAConfigValidator
from src.safety.input_sanitizer import (
    HaAutomationItemInput,
    HaCallServiceInput,
    HaConfigQueryInput,
    HaCreateAutomationInput,
    HaEditAutomationInput,
    HaEditConfigInput,
    HaLogsInput,
    HaQueryInput,
    HaToggleEntityInput,
)
from src.safety.path_validator import PathValidationError, PathValidator
from src.utils.backup import BackupManager

# Map from ha_config_query type to the HA REST API path segment
_CONFIG_TYPE_PATH: dict[str, str] = {
    "automations": "automation",
    "scenes": "scene",
    "scripts": "script",
}


class HomeAssistantModule(BaseModule):
    """Home Assistant management module providing HA REST API tools.

    All tools check ``config.services.homeassistant.enabled`` before
    executing.  The HA long-lived access token is loaded lazily from the
    configured ``token_file`` on first use.

    Registered tools:
    * ``ha_query``
    * ``ha_config_query``
    * ``ha_logs``
    * ``ha_check_config``
    * ``ha_toggle_entity``
    * ``ha_call_service``
    * ``ha_trigger_automation``
    * ``ha_activate_scene``
    * ``ha_create_automation``
    * ``ha_edit_automation``
    * ``ha_delete_automation``
    * ``ha_restart``
    * ``ha_edit_config``
    """

    MODULE_NAME = "homeassistant"

    def __init__(
        self,
        config: Any,
        permission_engine: Any,
        audit_logger: Any,
        circuit_breaker: Any = None,
    ) -> None:
        super().__init__(config, permission_engine, audit_logger, circuit_breaker)
        self._ha_token: str | None = None  # Lazy-loaded on first API call

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def _register_tools(self) -> None:
        """Register all 13 Home Assistant tools on the module's FastMCP server."""
        # Read tools
        self._register_tool(
            "ha_query",
            self._ha_query_impl,
            (
                "Query Home Assistant state. "
                "scope: 'status' (server info) | 'entities' (all entity states) | "
                "'entity' (single entity, requires entity_id) | "
                "'history' (entity history, requires entity_id). "
                "entity_id: HA entity ID in 'domain.object_id' format (e.g. 'light.living_room'). "
                "Returns a structured JSON report."
            ),
        )
        self._register_tool(
            "ha_config_query",
            self._ha_config_query_impl,
            (
                "Query Home Assistant configuration items. "
                "type: 'automations' | 'scenes' | 'scripts'. "
                "item_id: optional item ID to retrieve a single item's details. "
                "Returns a JSON list or single-item detail."
            ),
        )
        self._register_tool(
            "ha_logs",
            self._ha_logs_impl,
            (
                "Retrieve recent Home Assistant error log lines. "
                "lines: number of log lines to return (default 100, max 10000). "
                "Returns raw log text."
            ),
        )
        self._register_tool(
            "ha_check_config",
            self._ha_check_config_impl,
            (
                "Trigger Home Assistant's built-in configuration check. "
                "Returns the check result including any configuration errors found. "
                "Does not restart HA."
            ),
        )

        # Moderate tools
        self._register_tool(
            "ha_toggle_entity",
            self._ha_toggle_entity_impl,
            (
                "Toggle a Home Assistant entity on or off. "
                "entity_id: HA entity ID in 'domain.object_id' format. "
                "Returns the API response."
            ),
        )
        self._register_tool(
            "ha_call_service",
            self._ha_call_service_impl,
            (
                "Call a Home Assistant service. "
                "domain: HA domain (e.g. 'light', 'switch', 'homeassistant'). "
                "service: Service name (e.g. 'turn_on', 'turn_off'). "
                "data: JSON dict of service call data (e.g. {'entity_id': 'light.living_room'}). "
                "Returns the API response."
            ),
        )
        self._register_tool(
            "ha_trigger_automation",
            self._ha_trigger_automation_impl,
            (
                "Manually trigger a Home Assistant automation by its config item ID. "
                "item_id: Automation config item ID (alphanumeric + dash/underscore). "
                "Returns the API response."
            ),
        )
        self._register_tool(
            "ha_activate_scene",
            self._ha_activate_scene_impl,
            (
                "Activate a Home Assistant scene by its config item ID. "
                "item_id: Scene config item ID (alphanumeric + dash/underscore). "
                "Returns the API response."
            ),
        )

        # Elevated tools
        self._register_tool(
            "ha_create_automation",
            self._ha_create_automation_impl,
            (
                "Create a new Home Assistant automation from YAML content. "
                "yaml_content: YAML string describing the automation. "
                "dry_run: if true, validate and show what would be created without posting. "
                "The YAML is security-validated before posting to HA. "
                "ELEVATED: Creates a new persistent automation in Home Assistant."
            ),
        )
        self._register_tool(
            "ha_edit_automation",
            self._ha_edit_automation_impl,
            (
                "Edit an existing Home Assistant automation by ID. "
                "item_id: Automation config item ID to update. "
                "yaml_content: New YAML content for the automation. "
                "dry_run: if true, validate without updating. "
                "The YAML is security-validated before sending. "
                "ELEVATED: Modifies an existing automation in Home Assistant."
            ),
        )
        self._register_tool(
            "ha_delete_automation",
            self._ha_delete_automation_impl,
            (
                "Delete a Home Assistant automation by its config item ID. "
                "item_id: Automation config item ID to delete. "
                "ELEVATED: Permanently removes the automation from Home Assistant."
            ),
        )
        self._register_tool(
            "ha_restart",
            self._ha_restart_impl,
            (
                "Restart the Home Assistant process. "
                "ELEVATED: This will interrupt all automations and integrations "
                "during the restart cycle (typically 30–120 seconds)."
            ),
        )

        # Critical tools
        self._register_tool(
            "ha_edit_config",
            self._ha_edit_config_impl,
            (
                "Edit a Home Assistant configuration file directly. "
                "path: Absolute path to the config file "
                "(must be within the configured HA config path or filesystem.allowed_paths). "
                "content: New YAML content to write to the file. "
                "dry_run: if true, show a diff of what would change without writing. "
                "Content is security-validated; dangerous directives block the operation. "
                "A backup is automatically created before overwriting. "
                "CRITICAL: Directly modifies HA configuration files on disk."
            ),
        )

    # ------------------------------------------------------------------
    # Read tools
    # ------------------------------------------------------------------

    def _ha_query_impl(
        self,
        scope: str = "status",
        entity_id: str | None = None,
    ) -> str:
        """Query Home Assistant state.

        Args:
            scope: One of ``status``, ``entities``, ``entity``, ``history``.
            entity_id: HA entity ID (required for ``entity`` and ``history``).

        Returns:
            Formatted JSON response string.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaQueryInput(scope=scope, entity_id=entity_id)  # type: ignore[arg-type]
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        if params.scope in ("entity", "history") and not params.entity_id:
            return f"Invalid parameters: entity_id is required for scope='{params.scope}'"

        if params.scope == "status":
            data, err = self._ha_request("GET", "/api/")
        elif params.scope == "entities":
            data, err = self._ha_request("GET", "/api/states")
        elif params.scope == "entity":
            data, err = self._ha_request("GET", f"/api/states/{params.entity_id}")
        else:  # "history"
            data, err = self._ha_request(
                "GET",
                f"/api/history/period?filter_entity_id={params.entity_id}",
            )

        if err:
            return f"=== HA Query ({params.scope}) ===\nError: {err}"

        return (
            f"=== HA Query: {params.scope}"
            + (f" [{params.entity_id}]" if params.entity_id else "")
            + " ===\n"
            + json.dumps(data, indent=2, default=str)
        )

    def _ha_config_query_impl(
        self,
        type: str = "automations",  # noqa: A002
        item_id: str | None = None,
    ) -> str:
        """Query HA automation/scene/script configuration items.

        Args:
            type: One of ``automations``, ``scenes``, ``scripts``.
            item_id: Optional item ID to retrieve a single config item.

        Returns:
            Formatted JSON response string.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaConfigQueryInput(type=type, item_id=item_id)  # type: ignore[arg-type]
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        api_type = _CONFIG_TYPE_PATH[params.type]
        if params.item_id:
            path = f"/api/config/{api_type}/config/{params.item_id}"
        else:
            path = f"/api/config/{api_type}/config"

        data, err = self._ha_request("GET", path)
        if err:
            return f"=== HA Config Query ({params.type}) ===\nError: {err}"

        suffix = f" [{params.item_id}]" if params.item_id else ""
        return (
            f"=== HA Config Query: {params.type}{suffix} ===\n"
            + json.dumps(data, indent=2, default=str)
        )

    def _ha_logs_impl(self, lines: int = 100) -> str:
        """Retrieve recent HA error log lines.

        Args:
            lines: Number of tail lines to return.

        Returns:
            Raw log text (last N lines).
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaLogsInput(lines=lines)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        data, err = self._ha_request("GET", "/api/error_log")
        if err:
            return f"=== HA Logs ===\nError: {err}"

        if isinstance(data, str):
            log_lines = data.splitlines()
            tail = "\n".join(log_lines[-params.lines :])
        else:
            tail = json.dumps(data, indent=2, default=str)

        return f"=== HA Logs (last {params.lines} lines) ===\n{tail}"

    def _ha_check_config_impl(self) -> str:
        """Trigger HA's built-in configuration check.

        Returns:
            Check result string from HA.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        data, err = self._ha_request("POST", "/api/config/core/check_config")
        if err:
            return f"=== HA Check Config ===\nError: {err}"

        return "=== HA Check Config ===\n" + json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Moderate tools
    # ------------------------------------------------------------------

    def _ha_toggle_entity_impl(self, entity_id: str) -> str:
        """Toggle a HA entity.

        Args:
            entity_id: HA entity ID.

        Returns:
            API response string.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaToggleEntityInput(entity_id=entity_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        data, err = self._ha_request(
            "POST",
            "/api/services/homeassistant/toggle",
            json_data={"entity_id": params.entity_id},
        )
        if err:
            return f"=== HA Toggle Entity ({params.entity_id}) ===\nError: {err}"

        return (
            f"=== HA Toggle Entity: {params.entity_id} ===\n"
            + json.dumps(data, indent=2, default=str)
        )

    def _ha_call_service_impl(
        self,
        domain: str,
        service: str,
        data: dict[str, Any] | None = None,
    ) -> str:
        """Call a HA service with arbitrary data.

        Args:
            domain: HA integration domain (e.g. ``light``).
            service: Service name (e.g. ``turn_on``).
            data: Optional service call payload dict.

        Returns:
            API response string.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaCallServiceInput(domain=domain, service=service, data=data or {})
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        resp_data, err = self._ha_request(
            "POST",
            f"/api/services/{params.domain}/{params.service}",
            json_data=params.data,
        )
        if err:
            return f"=== HA Call Service ({params.domain}.{params.service}) ===\nError: {err}"

        return (
            f"=== HA Call Service: {params.domain}.{params.service} ===\n"
            + json.dumps(resp_data, indent=2, default=str)
        )

    def _ha_trigger_automation_impl(self, item_id: str) -> str:
        """Manually trigger a HA automation.

        Args:
            item_id: Automation config item ID.

        Returns:
            API response string.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaAutomationItemInput(item_id=item_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        data, err = self._ha_request(
            "POST",
            "/api/services/automation/trigger",
            json_data={"entity_id": f"automation.{params.item_id}"},
        )
        if err:
            return f"=== HA Trigger Automation ({params.item_id}) ===\nError: {err}"

        return (
            f"=== HA Trigger Automation: {params.item_id} ===\n"
            + json.dumps(data, indent=2, default=str)
        )

    def _ha_activate_scene_impl(self, item_id: str) -> str:
        """Activate a HA scene.

        Args:
            item_id: Scene config item ID.

        Returns:
            API response string.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaAutomationItemInput(item_id=item_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        data, err = self._ha_request(
            "POST",
            "/api/services/scene/turn_on",
            json_data={"entity_id": f"scene.{params.item_id}"},
        )
        if err:
            return f"=== HA Activate Scene ({params.item_id}) ===\nError: {err}"

        return (
            f"=== HA Activate Scene: {params.item_id} ===\n"
            + json.dumps(data, indent=2, default=str)
        )

    # ------------------------------------------------------------------
    # Elevated tools
    # ------------------------------------------------------------------

    def _ha_create_automation_impl(
        self,
        yaml_content: str,
        dry_run: bool = False,
    ) -> str:
        """Create a new HA automation from YAML.

        Steps:
        1. Validate input parameters.
        2. Parse YAML content.
        3. Run HAConfigValidator — block on critical violations.
        4. If dry_run, return validation report without posting.
        5. POST to HA API.

        Args:
            yaml_content: YAML string for the new automation.
            dry_run: When True, validate without posting.

        Returns:
            Result message or validation error report.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaCreateAutomationInput(yaml_content=yaml_content, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        automation_dict, parse_err = self._parse_yaml_string(params.yaml_content)
        if parse_err:
            return f"YAML parse error in automation content: {parse_err}"

        validator = HAConfigValidator()
        result = validator.validate_dict(automation_dict)
        if not result.passed:
            return (
                "=== HA Create Automation BLOCKED: Security Violations ===\n"
                "The automation content has critical security violations. "
                "The automation was NOT created.\n\n"
                + result.format_report()
            )

        if params.dry_run:
            report_suffix = ""
            if result.violations:
                report_suffix = "\n\nValidation warnings:\n" + result.format_report()
            return (
                "=== HA Create Automation (Dry Run) ===\n"
                "Automation YAML is valid. Would POST to HA API.\n"
                f"Alias: {automation_dict.get('alias', '(no alias)')}\n"
                + report_suffix
            )

        # Generate an ID from the alias or use a timestamp-derived name
        alias = str(automation_dict.get("alias", "unnamed"))
        new_id = alias.lower().replace(" ", "_")[:64]

        data, err = self._ha_request(
            "POST",
            f"/api/config/automation/config/{new_id}",
            json_data=automation_dict,
        )
        if err:
            return f"=== HA Create Automation ===\nError: {err}"

        lines = [f"=== HA Create Automation: {new_id} ===", "Automation created successfully."]
        if result.violations:
            lines.append("\nValidation warnings (automation was created despite warnings):")
            lines.append(result.format_report())
        lines.append("\nAPI response:\n" + json.dumps(data, indent=2, default=str))
        return "\n".join(lines)

    def _ha_edit_automation_impl(
        self,
        item_id: str,
        yaml_content: str,
        dry_run: bool = False,
    ) -> str:
        """Edit an existing HA automation.

        Steps:
        1. Validate input parameters.
        2. Parse YAML content.
        3. Run HAConfigValidator — block on critical violations.
        4. If dry_run, return validation report without updating.
        5. PUT to HA API.

        Args:
            item_id: Automation config item ID to update.
            yaml_content: New YAML content for the automation.
            dry_run: When True, validate without updating.

        Returns:
            Result message or validation error report.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaEditAutomationInput(
                item_id=item_id, yaml_content=yaml_content, dry_run=dry_run
            )
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        automation_dict, parse_err = self._parse_yaml_string(params.yaml_content)
        if parse_err:
            return f"YAML parse error in automation content: {parse_err}"

        validator = HAConfigValidator()
        result = validator.validate_dict(automation_dict)
        if not result.passed:
            return (
                f"=== HA Edit Automation BLOCKED: {params.item_id} ===\n"
                "The automation content has critical security violations. "
                "The automation was NOT updated.\n\n"
                + result.format_report()
            )

        if params.dry_run:
            report_suffix = ""
            if result.violations:
                report_suffix = "\n\nValidation warnings:\n" + result.format_report()
            return (
                f"=== HA Edit Automation (Dry Run): {params.item_id} ===\n"
                "Automation YAML is valid. Would PUT to HA API.\n"
                + report_suffix
            )

        data, err = self._ha_request(
            "PUT",
            f"/api/config/automation/config/{params.item_id}",
            json_data=automation_dict,
        )
        if err:
            return f"=== HA Edit Automation ({params.item_id}) ===\nError: {err}"

        lines = [
            f"=== HA Edit Automation: {params.item_id} ===",
            "Automation updated successfully.",
        ]
        if result.violations:
            lines.append("\nValidation warnings (automation was updated despite warnings):")
            lines.append(result.format_report())
        lines.append("\nAPI response:\n" + json.dumps(data, indent=2, default=str))
        return "\n".join(lines)

    def _ha_delete_automation_impl(self, item_id: str) -> str:
        """Delete a HA automation by ID.

        Args:
            item_id: Automation config item ID to delete.

        Returns:
            Result message.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaAutomationItemInput(item_id=item_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        data, err = self._ha_request(
            "DELETE",
            f"/api/config/automation/config/{params.item_id}",
        )
        if err:
            return f"=== HA Delete Automation ({params.item_id}) ===\nError: {err}"

        result_text = json.dumps(data, indent=2, default=str) if data else "Automation deleted."
        return f"=== HA Delete Automation: {params.item_id} ===\n{result_text}"

    def _ha_restart_impl(self) -> str:
        """Restart the Home Assistant process.

        Returns:
            Result message.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        data, err = self._ha_request(
            "POST",
            "/api/services/homeassistant/restart",
            timeout=self._config.http.timeout_long_seconds,
        )
        if err:
            return f"=== HA Restart ===\nError: {err}"

        result_text = json.dumps(data, indent=2, default=str) if data else "Restart initiated."
        return f"=== HA Restart ===\n{result_text}"

    # ------------------------------------------------------------------
    # Critical tools
    # ------------------------------------------------------------------

    def _ha_edit_config_impl(
        self,
        path: str,
        content: str,
        dry_run: bool = False,
    ) -> str:
        """Edit a raw HA config file on disk.

        Steps:
        1. Validate input parameters.
        2. Validate path via PathValidator (allowlist = HA config path + allowed_paths).
        3. Parse content as YAML and run HAConfigValidator.
        4. If validation fails (critical), return the report without writing.
        5. If dry_run, return a unified diff of what would change.
        6. Create a backup of the existing file.
        7. Write the new content.

        Args:
            path: Absolute path to the HA config file.
            content: New YAML content to write.
            dry_run: When True, show diff without writing.

        Returns:
            Result message, diff preview, or validation error report.
        """
        if not self._config.services.homeassistant.enabled:
            return "Home Assistant is not enabled in the server configuration."

        try:
            params = HaEditConfigInput(path=path, content=content, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        # Build the path allowlist: HA config dir + general filesystem.allowed_paths
        ha_config_path = self._config.services.homeassistant.config_path
        allowed: list[str] = []
        if ha_config_path:
            allowed.append(ha_config_path)
        allowed.extend(self._config.filesystem.allowed_paths or [])

        if not allowed:
            return (
                "No allowed paths configured. "
                "Set services.homeassistant.config_path or filesystem.allowed_paths "
                "in server.yaml to permit HA config edits."
            )

        blocked: list[str] = list(self._config.filesystem.blocked_paths or [])
        resolved_path, path_err = self._validate_ha_path(params.path, allowed, blocked)
        if path_err:
            return path_err

        # Parse and validate the new content
        new_data, parse_err = self._parse_yaml_string(params.content)
        if parse_err:
            return f"YAML parse error in new content: {parse_err}"

        validator = HAConfigValidator()
        validation = validator.validate_dict(new_data)
        if not validation.passed:
            return (
                "=== HA Edit Config BLOCKED: Security Violations ===\n"
                "The new content has critical security violations. "
                "The file was NOT written.\n\n"
                + validation.format_report()
            )

        # Read existing content for diff/backup
        existing_content = ""
        try:
            with open(resolved_path, encoding="utf-8") as fh:
                existing_content = fh.read()
        except OSError:
            pass  # File may not exist yet — allow creation

        if params.dry_run:
            diff_lines = list(
                difflib.unified_diff(
                    existing_content.splitlines(keepends=True),
                    params.content.splitlines(keepends=True),
                    fromfile=f"{params.path} (current)",
                    tofile=f"{params.path} (proposed)",
                )
            )
            diff_text = "".join(diff_lines) if diff_lines else "(no changes)"
            report_suffix = ""
            if validation.violations:
                report_suffix = "\n\nValidation warnings:\n" + validation.format_report()
            return (
                f"=== HA Edit Config (Dry Run): {params.path} ===\n"
                + diff_text
                + report_suffix
            )

        # Create a backup before writing
        if existing_content:
            backup_manager = BackupManager(
                backup_dir=self._config.security.backup_dir,
                retention_days=self._config.security.backup_retention_days,
                max_per_file=self._config.security.backup_max_per_file,
            )
            try:
                backup_path = backup_manager.create_backup(resolved_path)
            except Exception as exc:  # noqa: BLE001
                return f"Failed to create backup before editing: {exc}"
        else:
            backup_path = None

        # Write the file using the resolved (symlink-safe) path
        try:
            Path(resolved_path).parent.mkdir(parents=True, exist_ok=True)
            with open(resolved_path, "w", encoding="utf-8") as fh:
                fh.write(params.content)
        except OSError as exc:
            return f"Failed to write config file: {exc}"

        lines = [f"=== HA Edit Config: {params.path} ===", "File written successfully."]
        if backup_path:
            lines.append(f"Backup created: {backup_path}")
        if validation.violations:
            lines.append("\nValidation warnings (file was written despite warnings):")
            lines.append(validation.format_report())
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    def _get_token(self) -> tuple[str | None, str | None]:
        """Lazy-load the HA long-lived access token from the configured file.

        The token is cached after first successful load so subsequent calls
        do not re-read the file.

        Returns:
            A 2-tuple ``(token, error)``.  On success, ``error`` is ``None``.
            On failure, ``token`` is ``None`` and ``error`` is a human-readable
            message.
        """
        if self._ha_token is not None:
            return self._ha_token, None

        token_file = self._config.services.homeassistant.token_file
        if not token_file:
            return None, "No token_file configured for Home Assistant"

        try:
            self._ha_token = load_secret(token_file)
            return self._ha_token, None
        except (FileNotFoundError, ValueError) as exc:
            return None, str(exc)

    def _ha_request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> tuple[dict[str, Any] | list[Any] | str | None, str | None]:
        """Make an authenticated HTTP request to the HA REST API.

        Lazily imports ``httpx`` to avoid import-time dependency issues in
        environments where httpx is not installed.

        Args:
            method: HTTP method string (``"GET"``, ``"POST"``, ``"PUT"``,
                ``"DELETE"``).
            path: HA API path starting with ``/`` (e.g. ``"/api/states"``).
            json_data: Optional JSON-serialisable payload dict.
            timeout: Override for the default HTTP timeout in seconds.

        Returns:
            A 2-tuple ``(data, error)``.  On success, ``data`` is the parsed
            JSON response (dict or list) or raw text, and ``error`` is ``None``.
            On failure, ``data`` is ``None`` and ``error`` is a human-readable
            description.
        """
        token, err = self._get_token()
        if err:
            return None, err

        import httpx

        base_url = self._config.services.homeassistant.url.rstrip("/")
        url = base_url + path
        t = timeout or self._config.http.timeout_seconds

        try:
            with httpx.Client(timeout=t) as client:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                resp = client.request(method, url, headers=headers, json=json_data)

                if resp.status_code >= 400:
                    return (
                        None,
                        f"HA API error: HTTP {resp.status_code} — {resp.text[:500]}",
                    )

                ct = resp.headers.get("content-type", "")
                if ct.startswith("application/json"):
                    try:
                        return resp.json(), None
                    except Exception:  # noqa: BLE001
                        return resp.text, None

                return resp.text, None

        except httpx.HTTPError as exc:
            return None, f"HA connection error: {exc}"

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _parse_yaml_string(self, content: str) -> tuple[dict[str, Any], str | None]:
        """Parse a YAML string into a dict.

        Args:
            content: Raw YAML content string.

        Returns:
            A 2-tuple ``(parsed_dict, error_string)``.  On success,
            ``error_string`` is ``None``.  On failure, ``parsed_dict`` is an
            empty dict and ``error_string`` describes the problem.
        """
        try:
            raw = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return {}, str(exc)

        if not isinstance(raw, dict):
            return {}, f"Content is not a valid YAML mapping (got {type(raw).__name__!r})."

        return raw, None

    def _validate_ha_path(
        self,
        path: str,
        allowed_paths: list[str],
        blocked_paths: list[str],
    ) -> tuple[str | None, str | None]:
        """Validate a config file path against the HA-specific allowlist.

        Args:
            path: Path to validate.
            allowed_paths: List of allowed path prefixes.
            blocked_paths: Additional paths to block beyond the hardcoded list.

        Returns:
            A 2-tuple ``(resolved_path, error)``.  On success,
            ``resolved_path`` is the realpath-resolved path and ``error`` is
            ``None``.  On failure, ``resolved_path`` is ``None`` and ``error``
            contains a human-readable reason.
        """
        try:
            validator = PathValidator(
                allowed_paths=allowed_paths,
                blocked_paths=blocked_paths,
            )
            resolved = validator.validate_or_raise(path)
        except PathValidationError as exc:
            return None, str(exc)
        except Exception as exc:  # noqa: BLE001
            return None, f"Path validation error: {exc}"

        return resolved, None
