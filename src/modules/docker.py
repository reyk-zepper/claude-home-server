"""Docker management module for claude-home-server.

Provides 12 MCP tools split across three risk tiers:

**Read tools** (safe, non-mutating):
* ``docker_info`` — containers, images, networks, volumes survey.
* ``docker_logs`` — tail container log output.
* ``docker_compose_validate`` — security-check a compose file without
  writing anything.

**Moderate tools** (state-changing but reversible):
* ``docker_start`` — start a stopped container.
* ``docker_stop`` — stop a running container.
* ``docker_restart`` — restart a container.

**Critical tools** (high-impact or destructive):
* ``docker_compose_edit`` — overwrite a compose file (backup created first).
* ``docker_compose_up`` — deploy/recreate a compose stack.
* ``docker_compose_down`` — stop and remove a compose stack.
* ``docker_compose_pull`` — pull updated images for a compose stack.
* ``docker_prune`` — remove unused images / volumes / networks / all.
* ``docker_remove`` — stop and remove a container.

Security notes
--------------
* All subprocess calls go through :func:`~src.utils.subprocess_safe.safe_run`
  — ``subprocess`` is never used directly in this module.
* Every tool validates its inputs via the Pydantic models defined in
  :mod:`src.safety.input_sanitizer`.
* Compose file paths must fall within
  ``config.services.docker.compose_paths`` — otherwise the operation is
  rejected.
* ``docker inspect`` output may contain environment variables with secrets.
  Raw inspect output passes through the :class:`~src.safety.output_filter.OutputFilter`
  provided by :class:`~src.modules.base.BaseModule`, which scrubs known
  secret patterns.
* Write operations that modify compose files first create a backup via
  :class:`~src.utils.backup.BackupManager`.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any

import pydantic
import yaml

from src.modules.base import BaseModule
from src.safety.compose_validator import ComposeValidator, ValidationResult
from src.safety.input_sanitizer import (
    DockerActionInput,
    DockerComposeEditInput,
    DockerComposePathInput,
    DockerInfoInput,
    DockerLogsInput,
    DockerPruneInput,
)
from src.safety.path_validator import PathValidationError, PathValidator
from src.utils.backup import BackupManager
from src.utils.subprocess_safe import safe_run


class DockerModule(BaseModule):
    """Docker management module providing container and compose tools.

    All tools check ``config.services.docker.enabled`` before executing.
    Compose file path arguments are validated against the configured
    ``compose_paths`` allowlist before any file I/O occurs.

    Registered tools:
    * ``docker_info``
    * ``docker_logs``
    * ``docker_compose_validate``
    * ``docker_start``
    * ``docker_stop``
    * ``docker_restart``
    * ``docker_compose_edit``
    * ``docker_compose_up``
    * ``docker_compose_down``
    * ``docker_compose_pull``
    * ``docker_prune``
    * ``docker_remove``
    """

    MODULE_NAME = "docker"

    def _register_tools(self) -> None:
        """Register all 12 Docker tools on the module's FastMCP server."""
        # Read tools
        self._register_tool(
            "docker_info",
            self._docker_info_impl,
            (
                "Query Docker resource information. "
                "resource: 'containers' | 'images' | 'networks' | 'volumes'. "
                "target: optional container/resource name for detailed inspect. "
                "include_stats: include live CPU/memory stats for containers. "
                "Returns a structured plain-text report. "
                "Note: inspect output is filtered to redact secrets from environment variables."
            ),
        )
        self._register_tool(
            "docker_logs",
            self._docker_logs_impl,
            (
                "Retrieve recent log output from a container. "
                "container: container name. "
                "lines: number of log lines to return (default 100, max 10000). "
                "Returns raw log text."
            ),
        )
        self._register_tool(
            "docker_compose_validate",
            self._docker_compose_validate_impl,
            (
                "Security-validate a Docker Compose file without modifying it. "
                "path: absolute path to the compose file (must be within configured compose_paths). "
                "Returns a validation report listing any security violations found."
            ),
        )

        # Moderate tools
        self._register_tool(
            "docker_start",
            self._docker_start_impl,
            (
                "Start a stopped Docker container. "
                "container: container name. "
                "dry_run: if true, describe what would happen without executing. "
                "Returns the command output or dry-run description."
            ),
        )
        self._register_tool(
            "docker_stop",
            self._docker_stop_impl,
            (
                "Stop a running Docker container. "
                "container: container name. "
                "dry_run: if true, describe what would happen without executing. "
                "Returns the command output or dry-run description."
            ),
        )
        self._register_tool(
            "docker_restart",
            self._docker_restart_impl,
            (
                "Restart a Docker container. "
                "container: container name. "
                "dry_run: if true, describe what would happen without executing. "
                "Returns the command output or dry-run description."
            ),
        )

        # Critical tools
        self._register_tool(
            "docker_compose_edit",
            self._docker_compose_edit_impl,
            (
                "Edit (overwrite) a Docker Compose file. "
                "path: absolute path to the compose file. "
                "content: the new YAML content to write. "
                "dry_run: if true, show a diff of what would change without writing. "
                "The content is security-validated before writing; violations block the operation. "
                "A backup is automatically created before overwriting. "
                "CRITICAL: This overwrites the existing file."
            ),
        )
        self._register_tool(
            "docker_compose_up",
            self._docker_compose_up_impl,
            (
                "Deploy or recreate a Docker Compose stack (docker compose up -d). "
                "path: absolute path to the compose file. "
                "dry_run: if true, describe what would happen without executing. "
                "The compose file is security-validated before deployment. "
                "CRITICAL: This starts or recreates containers."
            ),
        )
        self._register_tool(
            "docker_compose_down",
            self._docker_compose_down_impl,
            (
                "Stop and remove a Docker Compose stack (docker compose down). "
                "path: absolute path to the compose file. "
                "dry_run: if true, describe what would happen without executing. "
                "CRITICAL: This stops and removes all containers in the stack."
            ),
        )
        self._register_tool(
            "docker_compose_pull",
            self._docker_compose_pull_impl,
            (
                "Pull updated images for a Docker Compose stack. "
                "path: absolute path to the compose file. "
                "dry_run: if true, describe what would happen without executing. "
                "CRITICAL: This downloads potentially large amounts of data."
            ),
        )
        self._register_tool(
            "docker_prune",
            self._docker_prune_impl,
            (
                "Remove unused Docker resources. "
                "type: 'images' | 'volumes' | 'networks' | 'all'. "
                "dry_run: if true, show what would be removed without removing. "
                "CRITICAL: Pruned resources cannot be recovered. "
                "Use 'all' to run docker system prune (removes images, containers, volumes, networks)."
            ),
        )
        self._register_tool(
            "docker_remove",
            self._docker_remove_impl,
            (
                "Stop and remove a Docker container. "
                "container: container name. "
                "dry_run: if true, describe what would happen without executing. "
                "CRITICAL: The container's ephemeral storage is permanently lost."
            ),
        )

    # ------------------------------------------------------------------
    # Read tools
    # ------------------------------------------------------------------

    def _docker_info_impl(
        self,
        resource: str = "containers",
        target: str | None = None,
        include_stats: bool = False,
    ) -> str:
        """Return a structured report on the requested Docker resource type.

        Args:
            resource: One of ``containers``, ``images``, ``networks``,
                ``volumes``.
            target: Optional container or resource name for detailed inspect.
                Inspect output is automatically filtered by the OutputFilter
                to redact secrets found in environment variable values.
            include_stats: When True and resource is ``containers``, append
                live CPU/memory stats.

        Returns:
            Structured plain-text report.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerInfoInput(
                resource=resource,  # type: ignore[arg-type]
                target=target,
                include_stats=include_stats,
            )
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        parts: list[str] = [f"=== Docker {params.resource.capitalize()} ==="]

        if params.resource == "containers":
            r = safe_run(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--format",
                    "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}",
                ],
                timeout=10,
            )
            if r.returncode == 0:
                parts.append(r.stdout.strip())
            else:
                parts.append(f"Error: {r.stderr.strip()}")

            if params.target:
                parts.append(f"\n--- Inspect: {params.target} ---")
                r_inspect = safe_run(
                    ["docker", "inspect", params.target], timeout=15
                )
                if r_inspect.returncode == 0:
                    # Parse and re-serialise to strip env var values with secrets.
                    # The OutputFilter on BaseModule also filters the final string,
                    # but we additionally scrub at the dict level here to be safe.
                    inspect_text = self._redact_inspect_env(r_inspect.stdout)
                    parts.append(inspect_text)
                else:
                    parts.append(f"Inspect error: {r_inspect.stderr.strip()}")

            if params.include_stats:
                parts.append("\n--- Live Stats ---")
                r_stats = safe_run(
                    [
                        "docker",
                        "stats",
                        "--no-stream",
                        "--format",
                        "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}",
                    ],
                    timeout=15,
                )
                if r_stats.returncode == 0:
                    parts.append(r_stats.stdout.strip())
                else:
                    parts.append(f"Stats error: {r_stats.stderr.strip()}")

        elif params.resource == "images":
            r = safe_run(
                [
                    "docker",
                    "images",
                    "--format",
                    "table {{.Repository}}\t{{.Tag}}\t{{.Size}}",
                ],
                timeout=10,
            )
            if r.returncode == 0:
                parts.append(r.stdout.strip())
            else:
                parts.append(f"Error: {r.stderr.strip()}")

        elif params.resource == "networks":
            r = safe_run(
                [
                    "docker",
                    "network",
                    "ls",
                    "--format",
                    "table {{.Name}}\t{{.Driver}}\t{{.Scope}}",
                ],
                timeout=10,
            )
            if r.returncode == 0:
                parts.append(r.stdout.strip())
            else:
                parts.append(f"Error: {r.stderr.strip()}")

        elif params.resource == "volumes":
            r = safe_run(
                [
                    "docker",
                    "volume",
                    "ls",
                    "--format",
                    "table {{.Name}}\t{{.Driver}}",
                ],
                timeout=10,
            )
            if r.returncode == 0:
                parts.append(r.stdout.strip())
            else:
                parts.append(f"Error: {r.stderr.strip()}")

        return "\n".join(parts)

    def _docker_logs_impl(self, container: str, lines: int = 100) -> str:
        """Return recent log output for a container.

        Args:
            container: Container name.
            lines: Number of log lines to return.

        Returns:
            Log output as plain text.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerLogsInput(container=container, lines=lines)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        parts = [f"=== Logs: {params.container} (last {params.lines} lines) ==="]
        r = safe_run(
            ["docker", "logs", "--tail", str(params.lines), params.container],
            timeout=30,
        )
        # docker logs writes to stderr by convention
        output = r.stdout + r.stderr
        if r.returncode == 0 or output.strip():
            parts.append(output.strip())
        else:
            parts.append(f"Error retrieving logs: {r.stderr.strip()}")

        return "\n".join(parts)

    def _docker_compose_validate_impl(self, path: str, dry_run: bool = False) -> str:
        """Security-validate a compose file without writing anything.

        Args:
            path: Absolute path to the compose file.
            dry_run: Unused for this read-only operation but accepted for API
                consistency.

        Returns:
            A validation report string.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerComposePathInput(path=path, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        resolved_path, path_err = self._validate_compose_path(params.path)
        if path_err:
            return path_err

        compose_data, parse_err = self._load_compose_yaml(resolved_path)
        if parse_err:
            return parse_err

        validator = self._make_compose_validator()
        result = validator.validate(compose_data)
        return result.format_report()

    # ------------------------------------------------------------------
    # Moderate tools
    # ------------------------------------------------------------------

    def _docker_start_impl(self, container: str, dry_run: bool = False) -> str:
        """Start a stopped container.

        Args:
            container: Container name.
            dry_run: When True, return a description without executing.

        Returns:
            Command output or dry-run description.
        """
        return self._container_action("start", container, dry_run)

    def _docker_stop_impl(self, container: str, dry_run: bool = False) -> str:
        """Stop a running container.

        Args:
            container: Container name.
            dry_run: When True, return a description without executing.

        Returns:
            Command output or dry-run description.
        """
        return self._container_action("stop", container, dry_run)

    def _docker_restart_impl(self, container: str, dry_run: bool = False) -> str:
        """Restart a container.

        Args:
            container: Container name.
            dry_run: When True, return a description without executing.

        Returns:
            Command output or dry-run description.
        """
        return self._container_action("restart", container, dry_run)

    # ------------------------------------------------------------------
    # Critical tools
    # ------------------------------------------------------------------

    def _docker_compose_edit_impl(
        self,
        path: str,
        content: str,
        dry_run: bool = False,
    ) -> str:
        """Overwrite a compose file after security validation.

        Steps:
        1. Validate input parameters.
        2. Check path is within configured compose_paths.
        3. Parse content as YAML and run the compose validator.
        4. If validation fails, return the report without writing.
        5. If dry_run, return a unified diff of what would change.
        6. Create a backup of the existing file.
        7. Write the new content.

        Args:
            path: Absolute path to the compose file.
            content: New YAML content for the file.
            dry_run: When True, show diff without writing.

        Returns:
            Result message, diff preview, or validation error report.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerComposeEditInput(path=path, content=content, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        resolved_path, path_err = self._validate_compose_path(params.path)
        if path_err:
            return path_err

        # Parse the new content as YAML
        new_data, parse_err = self._parse_yaml_string(params.content)
        if parse_err:
            return f"YAML parse error in new content: {parse_err}"

        # Security-validate the new content
        validator = self._make_compose_validator()
        result: ValidationResult = validator.validate(new_data)
        if not result.passed:
            return (
                "=== Compose Edit BLOCKED: Security Violations ===\n"
                "The new content has critical security violations. "
                "The file was NOT written.\n\n"
                + result.format_report()
            )

        # Read existing content for diff/backup — use resolved path to
        # prevent TOCTOU symlink races.
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
            if result.violations:
                report_suffix = "\n\nValidation warnings:\n" + result.format_report()
            return (
                f"=== Compose Edit (Dry Run): {params.path} ===\n"
                + diff_text
                + report_suffix
            )

        # Create backup before writing
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

        # Write the file — use resolved path to prevent TOCTOU
        try:
            Path(resolved_path).parent.mkdir(parents=True, exist_ok=True)
            with open(resolved_path, "w", encoding="utf-8") as fh:
                fh.write(params.content)
        except OSError as exc:
            return f"Failed to write compose file: {exc}"

        lines = [f"=== Compose Edit: {params.path} ===", "File written successfully."]
        if backup_path:
            lines.append(f"Backup created: {backup_path}")
        if result.violations:
            lines.append("\nValidation warnings (file was written despite warnings):")
            lines.append(result.format_report())
        return "\n".join(lines)

    def _docker_compose_up_impl(self, path: str, dry_run: bool = False) -> str:
        """Deploy or recreate a compose stack.

        Args:
            path: Absolute path to the compose file.
            dry_run: When True, describe the operation without executing.

        Returns:
            Command output or dry-run description.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerComposePathInput(path=path, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        resolved_path, path_err = self._validate_compose_path(params.path)
        if path_err:
            return path_err

        # Validate the compose file before deployment
        compose_data, parse_err = self._load_compose_yaml(resolved_path)
        if parse_err:
            return parse_err

        validator = self._make_compose_validator()
        validation = validator.validate(compose_data)
        if not validation.passed:
            return (
                "=== Compose Up BLOCKED: Security Violations ===\n"
                "The compose file has critical security violations. "
                "Fix them before deploying.\n\n"
                + validation.format_report()
            )

        if params.dry_run:
            return (
                f"=== Compose Up (Dry Run): {params.path} ===\n"
                "Would execute: docker compose -f <path> up -d\n"
                "This would start or recreate all services in the stack.\n"
                + (
                    "\nValidation warnings:\n" + validation.format_report()
                    if validation.violations
                    else "\nCompose file passed security validation."
                )
            )

        r = safe_run(
            ["docker", "compose", "-f", resolved_path, "up", "-d"],
            timeout=300,
        )
        return self._format_compose_result("Compose Up", params.path, r)

    def _docker_compose_down_impl(self, path: str, dry_run: bool = False) -> str:
        """Stop and remove a compose stack.

        Args:
            path: Absolute path to the compose file.
            dry_run: When True, describe the operation without executing.

        Returns:
            Command output or dry-run description.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerComposePathInput(path=path, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        resolved_path, path_err = self._validate_compose_path(params.path)
        if path_err:
            return path_err

        if params.dry_run:
            return (
                f"=== Compose Down (Dry Run): {params.path} ===\n"
                "Would execute: docker compose -f <path> down\n"
                "This would stop and remove all containers in the stack."
            )

        r = safe_run(
            ["docker", "compose", "-f", resolved_path, "down"],
            timeout=120,
        )
        return self._format_compose_result("Compose Down", params.path, r)

    def _docker_compose_pull_impl(self, path: str, dry_run: bool = False) -> str:
        """Pull updated images for a compose stack.

        Args:
            path: Absolute path to the compose file.
            dry_run: When True, describe the operation without executing.

        Returns:
            Command output or dry-run description.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerComposePathInput(path=path, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        resolved_path, path_err = self._validate_compose_path(params.path)
        if path_err:
            return path_err

        if params.dry_run:
            return (
                f"=== Compose Pull (Dry Run): {params.path} ===\n"
                "Would execute: docker compose -f <path> pull\n"
                "This would pull the latest images for all services in the stack. "
                "Note: This may download several gigabytes of data."
            )

        r = safe_run(
            ["docker", "compose", "-f", resolved_path, "pull"],
            timeout=600,
        )
        return self._format_compose_result("Compose Pull", params.path, r)

    def _docker_prune_impl(
        self,
        type: str = "images",  # noqa: A002
        dry_run: bool = False,
    ) -> str:
        """Remove unused Docker resources.

        Args:
            type: One of ``images``, ``volumes``, ``networks``, ``all``.
            dry_run: When True, show what would be removed without removing.

        Returns:
            Command output or dry-run listing.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerPruneInput(type=type, dry_run=dry_run)  # type: ignore[arg-type]
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        if params.dry_run:
            return self._prune_dry_run(params.type)

        if params.type == "images":
            r = safe_run(["docker", "image", "prune", "-af"], timeout=60)
        elif params.type == "volumes":
            r = safe_run(["docker", "volume", "prune", "-f"], timeout=60)
        elif params.type == "networks":
            r = safe_run(["docker", "network", "prune", "-f"], timeout=30)
        else:  # "all"
            r = safe_run(
                ["docker", "system", "prune", "-af", "--volumes"], timeout=120
            )

        parts = [f"=== Docker Prune ({params.type}) ==="]
        if r.returncode == 0:
            parts.append(r.stdout.strip() or "No unused resources found.")
        else:
            parts.append(f"Error: {r.stderr.strip()}")
        return "\n".join(parts)

    def _docker_remove_impl(self, container: str, dry_run: bool = False) -> str:
        """Stop and remove a container.

        Args:
            container: Container name.
            dry_run: When True, describe the operation without executing.

        Returns:
            Command output or dry-run description.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerActionInput(container=container, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        if params.dry_run:
            return (
                f"=== Docker Remove (Dry Run): {params.container} ===\n"
                f"Would stop (if running) then remove container '{params.container}'.\n"
                "All ephemeral container storage would be permanently lost."
            )

        parts = [f"=== Docker Remove: {params.container} ==="]

        # Stop first (idempotent — succeeds even if already stopped)
        r_stop = safe_run(["docker", "stop", params.container], timeout=30)
        if r_stop.returncode != 0 and "No such container" in r_stop.stderr:
            return f"Container '{params.container}' does not exist."
        if r_stop.returncode == 0:
            parts.append(f"Stopped: {r_stop.stdout.strip()}")

        # Remove the container
        r_rm = safe_run(["docker", "rm", params.container], timeout=15)
        if r_rm.returncode == 0:
            parts.append(f"Removed: {r_rm.stdout.strip()}")
        else:
            parts.append(f"Remove error: {r_rm.stderr.strip()}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _container_action(
        self,
        action: str,
        container: str,
        dry_run: bool,
    ) -> str:
        """Execute a single-container lifecycle action (start/stop/restart).

        Args:
            action: One of ``start``, ``stop``, ``restart``.
            container: Container name.
            dry_run: When True, describe without executing.

        Returns:
            Result string.
        """
        if not self._config.services.docker.enabled:
            return "Docker is not enabled in the server configuration."

        try:
            params = DockerActionInput(container=container, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        if params.dry_run:
            return (
                f"=== Docker {action.capitalize()} (Dry Run): {params.container} ===\n"
                f"Would execute: docker {action} {params.container}"
            )

        r = safe_run(["docker", action, params.container], timeout=30)
        parts = [f"=== Docker {action.capitalize()}: {params.container} ==="]
        if r.returncode == 0:
            parts.append(r.stdout.strip() or f"Container '{params.container}' {action}ed successfully.")
        else:
            parts.append(f"Error: {r.stderr.strip()}")
        return "\n".join(parts)

    def _validate_compose_path(self, path: str) -> tuple[str | None, str | None]:
        """Validate that a compose file path is within configured compose_paths.

        Uses PathValidator to resolve symlinks, apply hardcoded blocklists,
        and enforce the compose_paths allowlist. Returns the resolved path
        to prevent TOCTOU races — callers MUST use the resolved path for
        all subsequent I/O operations.

        Args:
            path: Path to validate.

        Returns:
            A 2-tuple of ``(resolved_path, error)``.  On success,
            ``resolved_path`` is the ``realpath``-resolved path and ``error``
            is ``None``.  On failure, ``resolved_path`` is ``None`` and
            ``error`` contains a human-readable reason.
        """
        compose_paths = self._config.services.docker.compose_paths
        if not compose_paths:
            return None, (
                "No compose_paths configured. "
                "Set services.docker.compose_paths in server.yaml to permit compose operations."
            )

        try:
            validator = PathValidator(allowed_paths=compose_paths)
            resolved = validator.validate_or_raise(path)
        except PathValidationError as exc:
            return None, str(exc)
        except Exception as exc:  # noqa: BLE001
            return None, f"Path validation error: {exc}"

        return resolved, None

    def _load_compose_yaml(self, path: str) -> tuple[dict[str, Any], str | None]:
        """Read and parse a compose YAML file from disk.

        Args:
            path: Absolute path to the compose file.

        Returns:
            A 2-tuple of ``(parsed_dict, error_string)``.  When successful,
            ``error_string`` is ``None``.
        """
        try:
            with open(path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except OSError as exc:
            return {}, f"Cannot read compose file {path!r}: {exc}"
        except yaml.YAMLError as exc:
            return {}, f"YAML parse error in {path!r}: {exc}"

        if not isinstance(raw, dict):
            return {}, f"Compose file {path!r} is not a valid YAML mapping."

        return raw, None

    def _parse_yaml_string(self, content: str) -> tuple[dict[str, Any], str | None]:
        """Parse a YAML string into a dict.

        Args:
            content: Raw YAML content string.

        Returns:
            A 2-tuple of ``(parsed_dict, error_string)``.
        """
        try:
            raw = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return {}, str(exc)

        if not isinstance(raw, dict):
            return {}, "Content is not a valid YAML mapping."

        return raw, None

    def _make_compose_validator(self) -> ComposeValidator:
        """Create a ComposeValidator configured from the server config.

        Returns:
            A ``ComposeValidator`` with ``allowed_volume_prefixes`` set to
            the configured compose_paths (as a reasonable default for
            allowed volume mount locations).
        """
        compose_paths = self._config.services.docker.compose_paths
        return ComposeValidator(allowed_volume_prefixes=compose_paths)

    def _format_compose_result(
        self,
        operation: str,
        path: str,
        r: Any,
    ) -> str:
        """Format the result of a compose CLI command.

        Args:
            operation: Human-readable operation name (e.g. ``"Compose Up"``).
            path: Path to the compose file.
            r: ``CommandResult`` from safe_run.

        Returns:
            Formatted result string.
        """
        parts = [f"=== {operation}: {path} ==="]
        if r.returncode == 0:
            output = (r.stdout + r.stderr).strip()
            parts.append(output or "Operation completed successfully.")
        else:
            if r.timed_out:
                parts.append("Operation timed out.")
            else:
                error = (r.stderr or r.stdout).strip()
                parts.append(f"Error (exit {r.returncode}):\n{error}")
        return "\n".join(parts)

    def _prune_dry_run(self, prune_type: str) -> str:
        """Show what would be removed by a prune operation.

        Queries Docker for the relevant dangling/unused resources and
        presents them without removing anything.

        Args:
            prune_type: One of ``images``, ``volumes``, ``networks``, ``all``.

        Returns:
            Dry-run description string.
        """
        parts = [f"=== Docker Prune (Dry Run — type={prune_type}) ==="]
        parts.append("The following unused resources would be removed:\n")

        def _list_images() -> None:
            r = safe_run(
                [
                    "docker",
                    "images",
                    "--filter",
                    "dangling=true",
                    "--format",
                    "table {{.Repository}}\t{{.Tag}}\t{{.Size}}",
                ],
                timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                parts.append("Dangling images:\n" + r.stdout.strip())
            else:
                parts.append("Dangling images: none")

        def _list_volumes() -> None:
            r = safe_run(
                [
                    "docker",
                    "volume",
                    "ls",
                    "--filter",
                    "dangling=true",
                    "--format",
                    "table {{.Name}}\t{{.Driver}}",
                ],
                timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                parts.append("Dangling volumes:\n" + r.stdout.strip())
            else:
                parts.append("Dangling volumes: none")

        def _list_networks() -> None:
            r = safe_run(
                [
                    "docker",
                    "network",
                    "ls",
                    "--filter",
                    "dangling=true",
                    "--format",
                    "table {{.Name}}\t{{.Driver}}",
                ],
                timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                parts.append("Unused networks:\n" + r.stdout.strip())
            else:
                parts.append("Unused networks: none")

        if prune_type == "images":
            _list_images()
        elif prune_type == "volumes":
            _list_volumes()
        elif prune_type == "networks":
            _list_networks()
        else:  # all
            _list_images()
            _list_volumes()
            _list_networks()
            parts.append(
                "\nNote: 'all' would also remove stopped containers "
                "and all unused images (not just dangling ones)."
            )

        return "\n".join(parts)

    def _redact_inspect_env(self, raw_inspect: str) -> str:
        """Parse docker inspect JSON and redact environment variable values.

        Docker inspect returns a JSON array. Environment variables under
        ``Config.Env`` may contain secrets (API keys, passwords, tokens).
        This method replaces each value with ``[REDACTED]`` before returning
        the text for output filtering.

        Args:
            raw_inspect: Raw JSON string from ``docker inspect``.

        Returns:
            JSON string with env var values redacted, or the original text
            on parse failure (the OutputFilter will still scrub secrets).
        """
        try:
            data = json.loads(raw_inspect)
        except (json.JSONDecodeError, ValueError):
            return raw_inspect

        if not isinstance(data, list):
            return raw_inspect

        for item in data:
            if not isinstance(item, dict):
                continue
            config = item.get("Config")
            if not isinstance(config, dict):
                continue
            env_list = config.get("Env")
            if not isinstance(env_list, list):
                continue
            redacted: list[str] = []
            for entry in env_list:
                if isinstance(entry, str) and "=" in entry:
                    key, _ = entry.split("=", 1)
                    redacted.append(f"{key}=[REDACTED]")
                else:
                    redacted.append(str(entry))
            config["Env"] = redacted

        try:
            return json.dumps(data, indent=2)
        except (TypeError, ValueError):
            return raw_inspect
