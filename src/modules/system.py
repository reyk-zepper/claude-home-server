"""System module — Claude's control plane for the home server OS.

Exposes twelve tools grouped by risk tier:

READ (auto-approve, no confirmation required)
    ``system_query``        — multi-scope OS survey (info, processes, services,
                              updates, firewall).
    ``system_logs``         — journalctl log tail for any systemd unit.
    ``system_auth_logs``    — authentication/login events from auth.log or sshd.
    ``system_sessions``     — active login sessions via loginctl and w.
    ``system_disk_health``  — SMART drive health via smartctl, with df fallback.
    ``system_failed_services`` — list of units currently in a failed state.

MODERATE (auto-approve)
    ``system_service_restart`` — restart a named systemd service.

ELEVATED (requires human confirmation)
    ``system_service_toggle``  — enable or disable a service's autostart.

CRITICAL (requires confirmation + backup)
    ``system_update_apply``    — apply pending apt upgrades.
    ``system_package_install`` — install a single apt package.
    ``system_firewall_edit``   — add/delete a UFW firewall rule.
    ``system_reboot``          — reboot the server.

All subprocess calls go through ``safe_run`` or ``safe_run_sudo`` — the
``subprocess`` module is never imported directly in this file.  Every tool
parameter set is validated through a Pydantic model from
``src.safety.input_sanitizer`` before any command is issued.
"""

from __future__ import annotations

import re
from pathlib import Path

import pydantic

from src.modules.base import BaseModule
from src.safety.input_sanitizer import (
    SystemFirewallEditInput,
    SystemLogsInput,
    SystemPackageInstallInput,
    SystemQueryInput,
    SystemRebootInput,
    SystemServiceInput,
    SystemServiceToggleInput,
    SystemUpdateApplyInput,
)
from src.utils.subprocess_safe import safe_run, safe_run_sudo


class SystemModule(BaseModule):
    """System module providing OS-level inspection and management tools.

    Registered tools:

    * ``system_query``           — multi-scope OS survey.
    * ``system_logs``            — journalctl log tail.
    * ``system_auth_logs``       — authentication and login events.
    * ``system_sessions``        — active user sessions.
    * ``system_disk_health``     — drive SMART / health data.
    * ``system_failed_services`` — systemd units in failed state.
    * ``system_service_restart`` — restart a systemd service.
    * ``system_service_toggle``  — enable/disable a service's autostart.
    * ``system_update_apply``    — apply pending apt upgrades.
    * ``system_package_install`` — install an apt package.
    * ``system_firewall_edit``   — modify a UFW firewall rule.
    * ``system_reboot``          — reboot the server.
    """

    MODULE_NAME = "system"

    def _register_tools(self) -> None:
        """Register all twelve system tools on the module server."""
        self._register_tool(
            "system_query",
            self._system_query_impl,
            (
                "Query system information across configurable scopes. "
                "scope: 'info' (hostname/kernel/OS/CPU/memory/uptime), "
                "'processes' (ps aux sorted by memory, optional target filter), "
                "'services' (systemctl list-units), "
                "'updates' (apt list --upgradable), "
                "'firewall' (ufw status verbose). "
                "target: optional filter string for processes/services scopes."
            ),
        )
        self._register_tool(
            "system_logs",
            self._system_logs_impl,
            (
                "Retrieve recent log entries for a systemd unit via journalctl. "
                "source: unit name (e.g. 'nginx', 'sshd'). "
                "lines: number of log lines to return (1-10000, default 100)."
            ),
        )
        self._register_tool(
            "system_auth_logs",
            self._system_auth_logs_impl,
            (
                "Retrieve authentication and login events. "
                "Reads /var/log/auth.log or falls back to journalctl -u ssh. "
                "lines: number of log lines to return (1-10000, default 100)."
            ),
        )
        self._register_tool(
            "system_sessions",
            self._system_sessions_impl,
            (
                "List all currently active login sessions. "
                "Uses loginctl list-sessions and the w command. "
                "No parameters required."
            ),
        )
        self._register_tool(
            "system_disk_health",
            self._system_disk_health_impl,
            (
                "Check drive health using SMART data via smartctl. "
                "Falls back to basic disk usage (df -h) when smartctl is not "
                "installed. No parameters required."
            ),
        )
        self._register_tool(
            "system_failed_services",
            self._system_failed_services_impl,
            (
                "List all systemd units currently in a failed state. "
                "Runs: systemctl list-units --failed --no-pager. "
                "No parameters required."
            ),
        )
        self._register_tool(
            "system_service_restart",
            self._system_service_restart_impl,
            (
                "Restart a named systemd service. "
                "name: service name (e.g. 'nginx', 'docker'). "
                "Uses the privileged mcp-service-restart wrapper script. "
                "MODERATE risk — auto-approved."
            ),
        )
        self._register_tool(
            "system_service_toggle",
            self._system_service_toggle_impl,
            (
                "Enable or disable the autostart of a systemd service. "
                "name: service name. "
                "enabled: true to enable, false to disable. "
                "dry_run: if true, describe the action without executing it. "
                "ELEVATED risk — requires confirmation."
            ),
        )
        self._register_tool(
            "system_update_apply",
            self._system_update_apply_impl,
            (
                "Apply all pending system package updates via apt. "
                "dry_run: if true, list upgradable packages without installing. "
                "CRITICAL risk — requires confirmation."
            ),
        )
        self._register_tool(
            "system_package_install",
            self._system_package_install_impl,
            (
                "Install a single package via apt. "
                "name: package name following Debian naming policy. "
                "dry_run: if true, show apt-cache info without installing. "
                "CRITICAL risk — requires confirmation."
            ),
        )
        self._register_tool(
            "system_firewall_edit",
            self._system_firewall_edit_impl,
            (
                "Add or delete a UFW firewall rule. "
                "rule: UFW rule string (e.g. 'allow 80/tcp', 'delete allow 80'). "
                "dry_run: if true, describe the action without applying it. "
                "NEVER deletes rules protecting ports in security.protected_ports "
                "(default: SSH port 22). "
                "CRITICAL risk — requires confirmation."
            ),
        )
        self._register_tool(
            "system_reboot",
            self._system_reboot_impl,
            (
                "Reboot the server immediately. "
                "dry_run: if true, return a warning message without rebooting. "
                "CRITICAL risk — requires confirmation."
            ),
        )

    # ------------------------------------------------------------------
    # READ tool implementations
    # ------------------------------------------------------------------

    def _system_query_impl(self, scope: str, target: str | None = None) -> str:
        """Survey the system according to the requested scope.

        Args:
            scope: One of ``info``, ``processes``, ``services``, ``updates``,
                or ``firewall``.
            target: Optional filter string used in ``processes`` and
                ``services`` scopes.

        Returns:
            Structured plain-text report for the requested scope.
        """
        try:
            validated = SystemQueryInput(scope=scope, target=target)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        scope_map = {
            "info": self._query_info,
            "processes": self._query_processes,
            "services": self._query_services,
            "updates": self._query_updates,
            "firewall": self._query_firewall,
        }
        handler = scope_map[validated.scope]
        return handler(validated.target)

    def _system_logs_impl(self, source: str, lines: int = 100) -> str:
        """Fetch recent journal entries for a systemd unit.

        Args:
            source: Systemd unit / syslog identifier to query.
            lines: Number of log lines to return.

        Returns:
            Plain-text log output or an error description.
        """
        try:
            validated = SystemLogsInput(source=source, lines=lines)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        r = safe_run(
            [
                "journalctl",
                "-u",
                validated.source,
                "-n",
                str(validated.lines),
                "--no-pager",
            ],
            timeout=30,
        )
        header = f"=== Logs: {validated.source} (last {validated.lines} lines) ==="
        if r.returncode != 0:
            return f"{header}\nError: {r.stderr.strip()}"
        output = r.stdout.strip() or "(no entries found)"
        return f"{header}\n{output}"

    def _system_auth_logs_impl(self, lines: int = 100) -> str:
        """Retrieve authentication and login events.

        Attempts to read ``/var/log/auth.log`` directly (last *lines* lines).
        Falls back to ``journalctl -u ssh`` when the file is not available.

        Args:
            lines: Number of log lines to return.

        Returns:
            Plain-text auth log output.
        """
        try:
            validated = SystemLogsInput(source="auth", lines=lines)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        header = f"=== Auth Logs (last {validated.lines} lines) ==="

        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            try:
                all_lines = auth_log.read_text(encoding="utf-8", errors="replace").splitlines()
                tail = all_lines[-validated.lines :] if len(all_lines) > validated.lines else all_lines
                content = "\n".join(tail) if tail else "(no entries found)"
                return f"{header}\nSource: /var/log/auth.log\n{content}"
            except OSError as exc:
                # Permission denied or other read error — fall through to journalctl
                pass

        # Fallback: journalctl for ssh unit
        r = safe_run(
            ["journalctl", "-u", "ssh", "-n", str(validated.lines), "--no-pager"],
            timeout=30,
        )
        if r.returncode == 0:
            output = r.stdout.strip() or "(no entries found)"
            return f"{header}\nSource: journalctl -u ssh\n{output}"

        # Last resort: try sshd unit name
        r2 = safe_run(
            ["journalctl", "-u", "sshd", "-n", str(validated.lines), "--no-pager"],
            timeout=30,
        )
        if r2.returncode == 0:
            output = r2.stdout.strip() or "(no entries found)"
            return f"{header}\nSource: journalctl -u sshd\n{output}"

        return f"{header}\nCould not retrieve auth logs: {r.stderr.strip()}"

    def _system_sessions_impl(self) -> str:
        """List active login sessions using loginctl and w.

        Returns:
            Plain-text section with session data from both commands.
        """
        parts = ["=== Active Sessions ==="]

        r = safe_run(["loginctl", "list-sessions", "--no-pager"], timeout=10)
        if r.returncode == 0:
            parts.append("loginctl:\n" + (r.stdout.strip() or "(no active sessions)"))
        else:
            parts.append(f"loginctl error: {r.stderr.strip()}")

        r2 = safe_run(["w"], timeout=10)
        if r2.returncode == 0:
            parts.append("w:\n" + (r2.stdout.strip() or "(no logged-in users)"))
        else:
            parts.append(f"w error: {r2.stderr.strip()}")

        return "\n\n".join(parts)

    def _system_disk_health_impl(self) -> str:
        """Report drive health using SMART data or basic disk usage.

        Tries ``smartctl -H /dev/sda`` first.  Falls back to ``df -h`` when
        smartctl is not installed on the system.

        Returns:
            Plain-text drive health report.
        """
        parts = ["=== Disk Health ==="]

        # Attempt SMART health check
        r = safe_run(["smartctl", "-H", "/dev/sda"], timeout=15)
        if r.returncode != -1:
            # smartctl was found (may still return non-zero exit for degraded drives)
            parts.append("SMART (smartctl -H /dev/sda):\n" + r.stdout.strip())
            if r.stderr.strip():
                parts.append(f"stderr: {r.stderr.strip()}")
        else:
            # smartctl not found or permission error — use basic df
            parts.append("smartctl not available — falling back to disk usage")
            r2 = safe_run(["df", "-h"], timeout=10)
            if r2.returncode == 0:
                parts.append("Disk Usage (df -h):\n" + r2.stdout.strip())
            else:
                parts.append(f"df error: {r2.stderr.strip()}")

        return "\n\n".join(parts)

    def _system_failed_services_impl(self) -> str:
        """List all systemd units currently in a failed state.

        Returns:
            Plain-text list of failed units.
        """
        r = safe_run(
            ["systemctl", "list-units", "--failed", "--no-pager"],
            timeout=15,
        )
        header = "=== Failed Services ==="
        if r.returncode != 0:
            return f"{header}\nError: {r.stderr.strip()}"
        output = r.stdout.strip() or "(no failed units)"
        return f"{header}\n{output}"

    # ------------------------------------------------------------------
    # MODERATE tool implementation
    # ------------------------------------------------------------------

    def _system_service_restart_impl(self, name: str) -> str:
        """Restart a named systemd service via the privileged wrapper script.

        Args:
            name: Systemd service name.

        Returns:
            Plain-text result string.
        """
        try:
            validated = SystemServiceInput(name=name)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        r = safe_run_sudo("/usr/local/bin/mcp-service-restart", [validated.name])
        header = f"=== Service Restart: {validated.name} ==="
        if r.returncode != 0:
            return f"{header}\nFAILED — {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip() or 'Service restarted successfully.'}"

    # ------------------------------------------------------------------
    # ELEVATED tool implementation
    # ------------------------------------------------------------------

    def _system_service_toggle_impl(
        self,
        name: str,
        enabled: bool,
        dry_run: bool = False,
    ) -> str:
        """Enable or disable the autostart of a systemd service.

        Args:
            name: Systemd service name.
            enabled: ``True`` to enable, ``False`` to disable.
            dry_run: When ``True``, describe the intended action without
                executing it.

        Returns:
            Plain-text result or dry-run description.
        """
        try:
            validated = SystemServiceToggleInput(name=name, enabled=enabled, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        action = "enable" if validated.enabled else "disable"
        header = f"=== Service Toggle: {validated.name} ({action}) ==="

        if validated.dry_run:
            return (
                f"{header}\n"
                f"DRY RUN — would run: mcp-service-toggle {validated.name} {action}\n"
                f"Effect: systemd autostart for '{validated.name}' would be {action}d."
            )

        r = safe_run_sudo("/usr/local/bin/mcp-service-toggle", [validated.name, action])
        if r.returncode != 0:
            return f"{header}\nFAILED — {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip() or f'Service {validated.name} {action}d successfully.'}"

    # ------------------------------------------------------------------
    # CRITICAL tool implementations
    # ------------------------------------------------------------------

    def _system_update_apply_impl(self, dry_run: bool = False) -> str:
        """Apply pending system package updates via apt.

        Args:
            dry_run: When ``True``, list upgradable packages without installing.

        Returns:
            Plain-text result or list of upgradable packages.
        """
        try:
            validated = SystemUpdateApplyInput(dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        header = "=== System Update ==="

        if validated.dry_run:
            r = safe_run(["apt", "list", "--upgradable"], timeout=60)
            if r.returncode != 0:
                return f"{header}\nDRY RUN — Could not list upgradable packages: {r.stderr.strip()}"
            output = r.stdout.strip() or "(no upgradable packages)"
            return f"{header}\nDRY RUN — Upgradable packages:\n{output}"

        r = safe_run_sudo("/usr/local/bin/mcp-apt-upgrade", [], timeout=600)
        if r.returncode != 0:
            return f"{header}\nFAILED — {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip() or 'System packages updated successfully.'}"

    def _system_package_install_impl(self, name: str, dry_run: bool = False) -> str:
        """Install a single apt package.

        Args:
            name: Package name following Debian naming policy.
            dry_run: When ``True``, show apt-cache info without installing.

        Returns:
            Plain-text result or package info.
        """
        try:
            validated = SystemPackageInstallInput(name=name, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        header = f"=== Package Install: {validated.name} ==="

        if validated.dry_run:
            r = safe_run(["apt-cache", "show", validated.name], timeout=30)
            if r.returncode != 0:
                return f"{header}\nDRY RUN — Package not found: {r.stderr.strip()}"
            return f"{header}\nDRY RUN — Package info:\n{r.stdout.strip()}"

        r = safe_run_sudo(
            "/usr/local/bin/mcp-apt-install",
            [validated.name],
            timeout=300,
        )
        if r.returncode != 0:
            return f"{header}\nFAILED — {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip() or f'Package {validated.name!r} installed successfully.'}"

    def _system_firewall_edit_impl(self, rule: str, dry_run: bool = False) -> str:
        """Add or delete a UFW firewall rule.

        Protected ports (from ``config.security.protected_ports``, default
        ``[22]``) cannot be removed.  Any rule that would delete or deny a
        protected port is refused before the wrapper script is called.

        Args:
            rule: UFW rule string (e.g. ``"allow 80/tcp"`` or
                ``"delete allow 80"``).
            dry_run: When ``True``, describe the action without applying it.

        Returns:
            Plain-text result, dry-run description, or refusal message.
        """
        try:
            validated = SystemFirewallEditInput(rule=rule, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        header = f"=== Firewall Edit: {validated.rule} ==="

        # ------------------------------------------------------------------
        # Protected-port guard: refuse to delete/deny rules for SSH (port 22)
        # or any other port in config.security.protected_ports.
        # ------------------------------------------------------------------
        protected_ports: list[int] = self._config.security.protected_ports
        if self._rule_affects_protected_port(validated.rule, protected_ports):
            port_list = ", ".join(str(p) for p in protected_ports)
            return (
                f"{header}\n"
                f"REFUSED — This rule would affect a protected port ({port_list}). "
                f"Modifying protected ports is not allowed to prevent loss of remote access."
            )

        if validated.dry_run:
            return (
                f"{header}\n"
                f"DRY RUN — would run: mcp-ufw-edit {validated.rule}\n"
                f"Effect: UFW rule '{validated.rule}' would be applied."
            )

        r = safe_run_sudo("/usr/local/bin/mcp-ufw-edit", validated.rule.split())
        if r.returncode != 0:
            return f"{header}\nFAILED — {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip() or 'Firewall rule applied successfully.'}"

    def _system_reboot_impl(self, dry_run: bool = False) -> str:
        """Reboot the server.

        Args:
            dry_run: When ``True``, return a warning without rebooting.

        Returns:
            Plain-text result or dry-run warning message.
        """
        try:
            validated = SystemRebootInput(dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"[VALIDATION ERROR] {exc}"

        header = "=== System Reboot ==="

        if validated.dry_run:
            return (
                f"{header}\n"
                "DRY RUN — WARNING: Executing this tool without dry_run=True will "
                "immediately reboot the server and terminate all active connections and "
                "running processes.  Ensure all critical work is saved before proceeding."
            )

        r = safe_run_sudo("/usr/local/bin/mcp-reboot", [])
        if r.returncode != 0:
            return f"{header}\nFAILED — {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip() or 'Reboot initiated.'}"

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _query_info(self, target: str | None) -> str:
        """Collect basic system identity and resource information.

        Args:
            target: Unused for this scope; accepted for uniform signature.

        Returns:
            Plain-text section starting with ``=== System Info ===``.
        """
        parts = ["=== System Info ==="]

        r = safe_run(["hostname", "-f"], timeout=5)
        if r.returncode == 0:
            parts.append(f"Hostname: {r.stdout.strip()}")

        r = safe_run(["uname", "-srm"], timeout=5)
        if r.returncode == 0:
            parts.append(f"Kernel:   {r.stdout.strip()}")

        # OS pretty name — read file directly; no subprocess overhead.
        try:
            with open("/etc/os-release", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                        parts.append(f"OS:       {os_name}")
                        break
        except OSError:
            pass

        r = safe_run(["nproc"], timeout=5)
        if r.returncode == 0:
            parts.append(f"CPUs:     {r.stdout.strip()}")

        r = safe_run(["free", "-h", "--si"], timeout=5)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.startswith("Mem:"):
                    parts.append(f"Memory:   {line}")
                    break

        r = safe_run(["uptime", "-p"], timeout=5)
        if r.returncode == 0:
            parts.append(f"Uptime:   {r.stdout.strip()}")

        return "\n".join(parts)

    def _query_processes(self, target: str | None) -> str:
        """List running processes, sorted by memory usage.

        Args:
            target: Optional substring to filter process output.

        Returns:
            Plain-text section starting with ``=== Processes ===``.
        """
        r = safe_run(["ps", "aux", "--sort=-%mem"], timeout=15)
        header = "=== Processes ==="
        if r.returncode != 0:
            return f"{header}\nError: {r.stderr.strip()}"

        lines = r.stdout.splitlines()
        if target:
            # Always keep the header row (first line)
            header_row = lines[:1]
            filtered = [ln for ln in lines[1:] if target.lower() in ln.lower()]
            content = "\n".join(header_row + filtered) if filtered else f"(no processes matching '{target}')"
        else:
            content = r.stdout.strip()

        return f"{header}\n{content}"

    def _query_services(self, target: str | None) -> str:
        """List systemd service units.

        Args:
            target: Optional substring to filter service output.

        Returns:
            Plain-text section starting with ``=== Services ===``.
        """
        r = safe_run(
            ["systemctl", "list-units", "--type=service", "--no-pager"],
            timeout=15,
        )
        header = "=== Services ==="
        if r.returncode != 0:
            return f"{header}\nError: {r.stderr.strip()}"

        lines = r.stdout.splitlines()
        if target:
            header_rows = lines[:1]
            filtered = [ln for ln in lines[1:] if target.lower() in ln.lower()]
            content = "\n".join(header_rows + filtered) if filtered else f"(no services matching '{target}')"
        else:
            content = r.stdout.strip()

        return f"{header}\n{content}"

    def _query_updates(self, target: str | None) -> str:
        """List packages with available upgrades via apt.

        Args:
            target: Unused for this scope.

        Returns:
            Plain-text section starting with ``=== Available Updates ===``.
        """
        r = safe_run(["apt", "list", "--upgradable"], timeout=60)
        header = "=== Available Updates ==="
        if r.returncode != 0:
            return f"{header}\nError: {r.stderr.strip()}"
        output = r.stdout.strip() or "(no upgradable packages)"
        return f"{header}\n{output}"

    def _query_firewall(self, target: str | None) -> str:
        """Report the current UFW firewall status.

        Args:
            target: Unused for this scope.

        Returns:
            Plain-text section starting with ``=== Firewall ==="```.
        """
        r = safe_run(["ufw", "status", "verbose"], timeout=10)
        header = "=== Firewall ==="
        if r.returncode != 0:
            return f"{header}\nError: {r.stderr.strip()}"
        return f"{header}\n{r.stdout.strip()}"

    @staticmethod
    def _rule_affects_protected_port(rule: str, protected_ports: list[int]) -> bool:
        """Return ``True`` if *rule* would affect any of the *protected_ports*.

        Checks for delete/deny/reject operations on a rule that explicitly
        references one of the protected port numbers.  Allow rules for protected
        ports are permitted (they reinforce access).

        Detection heuristic:
        - If the lowercase rule contains ``delete`` or ``deny`` or ``reject``
          AND any protected port number appears as a token in the rule string,
          the rule is considered dangerous.

        Args:
            rule: UFW rule string as provided by the caller.
            protected_ports: List of port numbers that must not be blocked.

        Returns:
            ``True`` when the rule would endanger remote access to a protected
            port.
        """
        lower = rule.lower()
        # Only restrict delete, deny, or reject operations
        dangerous_ops = ("delete", "deny", "reject")
        if not any(op in lower for op in dangerous_ops):
            return False

        # Extract all numeric tokens from the rule and compare against
        # protected ports.  We use a simple digit-boundary regex so that port
        # "22" is not matched inside "220" or "1022".
        tokens = re.findall(r"\b(\d+)\b", rule)
        for token in tokens:
            try:
                if int(token) in protected_ports:
                    return True
            except ValueError:
                continue
        return False
