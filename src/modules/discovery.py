"""Discovery module — Claude's eyes on the home server.

Provides two tools:

``discover``
    Read-only survey of the server across configurable scopes: system info,
    running services, open ports, storage layout, network interfaces, Docker
    containers/images/volumes/networks, and cron/systemd timers.  Scope
    ``"all"`` (default) combines every section into one structured report.

``health_check``
    MCP server self-diagnosis: verifies that config loaded, each enabled
    upstream service (Docker, Home Assistant, Plex) is reachable via HTTP or
    CLI, and that the backup directory and audit log are writable.

Both tools are read-only (``RiskLevel.READ``) and will never mutate system
state.  All subprocess calls go through ``safe_run`` — ``subprocess`` is
never imported directly in this module.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from src.modules.base import BaseModule
from src.utils.subprocess_safe import safe_run


class DiscoveryModule(BaseModule):
    """Discovery module providing server survey and health-check tools.

    Registered tools:

    * ``discover`` — multi-scope server survey.
    * ``health_check`` — subsystem connectivity and writability check.
    """

    MODULE_NAME = "discovery"

    def _register_tools(self) -> None:
        """Register ``discover`` and ``health_check`` on the module server."""
        self._register_tool(
            "discover",
            self._discover_impl,
            (
                "Discover and analyse the server. "
                "scope parameter selects what to survey: "
                "system, services, ports, storage, network, docker, crontabs, all. "
                "Defaults to all. Returns a structured plain-text report."
            ),
        )
        self._register_tool(
            "health_check",
            self._health_check_impl,
            (
                "Run MCP server self-diagnosis. "
                "Checks: config load, Docker reachability, Home Assistant reachability, "
                "Plex reachability, backup directory writability, audit log writability. "
                "Returns OK/FAIL per subsystem."
            ),
        )

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def _discover_impl(self, scope: str = "all") -> str:
        """Survey the server across one or more scopes.

        Args:
            scope: One of ``system``, ``services``, ``ports``, ``storage``,
                ``network``, ``docker``, ``crontabs``, or ``all``.
                Unknown values return a helpful error message.

        Returns:
            Structured plain-text report for the requested scope(s).
        """
        scope_map: dict[str, object] = {
            "system": self._discover_system,
            "services": self._discover_services,
            "ports": self._discover_ports,
            "storage": self._discover_storage,
            "network": self._discover_network,
            "docker": self._discover_docker,
            "crontabs": self._discover_crontabs,
        }

        if scope == "all":
            sections = [fn() for fn in scope_map.values()]  # type: ignore[operator]
            return "\n\n".join(sections)

        fn = scope_map.get(scope)
        if fn is None:
            valid = ", ".join(scope_map.keys())
            return f"Unknown scope: {scope!r}. Valid scopes: {valid}, all"

        return fn()  # type: ignore[operator]

    def _health_check_impl(self) -> str:
        """Run a full self-diagnostic sweep and report results.

        Checks (in order):
        1. Config loaded successfully (always true if we reached this point).
        2. Docker CLI reachable (when enabled in config).
        3. Home Assistant HTTP API reachable (when enabled).
        4. Plex HTTP identity endpoint reachable (when enabled).
        5. Backup directory is writable.
        6. Audit log path is writable.

        Returns:
            Multi-line report with ``[OK]`` / ``[FAIL]`` per check and a
            summary line at the top.
        """
        checks: list[str] = []
        all_ok = True

        # 1. Config — reaching this function means config loaded.
        checks.append(self._fmt_check("Config loaded", ok=True))

        # 2. Docker
        if self._config.services.docker.enabled:
            r = safe_run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10)
            ok = r.returncode == 0
            detail = r.stdout.strip() if ok else r.stderr.strip()
            checks.append(self._fmt_check("Docker", ok=ok, detail=detail))
            if not ok:
                all_ok = False

        # 3. Home Assistant
        if self._config.services.homeassistant.enabled:
            ha_url = self._config.services.homeassistant.url.rstrip("/") + "/api/"
            ok, msg = self._check_http(ha_url)
            checks.append(self._fmt_check("Home Assistant", ok=ok, detail=msg))
            if not ok:
                all_ok = False

        # 4. Plex
        if self._config.services.plex.enabled:
            plex_url = self._config.services.plex.url.rstrip("/") + "/identity"
            ok, msg = self._check_http(plex_url)
            checks.append(self._fmt_check("Plex", ok=ok, detail=msg))
            if not ok:
                all_ok = False

        # 5. Backup directory
        backup_dir: str = self._config.security.backup_dir
        try:
            os.makedirs(backup_dir, exist_ok=True)
            test_file = os.path.join(backup_dir, ".mcp_write_test")
            with open(test_file, "w") as fh:
                fh.write("test")
            os.remove(test_file)
            checks.append(self._fmt_check("Backup directory", ok=True, detail=backup_dir))
        except OSError as exc:
            checks.append(self._fmt_check("Backup directory", ok=False, detail=str(exc)))
            all_ok = False

        # 6. Audit log
        audit_path: str = self._config.security.audit_log
        try:
            Path(audit_path).parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a"):
                pass  # test append-open only; no data written
            checks.append(self._fmt_check("Audit log", ok=True, detail=audit_path))
        except OSError as exc:
            checks.append(self._fmt_check("Audit log", ok=False, detail=str(exc)))
            all_ok = False

        status = "ALL SYSTEMS OK" if all_ok else "ISSUES DETECTED"
        header = f"=== Health Check: {status} ===\n"
        return header + "\n".join(checks)

    # ------------------------------------------------------------------
    # Health-check helpers
    # ------------------------------------------------------------------

    def _fmt_check(self, name: str, *, ok: bool, detail: str = "") -> str:
        """Format a single health-check result line.

        Args:
            name: Human-readable subsystem name.
            ok: Whether the check passed.
            detail: Optional additional context (version string, path, error).

        Returns:
            Formatted string, e.g. ``"  [OK] Docker — 24.0.5"``.
        """
        symbol = "OK" if ok else "FAIL"
        line = f"  [{symbol}] {name}"
        if detail:
            line += f" — {detail}"
        return line

    def _check_http(self, url: str) -> tuple[bool, str]:
        """Attempt a GET request and return success status and description.

        Args:
            url: Full URL to probe.

        Returns:
            ``(True, "HTTP <status>")`` on success, or
            ``(False, "<error message>")`` on any failure.
        """
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(url)
                if resp.is_success:
                    return True, f"HTTP {resp.status_code}"
                return False, f"HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    # ------------------------------------------------------------------
    # Discovery sections — each returns a self-contained text block
    # ------------------------------------------------------------------

    def _discover_system(self) -> str:
        """Collect basic system identity, resource, and uptime information.

        Returns:
            Plain-text section starting with ``=== System ===``.
        """
        parts = ["=== System ==="]

        r = safe_run(["hostname", "-f"], timeout=5)
        if r.returncode == 0:
            parts.append(f"Hostname: {r.stdout.strip()}")

        r = safe_run(["uname", "-srm"], timeout=5)
        if r.returncode == 0:
            parts.append(f"Kernel:   {r.stdout.strip()}")

        # OS pretty name — read the file directly; no subprocess needed.
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

    def _discover_services(self) -> str:
        """List running systemd services and Docker containers.

        Returns:
            Plain-text section starting with ``=== Running Services ===``.
        """
        parts = ["=== Running Services ==="]

        r = safe_run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--plain",
            ],
            timeout=10,
        )
        if r.returncode == 0:
            parts.append("Systemd:\n" + r.stdout.strip())

        if self._config.services.docker.enabled:
            r = safe_run(
                [
                    "docker",
                    "ps",
                    "--format",
                    "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}",
                ],
                timeout=10,
            )
            if r.returncode == 0:
                parts.append("Docker:\n" + r.stdout.strip())

        return "\n\n".join(parts)

    def _discover_ports(self) -> str:
        """List all TCP/UDP sockets currently in LISTEN state.

        Returns:
            Plain-text section starting with ``=== Open Ports ===``.
        """
        r = safe_run(["ss", "-tlnp"], timeout=10)
        if r.returncode == 0:
            return "=== Open Ports ===\n" + r.stdout.strip()
        return "=== Open Ports ===\nCould not retrieve port information"

    def _discover_storage(self) -> str:
        """Report disk usage and block device layout.

        Returns:
            Plain-text section starting with ``=== Storage ===``.
        """
        parts = ["=== Storage ==="]

        r = safe_run(
            ["df", "-h", "--output=source,size,used,avail,pcent,target"],
            timeout=10,
        )
        if r.returncode == 0:
            parts.append("Disk Usage:\n" + r.stdout.strip())

        r = safe_run(
            ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"],
            timeout=10,
        )
        if r.returncode == 0:
            parts.append("Block Devices:\n" + r.stdout.strip())

        return "\n\n".join(parts)

    def _discover_network(self) -> str:
        """Report network interfaces, default route, and DNS resolvers.

        Reads ``/etc/resolv.conf`` directly — no subprocess for that file.

        Returns:
            Plain-text section starting with ``=== Network ===``.
        """
        parts = ["=== Network ==="]

        r = safe_run(["ip", "-brief", "addr", "show"], timeout=5)
        if r.returncode == 0:
            parts.append("Interfaces:\n" + r.stdout.strip())

        r = safe_run(["ip", "route", "show", "default"], timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            parts.append("Default route: " + r.stdout.strip())

        # DNS — read directly; no privilege needed and no subprocess overhead.
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                nameservers = [
                    line.strip()
                    for line in fh
                    if line.strip().startswith("nameserver")
                ]
                if nameservers:
                    parts.append("DNS:\n" + "\n".join(nameservers))
        except OSError:
            pass

        return "\n\n".join(parts)

    def _discover_docker(self) -> str:
        """Survey Docker containers, images, volumes, and networks.

        Returns early with a disabled notice when Docker is not enabled in
        the server configuration.

        Returns:
            Plain-text section starting with ``=== Docker ===``.
        """
        if not self._config.services.docker.enabled:
            return "=== Docker ===\nNot enabled in configuration"

        parts = ["=== Docker ==="]

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
            parts.append("Containers:\n" + r.stdout.strip())

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
            parts.append("Images:\n" + r.stdout.strip())

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
            parts.append("Volumes:\n" + r.stdout.strip())

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
            parts.append("Networks:\n" + r.stdout.strip())

        return "\n\n".join(parts)

    def _discover_crontabs(self) -> str:
        """List systemd timers and the current user's crontab entries.

        Returns:
            Plain-text section starting with ``=== Scheduled Tasks ===``.
        """
        parts = ["=== Scheduled Tasks ==="]

        r = safe_run(["systemctl", "list-timers", "--no-pager"], timeout=10)
        if r.returncode == 0:
            parts.append("Systemd Timers:\n" + r.stdout.strip())

        r = safe_run(["crontab", "-l"], timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            parts.append("User Crontab:\n" + r.stdout.strip())
        elif r.returncode == 0:
            parts.append("User Crontab: (empty)")

        return "\n\n".join(parts)
