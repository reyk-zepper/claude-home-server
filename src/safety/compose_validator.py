"""Docker Compose security validator for claude-home-server.

Analyses a parsed Docker Compose dict for dangerous configuration patterns
and returns a list of :class:`ComposeViolation` objects.  The validator is
intentionally *standalone* — it operates on an already-parsed ``dict`` so
that callers can run it before writing any file to disk.

Security model
--------------
Every service definition is checked for two classes of problems:

**Critical violations** — patterns that grant dangerous kernel or host access
and MUST block the operation:

* ``privileged: true``
* ``cap_add`` (any capability escalation)
* ``network_mode: host``
* ``pid: host``
* ``ipc: host``
* ``devices`` (direct device access)
* ``sysctls`` (kernel parameter changes)
* Volume mounts to sensitive host paths (``/``, ``/etc``, ``/root``,
  ``/proc``, ``/sys``, ``/dev``, ``/var/run/docker.sock``)

**Warnings** — patterns that are not inherently exploitable but indicate
potential misconfigurations that should be surfaced to the operator:

* Volume mounts outside the configured allowed prefixes
* ``restart: no`` (service will not auto-recover)
* No resource limits defined (``deploy.resources.limits``)
* ``DOCKER_HOST`` or ``DOCKER_SOCKET`` in environment

Compose format support
----------------------
Both the modern format (``services:`` at the top level, no ``version:`` key)
and the legacy format (``version:`` + ``services:``) are handled identically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Volume mount paths that are always critical regardless of configuration
# ---------------------------------------------------------------------------

_CRITICAL_HOST_PATHS: frozenset[str] = frozenset(
    [
        "/",
        "/etc",
        "/root",
        "/proc",
        "/sys",
        "/dev",
        "/var/run/docker.sock",
    ]
)

# Environment variable names that indicate docker socket exposure
_DOCKER_ENV_KEYS: frozenset[str] = frozenset(["DOCKER_HOST", "DOCKER_SOCKET"])


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ComposeViolation:
    """A single security violation found while validating a compose file.

    Attributes:
        service: Name of the service containing the violation.
        field: The compose field path that caused the violation
            (e.g. ``"privileged"``, ``"volumes[0]"``).
        severity: Either ``"critical"`` (must block) or ``"warning"``
            (should surface to the operator).
        message: Human-readable description of what was found and why it
            matters.
    """

    service: str
    field: str
    severity: str  # "critical" | "warning"
    message: str


@dataclass
class ValidationResult:
    """Aggregated result of a compose file validation pass.

    Attributes:
        violations: All violations found, ordered by (service, field).
        passed: ``True`` only when there are no critical violations.
    """

    violations: list[ComposeViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Return True when no critical violations are present."""
        return not any(v.severity == "critical" for v in self.violations)

    @property
    def critical_count(self) -> int:
        """Number of critical violations."""
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def warning_count(self) -> int:
        """Number of warning violations."""
        return sum(1 for v in self.violations if v.severity == "warning")

    def format_report(self) -> str:
        """Format a human-readable multi-line validation report.

        Returns:
            A plain-text report string suitable for returning to Claude.
        """
        if not self.violations:
            return "=== Compose Validation: PASSED ===\nNo security violations found."

        lines = [
            f"=== Compose Validation: {'PASSED' if self.passed else 'BLOCKED'} ===",
            f"Critical violations: {self.critical_count}",
            f"Warnings: {self.warning_count}",
            "",
        ]

        for viol in self.violations:
            symbol = "[CRITICAL]" if viol.severity == "critical" else "[WARNING]"
            lines.append(f"  {symbol} {viol.service}.{viol.field}: {viol.message}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class ComposeValidator:
    """Validate a parsed Docker Compose dict for dangerous configuration.

    Args:
        allowed_volume_prefixes: Host path prefixes that are explicitly
            permitted for volume mounts.  Mounts whose host path does not
            start with one of these prefixes produce a ``warning`` violation.
            Dangerous paths (e.g. ``/etc``) are always ``critical`` regardless
            of this list.  Defaults to an empty list (all non-critical mounts
            produce a warning).

    Example::

        validator = ComposeValidator(allowed_volume_prefixes=["/srv/data", "/media"])
        result = validator.validate(parsed_yaml_dict)
        if not result.passed:
            print(result.format_report())
    """

    def __init__(
        self,
        allowed_volume_prefixes: list[str] | None = None,
    ) -> None:
        self._allowed_volumes: list[str] = allowed_volume_prefixes or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, compose_data: dict[str, Any]) -> ValidationResult:
        """Validate a parsed compose dict and return all violations found.

        Handles both the modern (no ``version:`` key) and legacy
        (``version:`` + ``services:``) formats transparently.

        Args:
            compose_data: A Python dict produced by ``yaml.safe_load`` of
                a ``docker-compose.yml`` / ``compose.yaml`` file.

        Returns:
            A :class:`ValidationResult` containing all violations found.
            The ``passed`` property is ``True`` when no critical violations
            were found.
        """
        result = ValidationResult()

        if not isinstance(compose_data, dict):
            result.violations.append(
                ComposeViolation(
                    service="<root>",
                    field="<document>",
                    severity="critical",
                    message="Compose file must be a YAML mapping at the top level.",
                )
            )
            return result

        services = compose_data.get("services", {})
        if not isinstance(services, dict):
            result.violations.append(
                ComposeViolation(
                    service="<root>",
                    field="services",
                    severity="critical",
                    message="'services' must be a mapping.",
                )
            )
            return result

        for service_name, service_def in services.items():
            if not isinstance(service_def, dict):
                # Allow null/empty service definitions (valid compose syntax)
                continue
            self._check_service(str(service_name), service_def, result)

        return result

    # ------------------------------------------------------------------
    # Per-service checks
    # ------------------------------------------------------------------

    def _check_service(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Run all checks for a single service definition.

        Args:
            service_name: Name of the service being checked.
            service_def: The service's configuration dict.
            result: Accumulator — violations are appended here.
        """
        self._check_privileged(service_name, service_def, result)
        self._check_cap_add(service_name, service_def, result)
        self._check_network_mode(service_name, service_def, result)
        self._check_pid(service_name, service_def, result)
        self._check_ipc(service_name, service_def, result)
        self._check_devices(service_name, service_def, result)
        self._check_sysctls(service_name, service_def, result)
        self._check_volumes(service_name, service_def, result)
        self._check_restart_policy(service_name, service_def, result)
        self._check_resource_limits(service_name, service_def, result)
        self._check_environment(service_name, service_def, result)

    def _check_privileged(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block ``privileged: true``.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        if service_def.get("privileged") is True:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="privileged",
                    severity="critical",
                    message=(
                        "privileged: true grants full root access to the host "
                        "kernel. This is a critical security risk."
                    ),
                )
            )

    def _check_cap_add(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block any ``cap_add`` entry — all capability escalation is denied.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        cap_add = service_def.get("cap_add")
        if cap_add is None:
            return
        if not isinstance(cap_add, list):
            cap_add = [cap_add]
        for cap in cap_add:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="cap_add",
                    severity="critical",
                    message=(
                        f"cap_add: {cap!r} grants elevated Linux capabilities "
                        "that can be used to escape the container. "
                        "Remove all cap_add entries."
                    ),
                )
            )

    def _check_network_mode(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block ``network_mode: host``.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        network_mode = service_def.get("network_mode", "")
        if str(network_mode).lower() == "host":
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="network_mode",
                    severity="critical",
                    message=(
                        "network_mode: host shares the host's network stack. "
                        "This bypasses Docker's network isolation entirely."
                    ),
                )
            )

    def _check_pid(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block ``pid: host``.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        pid = service_def.get("pid", "")
        if str(pid).lower() == "host":
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="pid",
                    severity="critical",
                    message=(
                        "pid: host shares the host PID namespace. "
                        "The container can see and signal all host processes."
                    ),
                )
            )

    def _check_ipc(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block ``ipc: host``.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        ipc = service_def.get("ipc", "")
        if str(ipc).lower() == "host":
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="ipc",
                    severity="critical",
                    message=(
                        "ipc: host shares the host IPC namespace. "
                        "This enables inter-process communication with host processes."
                    ),
                )
            )

    def _check_devices(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block any ``devices`` entry — direct device access is denied.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        devices = service_def.get("devices")
        if not devices:
            return
        if not isinstance(devices, list):
            devices = [devices]
        for device in devices:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="devices",
                    severity="critical",
                    message=(
                        f"devices: {device!r} exposes a host device directly "
                        "to the container. Direct device access is not permitted."
                    ),
                )
            )

    def _check_sysctls(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Block any ``sysctls`` entry — kernel parameter changes are denied.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        sysctls = service_def.get("sysctls")
        if not sysctls:
            return
        result.violations.append(
            ComposeViolation(
                service=service_name,
                field="sysctls",
                severity="critical",
                message=(
                    "sysctls modifies kernel parameters for the container. "
                    "This can affect host stability and bypass security controls."
                ),
            )
        )

    def _check_volumes(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Validate volume mounts for dangerous host paths.

        Critical: mounts to paths in ``_CRITICAL_HOST_PATHS``.
        Warning: mounts outside the configured allowed prefixes.

        Handles both short syntax (``"./data:/app/data"``) and long syntax
        (``{type: bind, source: /host/path, target: /app/path}``).

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        volumes = service_def.get("volumes")
        if not volumes:
            return
        if not isinstance(volumes, list):
            return

        for idx, vol in enumerate(volumes):
            host_path = self._extract_host_path(vol)
            if host_path is None:
                # Named volume (no host path) — safe
                continue

            field_ref = f"volumes[{idx}]"

            # Check critical dangerous paths
            if self._is_critical_path(host_path):
                result.violations.append(
                    ComposeViolation(
                        service=service_name,
                        field=field_ref,
                        severity="critical",
                        message=(
                            f"Volume mount to {host_path!r} is forbidden. "
                            "Mounting sensitive host paths can expose secrets "
                            "or allow container escape."
                        ),
                    )
                )
                continue

            # Check against allowed prefixes — warn if outside
            if not self._is_allowed_volume(host_path):
                result.violations.append(
                    ComposeViolation(
                        service=service_name,
                        field=field_ref,
                        severity="warning",
                        message=(
                            f"Volume mount {host_path!r} is outside the "
                            "configured allowed volume paths. "
                            "Verify this path is intentional."
                        ),
                    )
                )

    def _check_restart_policy(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Warn when ``restart: no`` is set.

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        restart = service_def.get("restart")
        if restart == "no" or restart is False:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="restart",
                    severity="warning",
                    message=(
                        "restart: no means this service will not auto-recover "
                        "after a crash or host reboot. Consider 'unless-stopped' "
                        "or 'always'."
                    ),
                )
            )

    def _check_resource_limits(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Warn when no resource limits are defined.

        Checks for ``deploy.resources.limits`` (compose v2/v3 style).

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        deploy = service_def.get("deploy")
        if deploy is None:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="deploy.resources.limits",
                    severity="warning",
                    message=(
                        "No resource limits configured. "
                        "Without CPU/memory limits, a single service can "
                        "consume all host resources."
                    ),
                )
            )
            return

        if not isinstance(deploy, dict):
            return

        resources = deploy.get("resources")
        if not isinstance(resources, dict):
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="deploy.resources.limits",
                    severity="warning",
                    message=(
                        "No resource limits configured in deploy.resources.limits. "
                        "Without CPU/memory limits, a single service can "
                        "consume all host resources."
                    ),
                )
            )
            return

        limits = resources.get("limits")
        if not limits:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field="deploy.resources.limits",
                    severity="warning",
                    message=(
                        "deploy.resources.limits is empty or not set. "
                        "Set cpus and memory limits to protect host resources."
                    ),
                )
            )

    def _check_environment(
        self,
        service_name: str,
        service_def: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Warn when DOCKER_HOST or DOCKER_SOCKET appear in environment.

        Handles both list form (``- DOCKER_HOST=...``) and mapping form
        (``DOCKER_HOST: ...``).

        Args:
            service_name: Service being checked.
            service_def: Service configuration mapping.
            result: Violation accumulator.
        """
        env = service_def.get("environment")
        if not env:
            return

        found_keys: list[str] = []

        if isinstance(env, dict):
            for key in env:
                if str(key).upper() in _DOCKER_ENV_KEYS:
                    found_keys.append(str(key))
        elif isinstance(env, list):
            for entry in env:
                # Entries may be "KEY=value" or just "KEY"
                key = str(entry).split("=", 1)[0].upper()
                if key in _DOCKER_ENV_KEYS:
                    found_keys.append(key)

        for key in found_keys:
            result.violations.append(
                ComposeViolation(
                    service=service_name,
                    field=f"environment.{key}",
                    severity="warning",
                    message=(
                        f"{key} in environment may expose the Docker socket or "
                        "allow the container to communicate with the Docker daemon. "
                        "Verify this is intentional."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_host_path(self, volume_entry: Any) -> str | None:
        """Extract the host path from a volume entry, or ``None`` for named volumes.

        Handles:
        * Short syntax: ``"./data:/container/path[:options]"``
        * Short syntax (host-only): ``"/host/path"``
        * Long syntax dict: ``{type: bind, source: /host/path, ...}``
        * Named volumes (no host path): returns ``None``

        Args:
            volume_entry: A single element from the ``volumes`` list.

        Returns:
            The host-side path string, or ``None`` for named volumes.
        """
        if isinstance(volume_entry, dict):
            vol_type = volume_entry.get("type", "")
            if vol_type == "bind":
                return volume_entry.get("source")
            # volume or tmpfs type — no dangerous host path
            return None

        if isinstance(volume_entry, str):
            # Short syntax: [host:]container[:options]
            parts = volume_entry.split(":")
            if len(parts) >= 2:  # noqa: PLR2004
                host_part = parts[0]
                # Named volumes don't start with / or . (e.g. "myvolume:/data")
                if host_part.startswith("/") or host_part.startswith("."):
                    return host_part
            elif len(parts) == 1:
                # Just a container path — no host path (anonymous volume)
                return None

        return None

    def _is_critical_path(self, host_path: str) -> bool:
        """Return True when the host path maps to a known-dangerous location.

        Checks for exact matches and for paths that are descendants of a
        critical path (e.g. ``/etc/shadow`` is a descendant of ``/etc``).

        Args:
            host_path: The host-side path from a volume mount.

        Returns:
            True if the path is critically dangerous.
        """
        # Normalise away trailing slashes for consistent comparison
        normalised = host_path.rstrip("/") or "/"

        if normalised in _CRITICAL_HOST_PATHS:
            return True

        # Check if it is a descendant of a critical path
        for critical in _CRITICAL_HOST_PATHS:
            if critical == "/":
                # "/" is a parent of everything — but the root itself is exact-matched above
                # Mounting / is critical; mounting /anything IS mounting inside /
                # Since all paths start with /, we need to be careful:
                # Only flag as critical if the mount IS "/" exactly (handled above)
                continue
            if normalised.startswith(critical + "/") or normalised == critical:
                return True

        return False

    def _is_allowed_volume(self, host_path: str) -> bool:
        """Return True when the host path is within a configured allowed prefix.

        Relative paths (starting with ``.``) are always considered potentially
        unsafe and return False unless an allowed prefix explicitly covers them.

        Args:
            host_path: The host-side path from a volume mount.

        Returns:
            True if the path falls within an allowed prefix.
        """
        if not self._allowed_volumes:
            return False

        normalised = host_path.rstrip("/") or "/"
        for prefix in self._allowed_volumes:
            norm_prefix = prefix.rstrip("/")
            if normalised == norm_prefix or normalised.startswith(norm_prefix + "/"):
                return True

        return False
