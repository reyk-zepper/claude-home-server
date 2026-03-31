"""Unit tests for src.safety.compose_validator.

Coverage targets:
  - Every critical block pattern individually
  - Every warning condition individually
  - Clean compose file passes validation
  - Both Compose v2 (no version key) and legacy v3 (version + services) formats
  - Volume mount: exact critical paths, descendant paths, named volumes
  - Volume mount: allowed prefix check
  - Environment variable detection (dict form and list form)
  - cap_add with multiple entries
  - Resource limits: no deploy, no resources, no limits
  - Non-dict service definition (null service)
  - Non-dict top-level document
  - ValidationResult.format_report for clean and violations cases
  - ValidationResult.passed, critical_count, warning_count
"""
from __future__ import annotations

import pytest

from src.safety.compose_validator import (
    ComposeValidator,
    ComposeViolation,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_validator(allowed: list[str] | None = None) -> ComposeValidator:
    """Return a validator with optional allowed_volume_prefixes."""
    return ComposeValidator(allowed_volume_prefixes=allowed)


def _service(overrides: dict) -> dict:
    """Build a minimal compose dict with a single 'app' service."""
    return {"services": {"app": overrides}}


def _violations(result: ValidationResult, severity: str | None = None) -> list[ComposeViolation]:
    """Filter violations by optional severity."""
    if severity is None:
        return result.violations
    return [v for v in result.violations if v.severity == severity]


# ---------------------------------------------------------------------------
# ValidationResult properties
# ---------------------------------------------------------------------------


class TestValidationResult:
    def test_passed_when_no_violations(self) -> None:
        result = ValidationResult()
        assert result.passed is True

    def test_passed_false_when_critical(self) -> None:
        result = ValidationResult(
            violations=[
                ComposeViolation(service="app", field="privileged", severity="critical", message="x")
            ]
        )
        assert result.passed is False

    def test_passed_true_with_only_warnings(self) -> None:
        result = ValidationResult(
            violations=[
                ComposeViolation(service="app", field="restart", severity="warning", message="x")
            ]
        )
        assert result.passed is True

    def test_critical_count(self) -> None:
        result = ValidationResult(
            violations=[
                ComposeViolation(service="a", field="f", severity="critical", message="m"),
                ComposeViolation(service="b", field="f", severity="warning", message="m"),
                ComposeViolation(service="c", field="f", severity="critical", message="m"),
            ]
        )
        assert result.critical_count == 2

    def test_warning_count(self) -> None:
        result = ValidationResult(
            violations=[
                ComposeViolation(service="a", field="f", severity="critical", message="m"),
                ComposeViolation(service="b", field="f", severity="warning", message="m"),
            ]
        )
        assert result.warning_count == 1

    def test_format_report_clean(self) -> None:
        result = ValidationResult()
        report = result.format_report()
        assert "PASSED" in report
        assert "No security violations" in report

    def test_format_report_with_critical(self) -> None:
        result = ValidationResult(
            violations=[
                ComposeViolation(
                    service="app", field="privileged", severity="critical", message="test message"
                )
            ]
        )
        report = result.format_report()
        assert "BLOCKED" in report
        assert "[CRITICAL]" in report
        assert "app.privileged" in report
        assert "test message" in report

    def test_format_report_with_warning_only(self) -> None:
        result = ValidationResult(
            violations=[
                ComposeViolation(service="app", field="restart", severity="warning", message="w")
            ]
        )
        report = result.format_report()
        assert "PASSED" in report
        assert "[WARNING]" in report


# ---------------------------------------------------------------------------
# Clean compose file
# ---------------------------------------------------------------------------


class TestCleanCompose:
    def test_minimal_clean_service_passes(self) -> None:
        data = {
            "services": {
                "app": {
                    "image": "nginx:latest",
                    "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}},
                    "restart": "unless-stopped",
                }
            }
        }
        result = _make_validator(["/srv"]).validate(data)
        # Only warnings (no volumes outside allowed) — no criticals
        criticals = _violations(result, "critical")
        assert criticals == []

    def test_empty_services_passes(self) -> None:
        result = _make_validator().validate({"services": {}})
        assert result.violations == []

    def test_null_service_definition_is_skipped(self) -> None:
        """Null service values are valid compose syntax (inherits from extends etc)."""
        data = {"services": {"app": None}}
        result = _make_validator().validate(data)
        assert result.violations == []


# ---------------------------------------------------------------------------
# Document structure validation
# ---------------------------------------------------------------------------


class TestDocumentStructure:
    def test_non_dict_top_level_is_critical(self) -> None:
        result = _make_validator().validate("not a dict")  # type: ignore[arg-type]
        assert any(v.severity == "critical" for v in result.violations)

    def test_non_dict_services_is_critical(self) -> None:
        result = _make_validator().validate({"services": "not a dict"})
        assert any(v.severity == "critical" for v in result.violations)

    def test_missing_services_returns_empty_violations(self) -> None:
        result = _make_validator().validate({"version": "3.8"})
        assert result.violations == []


# ---------------------------------------------------------------------------
# Compose format: v2 (no version) and legacy v3 (version + services)
# ---------------------------------------------------------------------------


class TestComposeFormats:
    def test_v2_format_no_version_key(self) -> None:
        data = {"services": {"app": {"privileged": True}}}
        result = _make_validator().validate(data)
        assert any(v.field == "privileged" and v.severity == "critical" for v in result.violations)

    def test_legacy_v3_format_with_version_key(self) -> None:
        data = {"version": "3.8", "services": {"app": {"privileged": True}}}
        result = _make_validator().validate(data)
        assert any(v.field == "privileged" and v.severity == "critical" for v in result.violations)

    def test_multiple_services_checked_independently(self) -> None:
        data = {
            "services": {
                "safe": {"image": "nginx:latest"},
                "dangerous": {"privileged": True},
            }
        }
        result = _make_validator().validate(data)
        service_names = [v.service for v in result.violations if v.severity == "critical"]
        assert "dangerous" in service_names
        assert "safe" not in service_names


# ---------------------------------------------------------------------------
# Critical: privileged
# ---------------------------------------------------------------------------


class TestPrivileged:
    def test_privileged_true_is_critical(self) -> None:
        result = _make_validator().validate(_service({"privileged": True}))
        assert any(v.field == "privileged" and v.severity == "critical" for v in result.violations)

    def test_privileged_false_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"privileged": False}))
        criticals = _violations(result, "critical")
        assert not any(v.field == "privileged" for v in criticals)

    def test_privileged_absent_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"image": "nginx"}))
        assert not any(v.field == "privileged" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical: cap_add
# ---------------------------------------------------------------------------


class TestCapAdd:
    def test_cap_add_single_entry_is_critical(self) -> None:
        result = _make_validator().validate(_service({"cap_add": ["SYS_ADMIN"]}))
        assert any(v.field == "cap_add" and v.severity == "critical" for v in result.violations)

    def test_cap_add_net_admin_is_critical(self) -> None:
        result = _make_validator().validate(_service({"cap_add": ["NET_ADMIN"]}))
        criticals = [v for v in result.violations if v.severity == "critical" and v.field == "cap_add"]
        assert len(criticals) == 1

    def test_cap_add_all_is_critical(self) -> None:
        result = _make_validator().validate(_service({"cap_add": ["ALL"]}))
        assert any(v.field == "cap_add" and v.severity == "critical" for v in result.violations)

    def test_cap_add_multiple_entries_each_flagged(self) -> None:
        result = _make_validator().validate(
            _service({"cap_add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]})
        )
        cap_violations = [v for v in result.violations if v.field == "cap_add"]
        assert len(cap_violations) == 3

    def test_cap_drop_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"cap_drop": ["ALL"]}))
        assert not any(v.field == "cap_add" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical: network_mode host
# ---------------------------------------------------------------------------


class TestNetworkMode:
    def test_network_mode_host_is_critical(self) -> None:
        result = _make_validator().validate(_service({"network_mode": "host"}))
        assert any(v.field == "network_mode" and v.severity == "critical" for v in result.violations)

    def test_network_mode_host_case_insensitive(self) -> None:
        result = _make_validator().validate(_service({"network_mode": "HOST"}))
        assert any(v.field == "network_mode" and v.severity == "critical" for v in result.violations)

    def test_network_mode_bridge_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"network_mode": "bridge"}))
        assert not any(v.field == "network_mode" for v in result.violations)

    def test_network_mode_custom_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"network_mode": "mynetwork"}))
        assert not any(v.field == "network_mode" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical: pid host
# ---------------------------------------------------------------------------


class TestPidNamespace:
    def test_pid_host_is_critical(self) -> None:
        result = _make_validator().validate(_service({"pid": "host"}))
        assert any(v.field == "pid" and v.severity == "critical" for v in result.violations)

    def test_pid_host_case_insensitive(self) -> None:
        result = _make_validator().validate(_service({"pid": "HOST"}))
        assert any(v.field == "pid" and v.severity == "critical" for v in result.violations)

    def test_pid_absent_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"image": "nginx"}))
        assert not any(v.field == "pid" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical: ipc host
# ---------------------------------------------------------------------------


class TestIpcNamespace:
    def test_ipc_host_is_critical(self) -> None:
        result = _make_validator().validate(_service({"ipc": "host"}))
        assert any(v.field == "ipc" and v.severity == "critical" for v in result.violations)

    def test_ipc_host_case_insensitive(self) -> None:
        result = _make_validator().validate(_service({"ipc": "Host"}))
        assert any(v.field == "ipc" and v.severity == "critical" for v in result.violations)

    def test_ipc_service_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"ipc": "service:other"}))
        assert not any(v.field == "ipc" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical: devices
# ---------------------------------------------------------------------------


class TestDevices:
    def test_single_device_is_critical(self) -> None:
        result = _make_validator().validate(_service({"devices": ["/dev/sda:/dev/sda"]}))
        assert any(v.field == "devices" and v.severity == "critical" for v in result.violations)

    def test_multiple_devices_each_flagged(self) -> None:
        result = _make_validator().validate(
            _service({"devices": ["/dev/sda:/dev/sda", "/dev/video0:/dev/video0"]})
        )
        device_violations = [v for v in result.violations if v.field == "devices"]
        assert len(device_violations) == 2

    def test_empty_devices_list_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"devices": []}))
        assert not any(v.field == "devices" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical: sysctls
# ---------------------------------------------------------------------------


class TestSysctls:
    def test_sysctls_dict_is_critical(self) -> None:
        result = _make_validator().validate(
            _service({"sysctls": {"net.core.somaxconn": 1024}})
        )
        assert any(v.field == "sysctls" and v.severity == "critical" for v in result.violations)

    def test_sysctls_list_is_critical(self) -> None:
        result = _make_validator().validate(
            _service({"sysctls": ["net.core.somaxconn=1024"]})
        )
        assert any(v.field == "sysctls" and v.severity == "critical" for v in result.violations)

    def test_sysctls_absent_is_not_flagged(self) -> None:
        result = _make_validator().validate(_service({"image": "nginx"}))
        assert not any(v.field == "sysctls" for v in result.violations)


# ---------------------------------------------------------------------------
# Critical & Warning: volume mounts
# ---------------------------------------------------------------------------


class TestVolumeMounts:
    def test_root_mount_is_critical(self) -> None:
        result = _make_validator().validate(_service({"volumes": ["/:container_path"]}))
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_etc_mount_is_critical(self) -> None:
        result = _make_validator().validate(_service({"volumes": ["/etc:/etc:ro"]}))
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_root_dir_mount_is_critical(self) -> None:
        result = _make_validator().validate(_service({"volumes": ["/root:/root"]}))
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_proc_mount_is_critical(self) -> None:
        result = _make_validator().validate(_service({"volumes": ["/proc:/proc"]}))
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_sys_mount_is_critical(self) -> None:
        result = _make_validator().validate(_service({"volumes": ["/sys:/sys"]}))
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_dev_mount_is_critical(self) -> None:
        result = _make_validator().validate(_service({"volumes": ["/dev:/dev"]}))
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_docker_sock_mount_is_critical(self) -> None:
        result = _make_validator().validate(
            _service({"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]})
        )
        assert any("volumes[0]" in v.field and v.severity == "critical" for v in result.violations)

    def test_descendant_of_etc_is_critical(self) -> None:
        """Mounting /etc/shadow is a descendant of /etc — must be critical."""
        result = _make_validator().validate(
            _service({"volumes": ["/etc/shadow:/shadow:ro"]})
        )
        assert any(v.severity == "critical" for v in result.violations)

    def test_named_volume_is_not_flagged(self) -> None:
        """Named volumes (e.g. 'mydata:/data') have no dangerous host path."""
        result = _make_validator(["/srv"]).validate(
            _service({"volumes": ["mydata:/data"]})
        )
        volume_violations = [v for v in result.violations if "volume" in v.field.lower()]
        assert volume_violations == []

    def test_allowed_prefix_no_warning(self) -> None:
        result = _make_validator(allowed=["/srv/compose"]).validate(
            _service({"volumes": ["/srv/compose/data:/data"]})
        )
        volume_warnings = [v for v in result.violations if "volumes" in v.field and v.severity == "warning"]
        assert volume_warnings == []

    def test_outside_allowed_prefix_warns(self) -> None:
        result = _make_validator(allowed=["/srv/compose"]).validate(
            _service({"volumes": ["/opt/data:/data"]})
        )
        assert any("volumes[0]" in v.field and v.severity == "warning" for v in result.violations)

    def test_no_allowed_prefixes_warns_for_any_host_path(self) -> None:
        result = _make_validator(allowed=[]).validate(
            _service({"volumes": ["/opt/data:/data"]})
        )
        assert any("volumes[0]" in v.field and v.severity == "warning" for v in result.violations)

    def test_long_syntax_bind_mount_critical(self) -> None:
        """Long-form bind mount to /etc should be critical."""
        result = _make_validator().validate(
            _service(
                {
                    "volumes": [
                        {
                            "type": "bind",
                            "source": "/etc",
                            "target": "/host-etc",
                            "read_only": True,
                        }
                    ]
                }
            )
        )
        assert any(v.severity == "critical" for v in result.violations)

    def test_long_syntax_named_volume_not_flagged(self) -> None:
        """Long-form volume mount (type: volume) has no host path."""
        result = _make_validator(["/srv"]).validate(
            _service(
                {
                    "volumes": [
                        {
                            "type": "volume",
                            "source": "mydata",
                            "target": "/data",
                        }
                    ]
                }
            )
        )
        volume_violations = [v for v in result.violations if "volumes" in v.field]
        assert volume_violations == []

    def test_multiple_volumes_indexed_correctly(self) -> None:
        result = _make_validator().validate(
            _service(
                {
                    "volumes": [
                        "safedata:/data",          # index 0 — named, no host path
                        "/etc:/host-etc",           # index 1 — critical
                        "/opt/data:/opt-data",      # index 2 — warning (no allowed)
                    ]
                }
            )
        )
        fields = {v.field for v in result.violations}
        assert "volumes[1]" in fields
        assert "volumes[2]" in fields
        assert "volumes[0]" not in fields


# ---------------------------------------------------------------------------
# Warning: restart policy
# ---------------------------------------------------------------------------


class TestRestartPolicy:
    def test_restart_no_warns(self) -> None:
        result = _make_validator().validate(_service({"restart": "no"}))
        assert any(v.field == "restart" and v.severity == "warning" for v in result.violations)

    def test_restart_false_warns(self) -> None:
        result = _make_validator().validate(_service({"restart": False}))
        assert any(v.field == "restart" and v.severity == "warning" for v in result.violations)

    def test_restart_always_not_warned(self) -> None:
        result = _make_validator().validate(_service({"restart": "always"}))
        assert not any(v.field == "restart" for v in result.violations)

    def test_restart_unless_stopped_not_warned(self) -> None:
        result = _make_validator().validate(_service({"restart": "unless-stopped"}))
        assert not any(v.field == "restart" for v in result.violations)

    def test_restart_absent_not_warned(self) -> None:
        result = _make_validator().validate(_service({"image": "nginx"}))
        assert not any(v.field == "restart" for v in result.violations)


# ---------------------------------------------------------------------------
# Warning: resource limits
# ---------------------------------------------------------------------------


class TestResourceLimits:
    def test_no_deploy_warns(self) -> None:
        result = _make_validator().validate(_service({"image": "nginx"}))
        assert any("deploy.resources.limits" in v.field and v.severity == "warning" for v in result.violations)

    def test_deploy_no_resources_warns(self) -> None:
        result = _make_validator().validate(_service({"deploy": {"mode": "replicated"}}))
        assert any("deploy.resources.limits" in v.field and v.severity == "warning" for v in result.violations)

    def test_deploy_resources_no_limits_warns(self) -> None:
        result = _make_validator().validate(
            _service({"deploy": {"resources": {"reservations": {"cpus": "0.1"}}}})
        )
        assert any("deploy.resources.limits" in v.field and v.severity == "warning" for v in result.violations)

    def test_deploy_with_limits_not_warned(self) -> None:
        result = _make_validator().validate(
            _service(
                {
                    "deploy": {
                        "resources": {
                            "limits": {"cpus": "0.5", "memory": "256M"}
                        }
                    }
                }
            )
        )
        assert not any("deploy.resources.limits" in v.field for v in result.violations)


# ---------------------------------------------------------------------------
# Warning: environment variable leakage
# ---------------------------------------------------------------------------


class TestEnvironmentCheck:
    def test_docker_host_in_dict_env_warns(self) -> None:
        result = _make_validator().validate(
            _service({"environment": {"DOCKER_HOST": "unix:///var/run/docker.sock"}})
        )
        assert any("DOCKER_HOST" in v.field and v.severity == "warning" for v in result.violations)

    def test_docker_socket_in_dict_env_warns(self) -> None:
        result = _make_validator().validate(
            _service({"environment": {"DOCKER_SOCKET": "/var/run/docker.sock"}})
        )
        assert any("DOCKER_SOCKET" in v.field and v.severity == "warning" for v in result.violations)

    def test_docker_host_in_list_env_warns(self) -> None:
        result = _make_validator().validate(
            _service({"environment": ["DOCKER_HOST=unix:///var/run/docker.sock"]})
        )
        assert any("DOCKER_HOST" in v.field and v.severity == "warning" for v in result.violations)

    def test_docker_socket_in_list_env_warns(self) -> None:
        result = _make_validator().validate(
            _service({"environment": ["DOCKER_SOCKET=/var/run/docker.sock"]})
        )
        assert any("DOCKER_SOCKET" in v.field and v.severity == "warning" for v in result.violations)

    def test_safe_env_vars_not_warned(self) -> None:
        result = _make_validator().validate(
            _service({"environment": {"APP_ENV": "production", "DB_NAME": "mydb"}})
        )
        assert not any("environment" in v.field for v in result.violations)

    def test_env_var_key_only_no_value_list_form(self) -> None:
        """List form entry without '=' (key reference only) should still be checked."""
        result = _make_validator().validate(
            _service({"environment": ["DOCKER_HOST"]})
        )
        assert any("DOCKER_HOST" in v.field and v.severity == "warning" for v in result.violations)
