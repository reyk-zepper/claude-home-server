"""Unit tests for SystemModule.

Covers all twelve tools across every risk tier:

READ (auto-approve)
    system_query        — info / processes / services / updates / firewall scopes
    system_logs         — journalctl integration
    system_auth_logs    — auth.log + journalctl fallback
    system_sessions     — loginctl + w
    system_disk_health  — smartctl + df fallback
    system_failed_services

MODERATE
    system_service_restart

ELEVATED
    system_service_toggle (including dry_run)

CRITICAL
    system_update_apply   (dry_run + live)
    system_package_install (dry_run + live)
    system_firewall_edit   (dry_run + protected-port guard)
    system_reboot          (dry_run + live)

Cross-cutting concerns verified:
    - Input validation rejects injection attempts and bad values
    - dry_run returns a description without calling safe_run_sudo
    - Protected-port guard blocks SSH (22) deletion
    - ValidationError surfaces as a clean error string (not an exception)
    - safe_run / safe_run_sudo are always mocked — no real subprocesses
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from src.config import ServerConfig
from src.modules.system import SystemModule
from src.utils.subprocess_safe import CommandResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(stdout: str = "", stderr: str = "") -> CommandResult:
    """Construct a successful CommandResult."""
    return CommandResult(
        stdout=stdout,
        stderr=stderr,
        returncode=0,
        timed_out=False,
        truncated=False,
    )


def _fail(stderr: str = "error output", returncode: int = 1) -> CommandResult:
    """Construct a failed CommandResult."""
    return CommandResult(
        stdout="",
        stderr=stderr,
        returncode=returncode,
        timed_out=False,
        truncated=False,
    )


def _not_found(cmd: str = "command") -> CommandResult:
    """Simulate a 'command not found' result (returncode -1)."""
    return CommandResult(
        stdout="",
        stderr=f"Command not found: {cmd}",
        returncode=-1,
        timed_out=False,
        truncated=False,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def system_module(
    default_config: ServerConfig,
    permission_engine,
    audit_logger,
    circuit_breaker,
) -> SystemModule:
    """Instantiate a SystemModule wired to the shared test fixtures.

    Returns:
        A fully initialised SystemModule ready for testing.
    """
    return SystemModule(
        config=default_config,
        permission_engine=permission_engine,
        audit_logger=audit_logger,
        circuit_breaker=circuit_breaker,
    )


# ---------------------------------------------------------------------------
# Tests: system_query — info scope
# ---------------------------------------------------------------------------


class TestSystemQueryInfo:
    """system_query with scope='info'."""

    @patch("src.modules.system.safe_run")
    def test_info_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("myhostname")
        result = system_module._system_query_impl(scope="info")
        assert "=== System Info ===" in result

    @patch("src.modules.system.safe_run")
    def test_info_includes_hostname(self, mock_run, system_module):
        mock_run.return_value = _ok("server.local")
        result = system_module._system_query_impl(scope="info")
        assert "Hostname" in result

    @patch("src.modules.system.safe_run")
    def test_info_includes_kernel(self, mock_run, system_module):
        responses = [
            _ok("server.local"),          # hostname
            _ok("Linux 5.15.0 x86_64"),   # uname
            _ok("4"),                      # nproc
            _ok("Mem:  8.0G  2.0G  6.0G"),# free
            _ok("up 2 days"),              # uptime
        ]
        mock_run.side_effect = responses
        result = system_module._system_query_impl(scope="info")
        assert "Kernel" in result

    def test_info_invalid_scope_returns_validation_error(self, system_module):
        result = system_module._system_query_impl(scope="invalid_scope")
        assert "[VALIDATION ERROR]" in result

    def test_info_target_with_null_byte_rejected(self, system_module):
        result = system_module._system_query_impl(scope="info", target="foo\x00bar")
        assert "[VALIDATION ERROR]" in result


# ---------------------------------------------------------------------------
# Tests: system_query — processes scope
# ---------------------------------------------------------------------------


class TestSystemQueryProcesses:
    """system_query with scope='processes'."""

    @patch("src.modules.system.safe_run")
    def test_processes_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("USER PID\nnginx 123")
        result = system_module._system_query_impl(scope="processes")
        assert "=== Processes ===" in result

    @patch("src.modules.system.safe_run")
    def test_processes_calls_ps_aux(self, mock_run, system_module):
        mock_run.return_value = _ok("USER PID")
        system_module._system_query_impl(scope="processes")
        cmd = mock_run.call_args[0][0]
        assert "ps" in cmd
        assert "aux" in cmd

    @patch("src.modules.system.safe_run")
    def test_processes_filter_by_target(self, mock_run, system_module):
        mock_run.return_value = _ok(
            "USER   PID\nnginx  123 /usr/sbin/nginx\npython 456 /usr/bin/python3"
        )
        result = system_module._system_query_impl(scope="processes", target="nginx")
        assert "nginx" in result
        # python line should be filtered out
        assert "python3" not in result

    @patch("src.modules.system.safe_run")
    def test_processes_no_match_shows_message(self, mock_run, system_module):
        mock_run.return_value = _ok("USER PID\nnginx 123")
        result = system_module._system_query_impl(scope="processes", target="xyznonexistent")
        assert "no processes matching" in result

    @patch("src.modules.system.safe_run")
    def test_processes_failure_shows_error(self, mock_run, system_module):
        mock_run.return_value = _fail("ps: command not found")
        result = system_module._system_query_impl(scope="processes")
        assert "Error" in result


# ---------------------------------------------------------------------------
# Tests: system_query — services scope
# ---------------------------------------------------------------------------


class TestSystemQueryServices:
    """system_query with scope='services'."""

    @patch("src.modules.system.safe_run")
    def test_services_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("UNIT   LOAD   ACTIVE\nnginx  loaded active")
        result = system_module._system_query_impl(scope="services")
        assert "=== Services ===" in result

    @patch("src.modules.system.safe_run")
    def test_services_uses_systemctl(self, mock_run, system_module):
        mock_run.return_value = _ok("UNIT")
        system_module._system_query_impl(scope="services")
        cmd = mock_run.call_args[0][0]
        assert "systemctl" in cmd

    @patch("src.modules.system.safe_run")
    def test_services_filter_by_target(self, mock_run, system_module):
        mock_run.return_value = _ok(
            "UNIT\nnginx.service   loaded active\ndocker.service  loaded active"
        )
        result = system_module._system_query_impl(scope="services", target="nginx")
        assert "nginx" in result
        assert "docker" not in result


# ---------------------------------------------------------------------------
# Tests: system_query — updates scope
# ---------------------------------------------------------------------------


class TestSystemQueryUpdates:
    """system_query with scope='updates'."""

    @patch("src.modules.system.safe_run")
    def test_updates_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("Listing... Done\nnginx/focal 1.2 amd64")
        result = system_module._system_query_impl(scope="updates")
        assert "=== Available Updates ===" in result

    @patch("src.modules.system.safe_run")
    def test_updates_uses_apt_list(self, mock_run, system_module):
        mock_run.return_value = _ok("Listing... Done")
        system_module._system_query_impl(scope="updates")
        cmd = mock_run.call_args[0][0]
        assert "apt" in cmd
        assert "--upgradable" in cmd

    @patch("src.modules.system.safe_run")
    def test_updates_empty_output_shows_message(self, mock_run, system_module):
        mock_run.return_value = _ok("")
        result = system_module._system_query_impl(scope="updates")
        assert "no upgradable packages" in result


# ---------------------------------------------------------------------------
# Tests: system_query — firewall scope
# ---------------------------------------------------------------------------


class TestSystemQueryFirewall:
    """system_query with scope='firewall'."""

    @patch("src.modules.system.safe_run")
    def test_firewall_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("Status: active\nTo  Action")
        result = system_module._system_query_impl(scope="firewall")
        assert "=== Firewall ===" in result

    @patch("src.modules.system.safe_run")
    def test_firewall_uses_ufw_status(self, mock_run, system_module):
        mock_run.return_value = _ok("Status: active")
        system_module._system_query_impl(scope="firewall")
        cmd = mock_run.call_args[0][0]
        assert "ufw" in cmd
        assert "status" in cmd


# ---------------------------------------------------------------------------
# Tests: system_logs
# ---------------------------------------------------------------------------


class TestSystemLogs:
    """system_logs tool."""

    @patch("src.modules.system.safe_run")
    def test_logs_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("Mar 30 12:00:00 nginx[123]: started")
        result = system_module._system_logs_impl(source="nginx", lines=50)
        assert "=== Logs: nginx" in result

    @patch("src.modules.system.safe_run")
    def test_logs_passes_source_to_journalctl(self, mock_run, system_module):
        mock_run.return_value = _ok("log line")
        system_module._system_logs_impl(source="sshd", lines=100)
        cmd = mock_run.call_args[0][0]
        assert "journalctl" in cmd
        assert "-u" in cmd
        assert "sshd" in cmd

    @patch("src.modules.system.safe_run")
    def test_logs_passes_line_count(self, mock_run, system_module):
        mock_run.return_value = _ok("log line")
        system_module._system_logs_impl(source="nginx", lines=200)
        cmd = mock_run.call_args[0][0]
        assert "200" in cmd

    @patch("src.modules.system.safe_run")
    def test_logs_failure_shows_error(self, mock_run, system_module):
        mock_run.return_value = _fail("unit not found")
        result = system_module._system_logs_impl(source="nginx")
        assert "Error" in result

    def test_logs_invalid_source_with_injection_chars(self, system_module):
        """Source containing semicolon or other shell chars should be rejected."""
        result = system_module._system_logs_impl(source="nginx; rm -rf /")
        assert "[VALIDATION ERROR]" in result

    def test_logs_null_byte_in_source_rejected(self, system_module):
        result = system_module._system_logs_impl(source="ngi\x00nx")
        assert "[VALIDATION ERROR]" in result

    def test_logs_lines_below_minimum_rejected(self, system_module):
        result = system_module._system_logs_impl(source="nginx", lines=0)
        assert "[VALIDATION ERROR]" in result

    def test_logs_lines_above_maximum_rejected(self, system_module):
        result = system_module._system_logs_impl(source="nginx", lines=99_999)
        assert "[VALIDATION ERROR]" in result

    @patch("src.modules.system.safe_run")
    def test_logs_empty_output_shows_placeholder(self, mock_run, system_module):
        mock_run.return_value = _ok("")
        result = system_module._system_logs_impl(source="nginx")
        assert "no entries found" in result


# ---------------------------------------------------------------------------
# Tests: system_auth_logs
# ---------------------------------------------------------------------------


class TestSystemAuthLogs:
    """system_auth_logs tool."""

    @patch("src.modules.system.safe_run")
    @patch("src.modules.system.Path")
    def test_auth_logs_reads_auth_log_when_present(self, mock_path_cls, mock_run, system_module):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.read_text.return_value = "\n".join(f"line {i}" for i in range(200))
        mock_path_cls.return_value = mock_path_instance

        result = system_module._system_auth_logs_impl(lines=50)
        assert "=== Auth Logs" in result
        assert "/var/log/auth.log" in result
        # safe_run should NOT have been called (file read succeeded)
        mock_run.assert_not_called()

    @patch("src.modules.system.safe_run")
    @patch("src.modules.system.Path")
    def test_auth_logs_falls_back_to_journalctl_when_file_missing(
        self, mock_path_cls, mock_run, system_module
    ):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path_cls.return_value = mock_path_instance

        mock_run.return_value = _ok("Mar 30 sshd session opened")
        result = system_module._system_auth_logs_impl(lines=20)
        assert "=== Auth Logs" in result
        mock_run.assert_called()

    @patch("src.modules.system.safe_run")
    @patch("src.modules.system.Path")
    def test_auth_logs_falls_back_to_sshd_when_ssh_unit_missing(
        self, mock_path_cls, mock_run, system_module
    ):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path_cls.return_value = mock_path_instance

        # First call (ssh unit) fails, second call (sshd unit) succeeds
        mock_run.side_effect = [
            _fail("Unit ssh.service not found"),
            _ok("Mar 30 sshd auth event"),
        ]
        result = system_module._system_auth_logs_impl(lines=10)
        assert "=== Auth Logs" in result

    def test_auth_logs_invalid_lines_rejected(self, system_module):
        result = system_module._system_auth_logs_impl(lines=0)
        assert "[VALIDATION ERROR]" in result


# ---------------------------------------------------------------------------
# Tests: system_sessions
# ---------------------------------------------------------------------------


class TestSystemSessions:
    """system_sessions tool."""

    @patch("src.modules.system.safe_run")
    def test_sessions_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("SESSION  UID  USER  SEAT  TTY")
        result = system_module._system_sessions_impl()
        assert "=== Active Sessions ===" in result

    @patch("src.modules.system.safe_run")
    def test_sessions_calls_loginctl_and_w(self, mock_run, system_module):
        mock_run.return_value = _ok("output")
        system_module._system_sessions_impl()
        calls = [c[0][0] for c in mock_run.call_args_list]
        # loginctl must appear in at least one command
        any_loginctl = any("loginctl" in cmd for cmd in calls)
        # "w" must be the sole element of at least one command list
        any_w = any(cmd == ["w"] for cmd in calls)
        assert any_loginctl
        assert any_w

    @patch("src.modules.system.safe_run")
    def test_sessions_empty_shows_placeholder(self, mock_run, system_module):
        mock_run.return_value = _ok("")
        result = system_module._system_sessions_impl()
        assert "no active sessions" in result.lower() or "no logged-in users" in result.lower()


# ---------------------------------------------------------------------------
# Tests: system_disk_health
# ---------------------------------------------------------------------------


class TestSystemDiskHealth:
    """system_disk_health tool."""

    @patch("src.modules.system.safe_run")
    def test_disk_health_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("SMART overall-health: PASSED")
        result = system_module._system_disk_health_impl()
        assert "=== Disk Health ===" in result

    @patch("src.modules.system.safe_run")
    def test_disk_health_uses_smartctl(self, mock_run, system_module):
        mock_run.return_value = _ok("PASSED")
        system_module._system_disk_health_impl()
        cmd = mock_run.call_args[0][0]
        assert "smartctl" in cmd

    @patch("src.modules.system.safe_run")
    def test_disk_health_falls_back_to_df_when_smartctl_not_found(
        self, mock_run, system_module
    ):
        # returncode -1 simulates "command not found"
        mock_run.side_effect = [
            _not_found("smartctl"),
            _ok("/dev/sda  100G  50G  50G  50%  /"),
        ]
        result = system_module._system_disk_health_impl()
        assert "smartctl not available" in result
        # Second call should be df
        second_cmd = mock_run.call_args_list[1][0][0]
        assert "df" in second_cmd

    @patch("src.modules.system.safe_run")
    def test_disk_health_includes_smart_output(self, mock_run, system_module):
        mock_run.return_value = _ok("SMART overall-health self-assessment: PASSED")
        result = system_module._system_disk_health_impl()
        assert "PASSED" in result


# ---------------------------------------------------------------------------
# Tests: system_failed_services
# ---------------------------------------------------------------------------


class TestSystemFailedServices:
    """system_failed_services tool."""

    @patch("src.modules.system.safe_run")
    def test_failed_services_returns_header(self, mock_run, system_module):
        mock_run.return_value = _ok("0 loaded units listed.")
        result = system_module._system_failed_services_impl()
        assert "=== Failed Services ===" in result

    @patch("src.modules.system.safe_run")
    def test_failed_services_uses_systemctl_failed(self, mock_run, system_module):
        mock_run.return_value = _ok("0 loaded units listed.")
        system_module._system_failed_services_impl()
        cmd = mock_run.call_args[0][0]
        assert "systemctl" in cmd
        assert "--failed" in cmd

    @patch("src.modules.system.safe_run")
    def test_failed_services_empty_shows_placeholder(self, mock_run, system_module):
        mock_run.return_value = _ok("")
        result = system_module._system_failed_services_impl()
        assert "no failed units" in result

    @patch("src.modules.system.safe_run")
    def test_failed_services_error_propagated(self, mock_run, system_module):
        mock_run.return_value = _fail("systemctl: command not found")
        result = system_module._system_failed_services_impl()
        assert "Error" in result


# ---------------------------------------------------------------------------
# Tests: system_service_restart (MODERATE)
# ---------------------------------------------------------------------------


class TestSystemServiceRestart:
    """system_service_restart tool."""

    @patch("src.modules.system.safe_run_sudo")
    def test_restart_calls_wrapper_script(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("Restarted nginx.service")
        result = system_module._system_service_restart_impl(name="nginx")
        mock_sudo.assert_called_once_with(
            "/usr/local/bin/mcp-service-restart", ["nginx"]
        )
        assert "nginx" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_restart_returns_header(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("done")
        result = system_module._system_service_restart_impl(name="docker")
        assert "=== Service Restart: docker ===" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_restart_failure_reported(self, mock_sudo, system_module):
        mock_sudo.return_value = _fail("Failed to restart nginx.service")
        result = system_module._system_service_restart_impl(name="nginx")
        assert "FAILED" in result

    def test_restart_rejects_injection_attempt(self, system_module):
        result = system_module._system_service_restart_impl(name="nginx; rm -rf /")
        assert "[VALIDATION ERROR]" in result

    def test_restart_rejects_empty_name(self, system_module):
        result = system_module._system_service_restart_impl(name="")
        assert "[VALIDATION ERROR]" in result

    def test_restart_rejects_name_with_shell_metachar(self, system_module):
        result = system_module._system_service_restart_impl(name="nginx$(whoami)")
        assert "[VALIDATION ERROR]" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_restart_accepts_template_unit(self, mock_sudo, system_module):
        """Service names with @ (template units) are valid systemd names."""
        mock_sudo.return_value = _ok("done")
        result = system_module._system_service_restart_impl(name="getty@tty1.service")
        assert "[VALIDATION ERROR]" not in result
        mock_sudo.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: system_service_toggle (ELEVATED)
# ---------------------------------------------------------------------------


class TestSystemServiceToggle:
    """system_service_toggle tool."""

    @patch("src.modules.system.safe_run_sudo")
    def test_toggle_enable_calls_wrapper(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("Enabled nginx")
        system_module._system_service_toggle_impl(name="nginx", enabled=True)
        mock_sudo.assert_called_once_with(
            "/usr/local/bin/mcp-service-toggle", ["nginx", "enable"]
        )

    @patch("src.modules.system.safe_run_sudo")
    def test_toggle_disable_calls_wrapper_with_disable(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("Disabled nginx")
        system_module._system_service_toggle_impl(name="nginx", enabled=False)
        mock_sudo.assert_called_once_with(
            "/usr/local/bin/mcp-service-toggle", ["nginx", "disable"]
        )

    @patch("src.modules.system.safe_run_sudo")
    def test_toggle_dry_run_does_not_call_sudo(self, mock_sudo, system_module):
        result = system_module._system_service_toggle_impl(
            name="nginx", enabled=True, dry_run=True
        )
        mock_sudo.assert_not_called()
        assert "DRY RUN" in result
        assert "nginx" in result
        assert "enable" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_toggle_dry_run_disable_mentions_disable(self, mock_sudo, system_module):
        result = system_module._system_service_toggle_impl(
            name="cron", enabled=False, dry_run=True
        )
        assert "disable" in result
        mock_sudo.assert_not_called()

    def test_toggle_rejects_invalid_service_name(self, system_module):
        result = system_module._system_service_toggle_impl(
            name="../etc/passwd", enabled=True
        )
        assert "[VALIDATION ERROR]" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_toggle_failure_reported(self, mock_sudo, system_module):
        mock_sudo.return_value = _fail("Unit not found")
        result = system_module._system_service_toggle_impl(name="noexist", enabled=True)
        assert "FAILED" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_toggle_returns_header(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("done")
        result = system_module._system_service_toggle_impl(name="cron", enabled=True)
        assert "=== Service Toggle: cron" in result


# ---------------------------------------------------------------------------
# Tests: system_update_apply (CRITICAL)
# ---------------------------------------------------------------------------


class TestSystemUpdateApply:
    """system_update_apply tool."""

    @patch("src.modules.system.safe_run")
    def test_update_dry_run_lists_packages(self, mock_run, system_module):
        mock_run.return_value = _ok("Listing... Done\nnginx/focal 1.2 amd64")
        result = system_module._system_update_apply_impl(dry_run=True)
        assert "DRY RUN" in result
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "apt" in cmd
        assert "--upgradable" in cmd

    @patch("src.modules.system.safe_run_sudo")
    def test_update_live_calls_wrapper(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("Upgraded 5 packages.")
        result = system_module._system_update_apply_impl(dry_run=False)
        mock_sudo.assert_called_once_with(
            "/usr/local/bin/mcp-apt-upgrade", [], timeout=600
        )
        assert "=== System Update ===" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_update_dry_run_does_not_call_sudo(self, mock_sudo, system_module):
        with patch("src.modules.system.safe_run") as mock_run:
            mock_run.return_value = _ok("Listing... Done")
            system_module._system_update_apply_impl(dry_run=True)
            mock_sudo.assert_not_called()

    @patch("src.modules.system.safe_run_sudo")
    def test_update_failure_reported(self, mock_sudo, system_module):
        mock_sudo.return_value = _fail("E: lock file held")
        result = system_module._system_update_apply_impl(dry_run=False)
        assert "FAILED" in result


# ---------------------------------------------------------------------------
# Tests: system_package_install (CRITICAL)
# ---------------------------------------------------------------------------


class TestSystemPackageInstall:
    """system_package_install tool."""

    @patch("src.modules.system.safe_run")
    def test_install_dry_run_uses_apt_cache(self, mock_run, system_module):
        mock_run.return_value = _ok("Package: htop\nVersion: 3.0")
        result = system_module._system_package_install_impl(name="htop", dry_run=True)
        assert "DRY RUN" in result
        cmd = mock_run.call_args[0][0]
        assert "apt-cache" in cmd
        assert "htop" in cmd

    @patch("src.modules.system.safe_run_sudo")
    def test_install_live_calls_wrapper(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("htop installed.")
        result = system_module._system_package_install_impl(name="htop", dry_run=False)
        mock_sudo.assert_called_once_with(
            "/usr/local/bin/mcp-apt-install", ["htop"], timeout=300
        )
        assert "htop" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_install_dry_run_does_not_call_sudo(self, mock_sudo, system_module):
        with patch("src.modules.system.safe_run") as mock_run:
            mock_run.return_value = _ok("Package info")
            system_module._system_package_install_impl(name="htop", dry_run=True)
            mock_sudo.assert_not_called()

    def test_install_rejects_package_with_uppercase(self, system_module):
        result = system_module._system_package_install_impl(name="Nginx")
        assert "[VALIDATION ERROR]" in result

    def test_install_rejects_package_with_injection(self, system_module):
        result = system_module._system_package_install_impl(name="htop; rm -rf /")
        assert "[VALIDATION ERROR]" in result

    def test_install_rejects_empty_name(self, system_module):
        result = system_module._system_package_install_impl(name="")
        assert "[VALIDATION ERROR]" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_install_failure_reported(self, mock_sudo, system_module):
        mock_sudo.return_value = _fail("E: Unable to locate package")
        result = system_module._system_package_install_impl(name="no-such-pkg")
        assert "FAILED" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_install_returns_header(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("done")
        result = system_module._system_package_install_impl(name="curl")
        assert "=== Package Install: curl ===" in result

    @patch("src.modules.system.safe_run")
    def test_install_dry_run_package_not_found_shows_message(self, mock_run, system_module):
        mock_run.return_value = _fail("N: Unable to locate package")
        result = system_module._system_package_install_impl(name="fakepackage123", dry_run=True)
        assert "DRY RUN" in result
        assert "not found" in result.lower() or "FAILED" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# Tests: system_firewall_edit (CRITICAL)
# ---------------------------------------------------------------------------


class TestSystemFirewallEdit:
    """system_firewall_edit tool — including protected-port guard."""

    @patch("src.modules.system.safe_run_sudo")
    def test_firewall_edit_calls_wrapper(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("Rule added.")
        result = system_module._system_firewall_edit_impl(rule="allow 80/tcp")
        mock_sudo.assert_called_once_with(
            "/usr/local/bin/mcp-ufw-edit", ["allow", "80/tcp"]
        )
        assert "=== Firewall Edit" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_firewall_dry_run_does_not_call_sudo(self, mock_sudo, system_module):
        result = system_module._system_firewall_edit_impl(
            rule="allow 8080", dry_run=True
        )
        mock_sudo.assert_not_called()
        assert "DRY RUN" in result
        assert "8080" in result

    def test_firewall_blocks_delete_ssh_port(self, system_module):
        """Deleting port 22 rule must be refused."""
        result = system_module._system_firewall_edit_impl(rule="delete allow 22")
        assert "REFUSED" in result
        assert "22" in result

    def test_firewall_blocks_deny_ssh_port(self, system_module):
        """Denying port 22 must be refused."""
        result = system_module._system_firewall_edit_impl(rule="deny 22")
        assert "REFUSED" in result

    def test_firewall_blocks_reject_ssh_port(self, system_module):
        """Reject rules for port 22 must be refused."""
        result = system_module._system_firewall_edit_impl(rule="reject 22/tcp")
        assert "REFUSED" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_firewall_allows_rule_for_non_protected_port(self, mock_sudo, system_module):
        """Rules for non-protected ports should pass through."""
        mock_sudo.return_value = _ok("Rule added.")
        result = system_module._system_firewall_edit_impl(rule="allow 443")
        assert "REFUSED" not in result
        mock_sudo.assert_called_once()

    @patch("src.modules.system.safe_run_sudo")
    def test_firewall_allows_adding_rule_for_ssh_port(self, mock_sudo, system_module):
        """Allow rules for port 22 do not endanger access — should be permitted."""
        mock_sudo.return_value = _ok("Rule added.")
        result = system_module._system_firewall_edit_impl(rule="allow 22")
        assert "REFUSED" not in result
        mock_sudo.assert_called_once()

    def test_firewall_blocks_delete_custom_protected_port(self, permission_engine, audit_logger, circuit_breaker):
        """Protected ports from config must also be guarded."""
        config = ServerConfig()
        config.security.protected_ports = [22, 2222]
        module = SystemModule(
            config=config,
            permission_engine=permission_engine,
            audit_logger=audit_logger,
            circuit_breaker=circuit_breaker,
        )
        result = module._system_firewall_edit_impl(rule="delete allow 2222")
        assert "REFUSED" in result

    def test_firewall_rejects_rule_with_special_chars(self, system_module):
        result = system_module._system_firewall_edit_impl(rule="allow 80; rm -rf /")
        assert "[VALIDATION ERROR]" in result

    def test_firewall_rejects_null_byte_in_rule(self, system_module):
        result = system_module._system_firewall_edit_impl(rule="allow 80\x00")
        assert "[VALIDATION ERROR]" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_firewall_failure_reported(self, mock_sudo, system_module):
        mock_sudo.return_value = _fail("ERROR: Could not find a profile")
        result = system_module._system_firewall_edit_impl(rule="allow 9000")
        assert "FAILED" in result


# ---------------------------------------------------------------------------
# Tests: system_reboot (CRITICAL)
# ---------------------------------------------------------------------------


class TestSystemReboot:
    """system_reboot tool."""

    @patch("src.modules.system.safe_run_sudo")
    def test_reboot_dry_run_returns_warning(self, mock_sudo, system_module):
        result = system_module._system_reboot_impl(dry_run=True)
        assert "DRY RUN" in result
        assert "WARNING" in result
        mock_sudo.assert_not_called()

    @patch("src.modules.system.safe_run_sudo")
    def test_reboot_live_calls_wrapper(self, mock_sudo, system_module):
        mock_sudo.return_value = _ok("Rebooting now.")
        result = system_module._system_reboot_impl(dry_run=False)
        mock_sudo.assert_called_once_with("/usr/local/bin/mcp-reboot", [])
        assert "=== System Reboot ===" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_reboot_failure_reported(self, mock_sudo, system_module):
        mock_sudo.return_value = _fail("Permission denied")
        result = system_module._system_reboot_impl(dry_run=False)
        assert "FAILED" in result

    @patch("src.modules.system.safe_run_sudo")
    def test_reboot_dry_run_does_not_call_sudo(self, mock_sudo, system_module):
        system_module._system_reboot_impl(dry_run=True)
        mock_sudo.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: protected-port helper
# ---------------------------------------------------------------------------


class TestRuleAffectsProtectedPort:
    """Unit tests for the _rule_affects_protected_port static method."""

    def test_delete_allow_22_is_dangerous(self):
        assert SystemModule._rule_affects_protected_port("delete allow 22", [22]) is True

    def test_deny_22_is_dangerous(self):
        assert SystemModule._rule_affects_protected_port("deny 22", [22]) is True

    def test_reject_22_tcp_is_dangerous(self):
        assert SystemModule._rule_affects_protected_port("reject 22/tcp", [22]) is True

    def test_allow_22_is_not_dangerous(self):
        assert SystemModule._rule_affects_protected_port("allow 22", [22]) is False

    def test_delete_allow_80_with_protected_22_is_not_dangerous(self):
        assert SystemModule._rule_affects_protected_port("delete allow 80", [22]) is False

    def test_deny_custom_port_matches(self):
        assert SystemModule._rule_affects_protected_port("deny 2222", [22, 2222]) is True

    def test_allow_non_protected_port_is_safe(self):
        assert SystemModule._rule_affects_protected_port("allow 443", [22]) is False

    def test_empty_protected_ports_list_never_blocks(self):
        assert SystemModule._rule_affects_protected_port("delete allow 22", []) is False

    def test_port_220_does_not_match_22(self):
        """Port 220 must not be confused with port 22 (word-boundary check)."""
        assert SystemModule._rule_affects_protected_port("deny 220", [22]) is False

    def test_port_1022_does_not_match_22(self):
        assert SystemModule._rule_affects_protected_port("deny 1022", [22]) is False


# ---------------------------------------------------------------------------
# Tests: MODULE_NAME and server registration
# ---------------------------------------------------------------------------


class TestSystemModuleRegistration:
    """Meta tests for module registration."""

    def test_module_name_is_system(self, system_module):
        assert system_module.MODULE_NAME == "system"

    def test_create_server_returns_fastmcp_instance(self, system_module):
        server = system_module.create_server()
        assert server is not None

    def test_register_tools_does_not_raise(self, system_module):
        # create_server calls _register_tools internally
        system_module.create_server()  # should not raise
