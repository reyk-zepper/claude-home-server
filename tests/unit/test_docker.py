"""Unit tests for src.modules.docker.DockerModule.

Coverage targets:
  - docker_info: all four resource types (containers, images, networks, volumes)
  - docker_info: target inspect with env redaction
  - docker_info: include_stats
  - docker_logs: basic log retrieval
  - docker_compose_validate: valid path, invalid path, security violations
  - docker_start / docker_stop / docker_restart: happy path, dry_run, error
  - docker_compose_edit: validation blocks critical, dry_run diff, successful write
  - docker_compose_up: blocked by validation, dry_run, successful deploy
  - docker_compose_down: dry_run, successful teardown
  - docker_compose_pull: dry_run, successful pull
  - docker_prune: each type, dry_run
  - docker_remove: dry_run, successful remove
  - Docker disabled: all tools return disabled message
  - Input validation: invalid container names are rejected
  - Path outside compose_paths is rejected
  - No compose_paths configured returns helpful error
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from src.modules.docker import DockerModule
from src.utils.subprocess_safe import CommandResult


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_command_result(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    timed_out: bool = False,
    truncated: bool = False,
) -> CommandResult:
    """Return a CommandResult with the given values."""
    return CommandResult(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        timed_out=timed_out,
        truncated=truncated,
    )


def _make_config(
    docker_enabled: bool = True,
    compose_paths: list[str] | None = None,
    backup_dir: str = "/tmp/backups",
    backup_retention_days: int = 30,
    backup_max_per_file: int = 50,
) -> MagicMock:
    """Build a mock ServerConfig."""
    config = MagicMock()
    config.services.docker.enabled = docker_enabled
    config.services.docker.compose_paths = compose_paths or []
    config.security.backup_dir = backup_dir
    config.security.backup_retention_days = backup_retention_days
    config.security.backup_max_per_file = backup_max_per_file
    return config


def _make_module(
    docker_enabled: bool = True,
    compose_paths: list[str] | None = None,
) -> DockerModule:
    """Instantiate a DockerModule with mocked dependencies."""
    config = _make_config(
        docker_enabled=docker_enabled,
        compose_paths=compose_paths,
    )
    permission_engine = MagicMock()
    permission_engine.get_risk_level.return_value = MagicMock()
    audit_logger = MagicMock()
    circuit_breaker = MagicMock()
    circuit_breaker.check_circuit.return_value = None
    circuit_breaker.check_burst_limit.return_value = None
    circuit_breaker.record_success.return_value = None
    circuit_breaker.record_failure.return_value = None

    module = DockerModule(
        config=config,
        permission_engine=permission_engine,
        audit_logger=audit_logger,
        circuit_breaker=circuit_breaker,
    )
    return module


# Safe compose YAML without security violations
SAFE_COMPOSE_YAML = yaml.dump(
    {
        "services": {
            "web": {
                "image": "nginx:latest",
                "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}},
                "restart": "unless-stopped",
            }
        }
    }
)

# Unsafe compose YAML with critical violations
UNSAFE_COMPOSE_YAML = yaml.dump(
    {
        "services": {
            "web": {
                "image": "nginx:latest",
                "privileged": True,
            }
        }
    }
)


# ---------------------------------------------------------------------------
# Module disabled
# ---------------------------------------------------------------------------


class TestDockerDisabled:
    """All tools must return a helpful message when Docker is disabled."""

    def _module(self) -> DockerModule:
        return _make_module(docker_enabled=False)

    @patch("src.modules.docker.safe_run")
    def test_docker_info_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_info_impl(resource="containers")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_logs_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_logs_impl(container="myapp")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_compose_validate_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_compose_validate_impl(path="/srv/compose.yml")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_start_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_start_impl(container="myapp")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_stop_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_stop_impl(container="myapp")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_restart_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_restart_impl(container="myapp")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_compose_edit_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_compose_edit_impl(path="/srv/c.yml", content="services: {}")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_compose_up_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_compose_up_impl(path="/srv/c.yml")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_compose_down_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_compose_down_impl(path="/srv/c.yml")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_compose_pull_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_compose_pull_impl(path="/srv/c.yml")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_prune_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_prune_impl(type="images")
        assert "not enabled" in result.lower()

    @patch("src.modules.docker.safe_run")
    def test_docker_remove_disabled(self, _mock_run: Any) -> None:
        m = self._module()
        result = m._docker_remove_impl(container="myapp")
        assert "not enabled" in result.lower()


# ---------------------------------------------------------------------------
# Input validation — container names
# ---------------------------------------------------------------------------


class TestInputValidation:
    @patch("src.modules.docker.safe_run")
    def test_invalid_container_name_rejected_by_start(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_start_impl(container="my container; rm -rf /")
        assert "Invalid" in result or "invalid" in result

    @patch("src.modules.docker.safe_run")
    def test_invalid_container_name_with_backtick_rejected(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_stop_impl(container="`evil`")
        assert "Invalid" in result or "invalid" in result

    @patch("src.modules.docker.safe_run")
    def test_invalid_container_name_with_dollar_rejected(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_restart_impl(container="$(whoami)")
        assert "Invalid" in result or "invalid" in result

    @patch("src.modules.docker.safe_run")
    def test_valid_container_name_accepted(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="myapp\n")
        m = _make_module()
        result = m._docker_start_impl(container="my-app_v2.0")
        # Should not be a validation error
        assert "Invalid" not in result

    @patch("src.modules.docker.safe_run")
    def test_invalid_container_name_rejected_by_remove(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_remove_impl(container="../../etc/passwd")
        assert "Invalid" in result or "invalid" in result

    @patch("src.modules.docker.safe_run")
    def test_log_lines_out_of_range_rejected(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_logs_impl(container="myapp", lines=999999)
        assert "Invalid" in result or "invalid" in result


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


class TestPathValidation:
    def test_no_compose_paths_configured_returns_error(self) -> None:
        m = _make_module(compose_paths=[])
        result = m._docker_compose_validate_impl(path="/srv/compose.yml")
        assert "compose_paths" in result or "No compose_paths" in result

    def test_path_outside_compose_paths_rejected(self, tmp_path: Path) -> None:
        allowed = str(tmp_path / "allowed")
        m = _make_module(compose_paths=[allowed])
        result = m._docker_compose_validate_impl(path="/etc/docker/compose.yml")
        assert "Access denied" in result or "denied" in result.lower()

    def test_path_within_compose_paths_accepted(self, tmp_path: Path) -> None:
        compose_dir = tmp_path / "compose"
        compose_dir.mkdir()
        compose_file = compose_dir / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(compose_dir)])
        result = m._docker_compose_validate_impl(path=str(compose_file))
        # Should not be a path error — will be a validation report
        assert "compose_paths" not in result
        assert "Access denied" not in result

    def test_compose_up_rejects_path_outside_configured(self) -> None:
        m = _make_module(compose_paths=["/srv/safe"])
        result = m._docker_compose_up_impl(path="/tmp/evil/docker-compose.yml")
        assert "Access denied" in result or "denied" in result.lower() or "No compose_paths" in result


# ---------------------------------------------------------------------------
# docker_info
# ---------------------------------------------------------------------------


class TestDockerInfo:
    @patch("src.modules.docker.safe_run")
    def test_info_containers_calls_docker_ps(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stdout="NAMES\tSTATUS\tPORTS\tIMAGE\nmyapp\tUp 2 hours\t\tnginx:latest\n"
        )
        m = _make_module()
        result = m._docker_info_impl(resource="containers")
        assert "myapp" in result
        # Verify docker ps -a was called
        call_args = mock_run.call_args[0][0]
        assert "docker" in call_args
        assert "ps" in call_args

    @patch("src.modules.docker.safe_run")
    def test_info_images_calls_docker_images(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stdout="REPOSITORY\tTAG\tSIZE\nnginx\tlatest\t142MB\n"
        )
        m = _make_module()
        result = m._docker_info_impl(resource="images")
        assert "nginx" in result
        call_args = mock_run.call_args[0][0]
        assert "images" in call_args

    @patch("src.modules.docker.safe_run")
    def test_info_networks_calls_docker_network_ls(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stdout="NAME\tDRIVER\tSCOPE\nbridge\tbridge\tlocal\n"
        )
        m = _make_module()
        result = m._docker_info_impl(resource="networks")
        assert "bridge" in result
        call_args = mock_run.call_args[0][0]
        assert "network" in call_args

    @patch("src.modules.docker.safe_run")
    def test_info_volumes_calls_docker_volume_ls(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stdout="NAME\tDRIVER\nmydata\tlocal\n"
        )
        m = _make_module()
        result = m._docker_info_impl(resource="volumes")
        assert "mydata" in result
        call_args = mock_run.call_args[0][0]
        assert "volume" in call_args

    @patch("src.modules.docker.safe_run")
    def test_info_invalid_resource_rejected(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_info_impl(resource="pods")
        assert "Invalid" in result or "invalid" in result

    @patch("src.modules.docker.safe_run")
    def test_info_target_triggers_inspect(self, mock_run: Any) -> None:
        inspect_data = json.dumps(
            [{"Config": {"Env": ["SECRET_KEY=supersecret", "PORT=8080"]}}]
        )
        mock_run.side_effect = [
            _make_command_result(stdout="ps output\n"),  # docker ps
            _make_command_result(stdout=inspect_data),   # docker inspect
        ]
        m = _make_module()
        result = m._docker_info_impl(resource="containers", target="myapp")
        # Secret values must be redacted
        assert "supersecret" not in result
        assert "[REDACTED]" in result
        # PORT value should also be redacted (all env vals are redacted)
        assert "SECRET_KEY=[REDACTED]" in result

    @patch("src.modules.docker.safe_run")
    def test_info_include_stats_calls_docker_stats(self, mock_run: Any) -> None:
        mock_run.side_effect = [
            _make_command_result(stdout="ps output\n"),
            _make_command_result(stdout="NAME\tCPU %\tMEM USAGE\nmyapp\t0.5%\t50MiB / 256MiB\n"),
        ]
        m = _make_module()
        result = m._docker_info_impl(resource="containers", include_stats=True)
        assert "myapp" in result
        # Verify stats call was made
        stats_call = mock_run.call_args_list[1][0][0]
        assert "stats" in stats_call

    @patch("src.modules.docker.safe_run")
    def test_info_error_from_docker_shown_in_output(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stderr="Cannot connect to Docker daemon",
            returncode=1,
        )
        m = _make_module()
        result = m._docker_info_impl(resource="containers")
        assert "Error" in result or "error" in result


# ---------------------------------------------------------------------------
# docker_logs
# ---------------------------------------------------------------------------


class TestDockerLogs:
    @patch("src.modules.docker.safe_run")
    def test_logs_calls_docker_logs_with_tail(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stderr="2024-01-01 INFO server started\n2024-01-01 INFO ready\n"
        )
        m = _make_module()
        result = m._docker_logs_impl(container="myapp", lines=50)
        assert "server started" in result
        call_args = mock_run.call_args[0][0]
        assert "logs" in call_args
        assert "--tail" in call_args
        assert "50" in call_args
        assert "myapp" in call_args

    @patch("src.modules.docker.safe_run")
    def test_logs_default_100_lines(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stderr="log line\n")
        m = _make_module()
        m._docker_logs_impl(container="myapp")
        call_args = mock_run.call_args[0][0]
        assert "100" in call_args


# ---------------------------------------------------------------------------
# docker_compose_validate
# ---------------------------------------------------------------------------


class TestDockerComposeValidate:
    def test_validate_with_violations_returns_report(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(UNSAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_validate_impl(path=str(compose_file))
        assert "BLOCKED" in result or "critical" in result.lower() or "CRITICAL" in result

    def test_validate_clean_file_passes(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_validate_impl(path=str(compose_file))
        assert "PASSED" in result

    def test_validate_nonexistent_file_returns_error(self, tmp_path: Path) -> None:
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_validate_impl(path=str(tmp_path / "nofile.yml"))
        assert "Cannot read" in result or "error" in result.lower()

    def test_validate_invalid_yaml_returns_error(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(": invalid: yaml: [[[")
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_validate_impl(path=str(compose_file))
        assert "error" in result.lower() or "YAML" in result


# ---------------------------------------------------------------------------
# docker_start / docker_stop / docker_restart
# ---------------------------------------------------------------------------


class TestContainerLifecycle:
    @patch("src.modules.docker.safe_run")
    def test_start_calls_docker_start(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="myapp\n")
        m = _make_module()
        result = m._docker_start_impl(container="myapp")
        call_args = mock_run.call_args[0][0]
        assert "start" in call_args
        assert "myapp" in call_args

    @patch("src.modules.docker.safe_run")
    def test_stop_calls_docker_stop(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="myapp\n")
        m = _make_module()
        result = m._docker_stop_impl(container="myapp")
        call_args = mock_run.call_args[0][0]
        assert "stop" in call_args
        assert "myapp" in call_args

    @patch("src.modules.docker.safe_run")
    def test_restart_calls_docker_restart(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="myapp\n")
        m = _make_module()
        result = m._docker_restart_impl(container="myapp")
        call_args = mock_run.call_args[0][0]
        assert "restart" in call_args
        assert "myapp" in call_args

    @patch("src.modules.docker.safe_run")
    def test_start_dry_run_returns_description(self, mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_start_impl(container="myapp", dry_run=True)
        assert "Dry Run" in result or "dry" in result.lower()
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_stop_dry_run_no_subprocess(self, mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_stop_impl(container="myapp", dry_run=True)
        assert "Dry Run" in result or "dry" in result.lower()
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_restart_dry_run_no_subprocess(self, mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_restart_impl(container="myapp", dry_run=True)
        assert "Dry Run" in result or "dry" in result.lower()
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_start_docker_error_shown_in_result(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stderr="No such container: myapp", returncode=1
        )
        m = _make_module()
        result = m._docker_start_impl(container="myapp")
        assert "Error" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# docker_compose_edit
# ---------------------------------------------------------------------------


class TestDockerComposeEdit:
    def test_edit_blocks_critical_violations(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_edit_impl(
            path=str(compose_file), content=UNSAFE_COMPOSE_YAML
        )
        assert "BLOCKED" in result
        # The file should NOT have been overwritten
        assert compose_file.read_text() == SAFE_COMPOSE_YAML

    def test_edit_dry_run_shows_diff(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        new_content = yaml.dump(
            {
                "services": {
                    "web": {
                        "image": "nginx:alpine",  # changed tag
                        "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}},
                        "restart": "unless-stopped",
                    }
                }
            }
        )
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_edit_impl(
            path=str(compose_file), content=new_content, dry_run=True
        )
        assert "Dry Run" in result
        # Should not have modified the file
        assert compose_file.read_text() == SAFE_COMPOSE_YAML

    def test_edit_dry_run_no_subprocess(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        with patch("src.modules.docker.safe_run") as mock_run:
            m._docker_compose_edit_impl(
                path=str(compose_file), content=SAFE_COMPOSE_YAML, dry_run=True
            )
            mock_run.assert_not_called()

    def test_edit_writes_file_on_success(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        new_content = yaml.dump(
            {
                "services": {
                    "web": {
                        "image": "nginx:alpine",
                        "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}},
                        "restart": "unless-stopped",
                    }
                }
            }
        )
        m = _make_module(compose_paths=[str(tmp_path)])
        with patch("src.modules.docker.BackupManager") as mock_bm_cls:
            mock_bm = MagicMock()
            mock_bm.create_backup.return_value = "/tmp/backups/compose.bak"
            mock_bm_cls.return_value = mock_bm
            result = m._docker_compose_edit_impl(
                path=str(compose_file), content=new_content
            )
        assert "written successfully" in result or "File written" in result
        assert compose_file.read_text() == new_content

    def test_edit_creates_backup_before_write(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        with patch("src.modules.docker.BackupManager") as mock_bm_cls:
            mock_bm = MagicMock()
            mock_bm.create_backup.return_value = "/tmp/backups/compose.bak"
            mock_bm_cls.return_value = mock_bm
            m._docker_compose_edit_impl(
                path=str(compose_file), content=SAFE_COMPOSE_YAML
            )
            mock_bm.create_backup.assert_called_once_with(str(compose_file))

    def test_edit_invalid_yaml_content_rejected(self, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_edit_impl(
            path=str(compose_file), content=": invalid yaml :::["
        )
        assert "YAML parse error" in result or "error" in result.lower()
        assert compose_file.read_text() == SAFE_COMPOSE_YAML


# ---------------------------------------------------------------------------
# docker_compose_up
# ---------------------------------------------------------------------------


class TestDockerComposeUp:
    @patch("src.modules.docker.safe_run")
    def test_compose_up_blocked_by_critical_violation(
        self, mock_run: Any, tmp_path: Path
    ) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(UNSAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_up_impl(path=str(compose_file))
        assert "BLOCKED" in result
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_compose_up_dry_run(self, mock_run: Any, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_up_impl(path=str(compose_file), dry_run=True)
        assert "Dry Run" in result
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_compose_up_calls_docker_compose(
        self, mock_run: Any, tmp_path: Path
    ) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        mock_run.return_value = _make_command_result(stdout="Creating myapp ... done\n")
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_up_impl(path=str(compose_file))
        call_args = mock_run.call_args[0][0]
        assert "compose" in call_args
        assert "up" in call_args
        assert "-d" in call_args
        assert str(compose_file) in call_args


# ---------------------------------------------------------------------------
# docker_compose_down
# ---------------------------------------------------------------------------


class TestDockerComposeDown:
    @patch("src.modules.docker.safe_run")
    def test_compose_down_dry_run(self, mock_run: Any, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_down_impl(path=str(compose_file), dry_run=True)
        assert "Dry Run" in result
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_compose_down_calls_docker_compose(
        self, mock_run: Any, tmp_path: Path
    ) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        mock_run.return_value = _make_command_result(stdout="Stopping myapp ... done\n")
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_down_impl(path=str(compose_file))
        call_args = mock_run.call_args[0][0]
        assert "compose" in call_args
        assert "down" in call_args


# ---------------------------------------------------------------------------
# docker_compose_pull
# ---------------------------------------------------------------------------


class TestDockerComposePull:
    @patch("src.modules.docker.safe_run")
    def test_compose_pull_dry_run(self, mock_run: Any, tmp_path: Path) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_pull_impl(path=str(compose_file), dry_run=True)
        assert "Dry Run" in result
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_compose_pull_calls_docker_compose(
        self, mock_run: Any, tmp_path: Path
    ) -> None:
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(SAFE_COMPOSE_YAML)
        mock_run.return_value = _make_command_result(stdout="Pulling web ... done\n")
        m = _make_module(compose_paths=[str(tmp_path)])
        result = m._docker_compose_pull_impl(path=str(compose_file))
        call_args = mock_run.call_args[0][0]
        assert "pull" in call_args


# ---------------------------------------------------------------------------
# docker_prune
# ---------------------------------------------------------------------------


class TestDockerPrune:
    @patch("src.modules.docker.safe_run")
    def test_prune_images_calls_image_prune(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="Deleted: sha256:abc123\n")
        m = _make_module()
        result = m._docker_prune_impl(type="images")
        call_args = mock_run.call_args[0][0]
        assert "image" in call_args
        assert "prune" in call_args

    @patch("src.modules.docker.safe_run")
    def test_prune_volumes_calls_volume_prune(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="Deleted Volumes: mydata\n")
        m = _make_module()
        result = m._docker_prune_impl(type="volumes")
        call_args = mock_run.call_args[0][0]
        assert "volume" in call_args
        assert "prune" in call_args

    @patch("src.modules.docker.safe_run")
    def test_prune_networks_calls_network_prune(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="Deleted Networks: mynet\n")
        m = _make_module()
        result = m._docker_prune_impl(type="networks")
        call_args = mock_run.call_args[0][0]
        assert "network" in call_args
        assert "prune" in call_args

    @patch("src.modules.docker.safe_run")
    def test_prune_all_calls_system_prune(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="Total reclaimed space: 1.5GB\n")
        m = _make_module()
        result = m._docker_prune_impl(type="all")
        call_args = mock_run.call_args[0][0]
        assert "system" in call_args
        assert "prune" in call_args
        assert "--volumes" in call_args

    @patch("src.modules.docker.safe_run")
    def test_prune_dry_run_calls_listing_commands(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(stdout="REPOSITORY\tTAG\tSIZE\n")
        m = _make_module()
        result = m._docker_prune_impl(type="images", dry_run=True)
        assert "Dry Run" in result
        # Should have called docker images --filter dangling=true
        assert mock_run.called

    @patch("src.modules.docker.safe_run")
    def test_prune_invalid_type_rejected(self, _mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_prune_impl(type="containers")
        assert "Invalid" in result or "invalid" in result


# ---------------------------------------------------------------------------
# docker_remove
# ---------------------------------------------------------------------------


class TestDockerRemove:
    @patch("src.modules.docker.safe_run")
    def test_remove_stops_then_removes(self, mock_run: Any) -> None:
        mock_run.side_effect = [
            _make_command_result(stdout="myapp\n"),  # docker stop
            _make_command_result(stdout="myapp\n"),  # docker rm
        ]
        m = _make_module()
        result = m._docker_remove_impl(container="myapp")
        assert mock_run.call_count == 2
        stop_args = mock_run.call_args_list[0][0][0]
        rm_args = mock_run.call_args_list[1][0][0]
        assert "stop" in stop_args
        assert "rm" in rm_args

    @patch("src.modules.docker.safe_run")
    def test_remove_dry_run_no_subprocess(self, mock_run: Any) -> None:
        m = _make_module()
        result = m._docker_remove_impl(container="myapp", dry_run=True)
        assert "Dry Run" in result
        mock_run.assert_not_called()

    @patch("src.modules.docker.safe_run")
    def test_remove_nonexistent_container_returns_message(self, mock_run: Any) -> None:
        mock_run.return_value = _make_command_result(
            stderr="No such container: myapp", returncode=1
        )
        m = _make_module()
        result = m._docker_remove_impl(container="myapp")
        assert "does not exist" in result or "No such container" in result


# ---------------------------------------------------------------------------
# _redact_inspect_env helper
# ---------------------------------------------------------------------------


class TestRedactInspectEnv:
    def test_redacts_env_values(self) -> None:
        m = _make_module()
        inspect_data = json.dumps(
            [{"Config": {"Env": ["SECRET_KEY=abc123", "DB_PASS=hunter2"]}}]
        )
        result = m._redact_inspect_env(inspect_data)
        assert "abc123" not in result
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_preserves_env_keys(self) -> None:
        m = _make_module()
        inspect_data = json.dumps(
            [{"Config": {"Env": ["MY_KEY=myvalue"]}}]
        )
        result = m._redact_inspect_env(inspect_data)
        assert "MY_KEY" in result

    def test_invalid_json_returns_original(self) -> None:
        m = _make_module()
        bad = "not valid json {"
        result = m._redact_inspect_env(bad)
        assert result == bad

    def test_non_list_inspect_returns_original(self) -> None:
        m = _make_module()
        data = json.dumps({"Config": {"Env": ["KEY=val"]}})
        result = m._redact_inspect_env(data)
        # Non-list top level — returned as-is
        assert result == data
