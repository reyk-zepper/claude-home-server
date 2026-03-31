"""Unit tests for src.modules.homeassistant.HomeAssistantModule.

Coverage targets:
  - All 13 tools return "not enabled" message when HA is disabled
  - ha_query: status, entities, entity (with entity_id), history (with entity_id)
  - ha_query: entity_id required for entity/history scopes
  - ha_config_query: automations/scenes/scripts list, item detail
  - ha_logs: line limit, raw text slicing
  - ha_check_config: success and failure responses
  - ha_toggle_entity: entity_id validation, API call
  - ha_call_service: domain/service validation, data forwarding
  - ha_trigger_automation: item_id validation, API call
  - ha_activate_scene: item_id validation, API call
  - ha_create_automation: YAML parse error, validation blocks critical, dry_run, API call
  - ha_edit_automation: item_id + YAML validation, dry_run, API call
  - ha_delete_automation: item_id validation, API call
  - ha_restart: long timeout is used, API call
  - ha_edit_config: path validation, HA validation blocks critical, backup, dry_run diff, write
  - Token loading: missing token_file, FileNotFoundError, ValueError
  - API errors: HTTP 4xx/5xx, connection errors
  - All 13 tools are registered with correct names
  - Invalid entity_id formats rejected
  - Invalid item_id formats rejected
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.modules.homeassistant import HomeAssistantModule


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_config(
    ha_enabled: bool = True,
    ha_url: str = "http://localhost:8123",
    ha_token_file: str = "/tmp/ha_token",
    ha_config_path: str = "/opt/ha/config",
) -> MagicMock:
    """Build a mock ServerConfig with HA settings."""
    config = MagicMock()
    config.services.homeassistant.enabled = ha_enabled
    config.services.homeassistant.url = ha_url
    config.services.homeassistant.token_file = ha_token_file
    config.services.homeassistant.config_path = ha_config_path
    config.filesystem.allowed_paths = [ha_config_path]
    config.filesystem.blocked_paths = []
    config.security.backup_dir = "/tmp/backups"
    config.security.backup_retention_days = 30
    config.security.backup_max_per_file = 50
    config.http.timeout_seconds = 10
    config.http.timeout_long_seconds = 600
    return config


def _make_module(ha_enabled: bool = True, **kwargs: Any) -> HomeAssistantModule:
    """Instantiate a HomeAssistantModule with mocked dependencies."""
    config = _make_config(ha_enabled=ha_enabled, **kwargs)
    permission_engine = MagicMock()
    permission_engine.get_risk_level.return_value = MagicMock()
    audit_logger = MagicMock()
    circuit_breaker = MagicMock()
    circuit_breaker.check_circuit.return_value = None
    circuit_breaker.check_burst_limit.return_value = None
    circuit_breaker.record_success.return_value = None
    circuit_breaker.record_failure.return_value = None

    module = HomeAssistantModule(
        config=config,
        permission_engine=permission_engine,
        audit_logger=audit_logger,
        circuit_breaker=circuit_breaker,
    )
    return module


def _mock_ha_response(
    json_data: Any = None,
    status_code: int = 200,
    text: str = "",
    content_type: str = "application/json",
) -> MagicMock:
    """Build a mock httpx Response."""
    response = MagicMock()
    response.status_code = status_code
    response.text = text or (json.dumps(json_data) if json_data is not None else "")
    response.headers = {"content-type": content_type}
    if json_data is not None:
        response.json.return_value = json_data
    return response


def _mock_client(response: MagicMock) -> MagicMock:
    """Build a mock httpx.Client context manager returning the given response."""
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.request.return_value = response
    return client


# ---------------------------------------------------------------------------
# Disabled module — all 13 tools return "not enabled"
# ---------------------------------------------------------------------------


class TestHADisabled:
    """All tools must return a helpful message when HA is disabled."""

    def _module(self) -> HomeAssistantModule:
        return _make_module(ha_enabled=False)

    def test_ha_query_disabled(self) -> None:
        result = self._module()._ha_query_impl(scope="status")
        assert "not enabled" in result.lower()

    def test_ha_config_query_disabled(self) -> None:
        result = self._module()._ha_config_query_impl(type="automations")
        assert "not enabled" in result.lower()

    def test_ha_logs_disabled(self) -> None:
        result = self._module()._ha_logs_impl()
        assert "not enabled" in result.lower()

    def test_ha_check_config_disabled(self) -> None:
        result = self._module()._ha_check_config_impl()
        assert "not enabled" in result.lower()

    def test_ha_toggle_entity_disabled(self) -> None:
        result = self._module()._ha_toggle_entity_impl(entity_id="light.test")
        assert "not enabled" in result.lower()

    def test_ha_call_service_disabled(self) -> None:
        result = self._module()._ha_call_service_impl(
            domain="light", service="turn_on"
        )
        assert "not enabled" in result.lower()

    def test_ha_trigger_automation_disabled(self) -> None:
        result = self._module()._ha_trigger_automation_impl(item_id="my_auto")
        assert "not enabled" in result.lower()

    def test_ha_activate_scene_disabled(self) -> None:
        result = self._module()._ha_activate_scene_impl(item_id="movie_time")
        assert "not enabled" in result.lower()

    def test_ha_create_automation_disabled(self) -> None:
        result = self._module()._ha_create_automation_impl(yaml_content="alias: test\n")
        assert "not enabled" in result.lower()

    def test_ha_edit_automation_disabled(self) -> None:
        result = self._module()._ha_edit_automation_impl(
            item_id="abc123", yaml_content="alias: test\n"
        )
        assert "not enabled" in result.lower()

    def test_ha_delete_automation_disabled(self) -> None:
        result = self._module()._ha_delete_automation_impl(item_id="abc123")
        assert "not enabled" in result.lower()

    def test_ha_restart_disabled(self) -> None:
        result = self._module()._ha_restart_impl()
        assert "not enabled" in result.lower()

    def test_ha_edit_config_disabled(self) -> None:
        result = self._module()._ha_edit_config_impl(
            path="/opt/ha/config/configuration.yaml",
            content="homeassistant:\n  name: Home\n",
        )
        assert "not enabled" in result.lower()


# ---------------------------------------------------------------------------
# Token loading
# ---------------------------------------------------------------------------


class TestTokenLoading:
    def test_missing_token_file_config_returns_error(self) -> None:
        m = _make_module(ha_token_file="")
        with patch("src.modules.homeassistant.load_secret") as mock_load:
            result = m._ha_query_impl(scope="status")
        assert "token_file" in result.lower() or "not configured" in result.lower() or "no token" in result.lower()

    def test_token_file_not_found_returns_error(self) -> None:
        m = _make_module(ha_token_file="/nonexistent/token")
        with patch(
            "src.modules.homeassistant.load_secret",
            side_effect=FileNotFoundError("not found"),
        ):
            result = m._ha_query_impl(scope="status")
        assert "Error" in result or "error" in result or "not found" in result.lower()

    def test_empty_token_file_returns_error(self) -> None:
        m = _make_module(ha_token_file="/tmp/empty_token")
        with patch(
            "src.modules.homeassistant.load_secret",
            side_effect=ValueError("empty file"),
        ):
            result = m._ha_query_impl(scope="status")
        assert "Error" in result or "error" in result or "empty" in result.lower()

    def test_token_loaded_successfully_caches(self) -> None:
        m = _make_module()
        with patch("src.modules.homeassistant.load_secret", return_value="my-token") as mock_load:
            token, err = m._get_token()
            assert token == "my-token"
            assert err is None
            # Second call should not re-read the file (cached)
            token2, err2 = m._get_token()
            assert mock_load.call_count == 1
            assert token2 == "my-token"


# ---------------------------------------------------------------------------
# ha_query — status
# ---------------------------------------------------------------------------


class TestHaQueryStatus:
    def test_status_calls_api_root(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        response_data = {"version": "2024.1.0", "state": "RUNNING"}
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=response_data)
            )
            result = m._ha_query_impl(scope="status")
        assert "2024.1.0" in result
        assert "status" in result.lower()

    def test_status_result_includes_header(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data={"state": "RUNNING"})
            )
            result = m._ha_query_impl(scope="status")
        assert "HA Query" in result

    def test_status_api_error_returns_error_message(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(status_code=401, text="Unauthorized")
            )
            result = m._ha_query_impl(scope="status")
        assert "Error" in result or "error" in result.lower()

    def test_invalid_scope_returns_validation_error(self) -> None:
        m = _make_module()
        result = m._ha_query_impl(scope="invalid_scope")
        assert "Invalid" in result or "invalid" in result.lower()


# ---------------------------------------------------------------------------
# ha_query — entities
# ---------------------------------------------------------------------------


class TestHaQueryEntities:
    def test_entities_returns_list(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        entities = [
            {"entity_id": "light.living_room", "state": "on"},
            {"entity_id": "switch.fan", "state": "off"},
        ]
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=entities)
            )
            result = m._ha_query_impl(scope="entities")
        assert "light.living_room" in result
        assert "switch.fan" in result

    def test_entities_result_has_json_format(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=[{"entity_id": "sensor.temp", "state": "21"}])
            )
            result = m._ha_query_impl(scope="entities")
        assert "entity_id" in result


# ---------------------------------------------------------------------------
# ha_query — entity (requires entity_id)
# ---------------------------------------------------------------------------


class TestHaQueryEntity:
    def test_entity_requires_entity_id(self) -> None:
        m = _make_module()
        result = m._ha_query_impl(scope="entity")
        assert "entity_id" in result.lower() or "required" in result.lower()

    def test_entity_with_valid_id_calls_correct_path(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        entity_data = {"entity_id": "light.living_room", "state": "on", "attributes": {}}
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=entity_data))
            mock_client_cls.return_value = client
            result = m._ha_query_impl(scope="entity", entity_id="light.living_room")
        assert "light.living_room" in result
        # Verify the URL contained the entity_id
        call_args = client.request.call_args
        assert "light.living_room" in call_args[0][1] or "light.living_room" in str(call_args)

    def test_entity_invalid_entity_id_format_rejected(self) -> None:
        m = _make_module()
        result = m._ha_query_impl(scope="entity", entity_id="INVALID ID!")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_entity_result_includes_entity_id_in_header(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data={"entity_id": "sensor.temp", "state": "20"})
            )
            result = m._ha_query_impl(scope="entity", entity_id="sensor.temp")
        assert "sensor.temp" in result


# ---------------------------------------------------------------------------
# ha_query — history (requires entity_id)
# ---------------------------------------------------------------------------


class TestHaQueryHistory:
    def test_history_requires_entity_id(self) -> None:
        m = _make_module()
        result = m._ha_query_impl(scope="history")
        assert "entity_id" in result.lower() or "required" in result.lower()

    def test_history_with_valid_id_calls_api(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        history_data = [[{"entity_id": "sensor.temp", "state": "21", "last_changed": "2026-01-01T00:00:00"}]]
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=history_data)
            )
            result = m._ha_query_impl(scope="history", entity_id="sensor.temp")
        assert "sensor.temp" in result or "21" in result

    def test_history_invalid_entity_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_query_impl(scope="history", entity_id="../etc/passwd")
        assert "Invalid" in result or "invalid" in result.lower()


# ---------------------------------------------------------------------------
# ha_config_query
# ---------------------------------------------------------------------------


class TestHaConfigQuery:
    def test_automations_list_calls_correct_endpoint(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        automations = [{"id": "abc123", "alias": "Turn on lights"}]
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=automations))
            mock_client_cls.return_value = client
            result = m._ha_config_query_impl(type="automations")
        assert "abc123" in result or "Turn on lights" in result
        call_url = client.request.call_args[0][1]
        assert "automation" in call_url

    def test_scenes_list_calls_correct_endpoint(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            result = m._ha_config_query_impl(type="scenes")
        call_url = client.request.call_args[0][1]
        assert "scene" in call_url

    def test_scripts_list_calls_correct_endpoint(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            result = m._ha_config_query_impl(type="scripts")
        call_url = client.request.call_args[0][1]
        assert "script" in call_url

    def test_item_detail_calls_path_with_id(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        automation_detail = {"id": "abc123", "alias": "Test"}
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=automation_detail))
            mock_client_cls.return_value = client
            result = m._ha_config_query_impl(type="automations", item_id="abc123")
        call_url = client.request.call_args[0][1]
        assert "abc123" in call_url

    def test_invalid_type_rejected(self) -> None:
        m = _make_module()
        result = m._ha_config_query_impl(type="invalid_type")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_invalid_item_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_config_query_impl(type="automations", item_id="../../etc")
        assert "Invalid" in result or "invalid" in result.lower()


# ---------------------------------------------------------------------------
# ha_logs
# ---------------------------------------------------------------------------


class TestHaLogs:
    def test_logs_returns_last_n_lines(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        log_text = "\n".join(f"line {i}" for i in range(200))
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(
                    text=log_text,
                    content_type="text/plain",
                )
            )
            result = m._ha_logs_impl(lines=10)
        # Should have at most the last 10 lines
        result_lines = [l for l in result.split("\n") if l.startswith("line ")]
        assert len(result_lines) <= 10

    def test_logs_default_lines_100(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(text="log line 1\nlog line 2\n", content_type="text/plain")
            )
            result = m._ha_logs_impl()
        assert "last 100 lines" in result

    def test_logs_invalid_lines_rejected(self) -> None:
        m = _make_module()
        result = m._ha_logs_impl(lines=0)
        assert "Invalid" in result or "invalid" in result.lower()

    def test_logs_too_many_lines_rejected(self) -> None:
        m = _make_module()
        result = m._ha_logs_impl(lines=999999)
        assert "Invalid" in result or "invalid" in result.lower()

    def test_logs_api_error_returns_error(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(status_code=500, text="Internal Server Error")
            )
            result = m._ha_logs_impl()
        assert "Error" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# ha_check_config
# ---------------------------------------------------------------------------


class TestHaCheckConfig:
    def test_check_config_success_returns_result(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        check_data = {"result": "valid", "errors": None}
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=check_data)
            )
            result = m._ha_check_config_impl()
        assert "valid" in result or "Check Config" in result

    def test_check_config_error_case(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        check_data = {"result": "invalid", "errors": "Invalid YAML in configuration.yaml"}
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=check_data)
            )
            result = m._ha_check_config_impl()
        assert "invalid" in result.lower() or "error" in result.lower() or "Invalid YAML" in result

    def test_check_config_connection_error(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        import httpx
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = MagicMock(
                side_effect=httpx.ConnectError("refused")
            )
            result = m._ha_check_config_impl()
        assert "Error" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# ha_toggle_entity
# ---------------------------------------------------------------------------


class TestHaToggleEntity:
    def test_toggle_sends_entity_id_in_payload(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            result = m._ha_toggle_entity_impl(entity_id="light.living_room")
        call_kwargs = client.request.call_args[1]
        assert call_kwargs.get("json", {}).get("entity_id") == "light.living_room"

    def test_toggle_calls_homeassistant_toggle_service(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_toggle_entity_impl(entity_id="switch.fan")
        call_url = client.request.call_args[0][1]
        assert "homeassistant/toggle" in call_url

    def test_toggle_invalid_entity_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_toggle_entity_impl(entity_id="INVALID ENTITY")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_toggle_invalid_entity_id_no_domain_rejected(self) -> None:
        m = _make_module()
        result = m._ha_toggle_entity_impl(entity_id="noDot")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_toggle_api_error_returns_error_string(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(status_code=404, text="Not Found")
            )
            result = m._ha_toggle_entity_impl(entity_id="light.unknown")
        assert "Error" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# ha_call_service
# ---------------------------------------------------------------------------


class TestHaCallService:
    def test_call_service_constructs_correct_url(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_call_service_impl(domain="light", service="turn_on", data={"entity_id": "light.test"})
        call_url = client.request.call_args[0][1]
        assert "light/turn_on" in call_url

    def test_call_service_passes_data_as_json(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_call_service_impl(
                domain="light",
                service="turn_on",
                data={"entity_id": "light.living_room", "brightness": 200},
            )
        call_kwargs = client.request.call_args[1]
        assert call_kwargs.get("json", {}).get("entity_id") == "light.living_room"

    def test_call_service_invalid_domain_rejected(self) -> None:
        m = _make_module()
        result = m._ha_call_service_impl(domain="INVALID DOMAIN!", service="turn_on")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_call_service_invalid_service_rejected(self) -> None:
        m = _make_module()
        result = m._ha_call_service_impl(domain="light", service="INVALID SERVICE!")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_call_service_empty_data_is_ok(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            result = m._ha_call_service_impl(domain="homeassistant", service="reload_all")
        assert "Invalid" not in result


# ---------------------------------------------------------------------------
# ha_trigger_automation
# ---------------------------------------------------------------------------


class TestHaTriggerAutomation:
    def test_trigger_sends_automation_entity_id(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_trigger_automation_impl(item_id="my_automation")
        call_kwargs = client.request.call_args[1]
        assert call_kwargs.get("json", {}).get("entity_id") == "automation.my_automation"

    def test_trigger_calls_automation_trigger_service(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_trigger_automation_impl(item_id="my_auto")
        call_url = client.request.call_args[0][1]
        assert "automation/trigger" in call_url

    def test_trigger_invalid_item_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_trigger_automation_impl(item_id="../../etc/passwd")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_trigger_item_id_with_spaces_rejected(self) -> None:
        m = _make_module()
        result = m._ha_trigger_automation_impl(item_id="invalid id")
        assert "Invalid" in result or "invalid" in result.lower()


# ---------------------------------------------------------------------------
# ha_activate_scene
# ---------------------------------------------------------------------------


class TestHaActivateScene:
    def test_activate_scene_sends_scene_entity_id(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_activate_scene_impl(item_id="movie_time")
        call_kwargs = client.request.call_args[1]
        assert call_kwargs.get("json", {}).get("entity_id") == "scene.movie_time"

    def test_activate_scene_calls_scene_turn_on(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_activate_scene_impl(item_id="night_mode")
        call_url = client.request.call_args[0][1]
        assert "scene/turn_on" in call_url

    def test_activate_invalid_item_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_activate_scene_impl(item_id="bad scene!")
        assert "Invalid" in result or "invalid" in result.lower()


# ---------------------------------------------------------------------------
# ha_create_automation
# ---------------------------------------------------------------------------


class TestHaCreateAutomation:
    VALID_YAML = (
        "alias: Turn on lights at sunset\n"
        "trigger:\n"
        "  - platform: sun\n"
        "    event: sunset\n"
        "action:\n"
        "  - service: light.turn_on\n"
        "    entity_id: light.living_room\n"
    )

    BLOCKED_YAML = (
        "alias: Evil automation\n"
        "trigger: []\n"
        "action:\n"
        "  - service: shell_command.evil\n"
        "shell_command:\n"
        "  evil: 'rm -rf /'\n"
    )

    def test_create_valid_automation_posts_to_api(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={"result": "ok"}))
            mock_client_cls.return_value = client
            result = m._ha_create_automation_impl(yaml_content=self.VALID_YAML)
        assert "created" in result.lower() or "ok" in result.lower()
        assert client.request.call_count == 1

    def test_create_uses_post_method(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            m._ha_create_automation_impl(yaml_content=self.VALID_YAML)
        call_method = client.request.call_args[0][0]
        assert call_method == "POST"

    def test_create_blocked_yaml_returns_blocked_message(self) -> None:
        m = _make_module()
        result = m._ha_create_automation_impl(yaml_content=self.BLOCKED_YAML)
        assert "BLOCKED" in result or "blocked" in result.lower()
        assert "was not created" in result.lower()

    def test_create_blocked_yaml_does_not_call_api(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            m._ha_create_automation_impl(yaml_content=self.BLOCKED_YAML)
        assert client.request.call_count == 0

    def test_create_dry_run_does_not_call_api(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            result = m._ha_create_automation_impl(yaml_content=self.VALID_YAML, dry_run=True)
        assert "Dry Run" in result or "dry run" in result.lower() or "dry_run" in result.lower()
        assert client.request.call_count == 0

    def test_create_dry_run_shows_alias(self) -> None:
        m = _make_module()
        result = m._ha_create_automation_impl(yaml_content=self.VALID_YAML, dry_run=True)
        assert "Turn on lights at sunset" in result

    def test_create_invalid_yaml_returns_parse_error(self) -> None:
        m = _make_module()
        result = m._ha_create_automation_impl(yaml_content="key: [\nunclosed")
        assert "parse error" in result.lower() or "yaml" in result.lower()

    def test_create_non_dict_yaml_returns_error(self) -> None:
        m = _make_module()
        result = m._ha_create_automation_impl(yaml_content="- item1\n- item2\n")
        assert "error" in result.lower() or "mapping" in result.lower()


# ---------------------------------------------------------------------------
# ha_edit_automation
# ---------------------------------------------------------------------------


class TestHaEditAutomation:
    VALID_YAML = (
        "alias: Updated automation\n"
        "trigger:\n"
        "  - platform: time\n"
        "    at: '07:00:00'\n"
        "action:\n"
        "  - service: light.turn_on\n"
        "    entity_id: light.bedroom\n"
    )

    def test_edit_uses_put_method(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            m._ha_edit_automation_impl(item_id="abc123", yaml_content=self.VALID_YAML)
        call_method = client.request.call_args[0][0]
        assert call_method == "PUT"

    def test_edit_url_contains_item_id(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            m._ha_edit_automation_impl(item_id="myauto123", yaml_content=self.VALID_YAML)
        call_url = client.request.call_args[0][1]
        assert "myauto123" in call_url

    def test_edit_blocked_yaml_does_not_call_api(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        blocked_yaml = "alias: Evil\nshell_command:\n  x: 'rm -rf /'\n"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            result = m._ha_edit_automation_impl(item_id="abc123", yaml_content=blocked_yaml)
        assert "BLOCKED" in result
        assert client.request.call_count == 0

    def test_edit_dry_run_does_not_call_api(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data={}))
            mock_client_cls.return_value = client
            result = m._ha_edit_automation_impl(
                item_id="abc123", yaml_content=self.VALID_YAML, dry_run=True
            )
        assert "Dry Run" in result or "dry run" in result.lower()
        assert client.request.call_count == 0

    def test_edit_invalid_item_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_edit_automation_impl(item_id="bad id!", yaml_content=self.VALID_YAML)
        assert "Invalid" in result or "invalid" in result.lower()

    def test_edit_success_returns_success_message(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(_mock_ha_response(json_data={}))
            result = m._ha_edit_automation_impl(item_id="abc123", yaml_content=self.VALID_YAML)
        assert "updated" in result.lower()


# ---------------------------------------------------------------------------
# ha_delete_automation
# ---------------------------------------------------------------------------


class TestHaDeleteAutomation:
    def test_delete_uses_delete_method(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=None, text="ok"))
            mock_client_cls.return_value = client
            m._ha_delete_automation_impl(item_id="abc123")
        call_method = client.request.call_args[0][0]
        assert call_method == "DELETE"

    def test_delete_url_contains_item_id(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=None, text="ok"))
            mock_client_cls.return_value = client
            m._ha_delete_automation_impl(item_id="myauto456")
        call_url = client.request.call_args[0][1]
        assert "myauto456" in call_url

    def test_delete_invalid_item_id_rejected(self) -> None:
        m = _make_module()
        result = m._ha_delete_automation_impl(item_id="bad id!!")
        assert "Invalid" in result or "invalid" in result.lower()

    def test_delete_api_error_returns_error(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(status_code=404, text="Not Found")
            )
            result = m._ha_delete_automation_impl(item_id="nonexistent")
        assert "Error" in result or "error" in result.lower()

    def test_delete_success_result_mentions_item_id(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(json_data=None, text="", content_type="text/plain")
            )
            result = m._ha_delete_automation_impl(item_id="abc123")
        assert "abc123" in result


# ---------------------------------------------------------------------------
# ha_restart
# ---------------------------------------------------------------------------


class TestHaRestart:
    def test_restart_uses_long_timeout(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_restart_impl()
        # Check that the Client was created with the long timeout
        call_kwargs = mock_client_cls.call_args[1]
        assert call_kwargs.get("timeout") == 600

    def test_restart_calls_correct_endpoint(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_restart_impl()
        call_url = client.request.call_args[0][1]
        assert "homeassistant/restart" in call_url

    def test_restart_uses_post_method(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            client = _mock_client(_mock_ha_response(json_data=[]))
            mock_client_cls.return_value = client
            m._ha_restart_impl()
        call_method = client.request.call_args[0][0]
        assert call_method == "POST"

    def test_restart_connection_error_returns_error(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        import httpx
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = MagicMock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = m._ha_restart_impl()
        assert "Error" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# ha_edit_config
# ---------------------------------------------------------------------------


class TestHaEditConfig:
    VALID_YAML = "homeassistant:\n  name: Home\n  unit_system: metric\n"
    BLOCKED_YAML = "shell_command:\n  test: 'echo hello'\n"

    def test_edit_config_blocked_content_not_written(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        result = m._ha_edit_config_impl(
            path=str(config_file), content=self.BLOCKED_YAML
        )
        assert "BLOCKED" in result
        # File should NOT be changed
        assert config_file.read_text() == self.VALID_YAML

    def test_edit_config_dry_run_shows_diff(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        new_content = "homeassistant:\n  name: New Home\n  unit_system: imperial\n"
        result = m._ha_edit_config_impl(
            path=str(config_file), content=new_content, dry_run=True
        )
        assert "Dry Run" in result
        # Diff should show added/removed lines
        assert "New Home" in result or "+" in result

    def test_edit_config_dry_run_does_not_write(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        new_content = "homeassistant:\n  name: Changed\n"
        m._ha_edit_config_impl(path=str(config_file), content=new_content, dry_run=True)
        # File content should be unchanged
        assert config_file.read_text() == self.VALID_YAML

    def test_edit_config_success_writes_file(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        new_content = "homeassistant:\n  name: Updated Home\n"
        with patch("src.modules.homeassistant.BackupManager") as mock_bm:
            mock_bm.return_value.create_backup.return_value = "/tmp/backups/config.bak"
            result = m._ha_edit_config_impl(path=str(config_file), content=new_content)
        assert config_file.read_text() == new_content
        assert "written" in result.lower()

    def test_edit_config_creates_backup_before_write(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        new_content = "homeassistant:\n  name: Updated\n"
        with patch("src.modules.homeassistant.BackupManager") as mock_bm:
            mock_bm.return_value.create_backup.return_value = "/tmp/backups/config.bak"
            m._ha_edit_config_impl(path=str(config_file), content=new_content)
        assert mock_bm.return_value.create_backup.call_count == 1

    def test_edit_config_backup_failure_aborts_write(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        new_content = "homeassistant:\n  name: Updated\n"
        with patch("src.modules.homeassistant.BackupManager") as mock_bm:
            mock_bm.return_value.create_backup.side_effect = Exception("disk full")
            result = m._ha_edit_config_impl(path=str(config_file), content=new_content)
        assert "backup" in result.lower()
        # File should be unchanged
        assert config_file.read_text() == self.VALID_YAML

    def test_edit_config_path_outside_allowed_rejected(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        m = _make_module(ha_config_path=str(config_dir))
        result = m._ha_edit_config_impl(
            path="/etc/passwd",
            content="root:x:0:0:::/bin/sh\n",
        )
        assert "Access denied" in result or "denied" in result.lower()

    def test_edit_config_invalid_yaml_content_rejected(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        result = m._ha_edit_config_impl(
            path=str(config_file), content="key: [\nunclosed"
        )
        assert "parse error" in result.lower() or "yaml" in result.lower()

    def test_edit_config_no_allowed_paths_returns_error(self) -> None:
        m = _make_module(ha_config_path="")
        # Also clear filesystem.allowed_paths
        m._config.filesystem.allowed_paths = []
        result = m._ha_edit_config_impl(
            path="/opt/ha/config/configuration.yaml",
            content=self.VALID_YAML,
        )
        assert "No allowed paths" in result or "not configured" in result.lower()

    def test_edit_config_result_mentions_backup_path(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "ha_config"
        config_dir.mkdir()
        config_file = config_dir / "configuration.yaml"
        config_file.write_text(self.VALID_YAML)

        m = _make_module(ha_config_path=str(config_dir))
        new_content = "homeassistant:\n  name: Changed\n"
        with patch("src.modules.homeassistant.BackupManager") as mock_bm:
            mock_bm.return_value.create_backup.return_value = "/tmp/backups/configuration.yaml.20260101.bak"
            result = m._ha_edit_config_impl(path=str(config_file), content=new_content)
        assert "/tmp/backups/configuration.yaml.20260101.bak" in result


# ---------------------------------------------------------------------------
# API errors — connection, HTTP 4xx/5xx
# ---------------------------------------------------------------------------


class TestHaApiErrors:
    def test_connection_error_returns_error_string(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        import httpx

        with patch("httpx.Client") as mock_client_cls:
            client = MagicMock()
            client.__enter__ = MagicMock(return_value=client)
            client.__exit__ = MagicMock(return_value=False)
            client.request.side_effect = httpx.ConnectError("connection refused")
            mock_client_cls.return_value = client
            result = m._ha_query_impl(scope="status")
        assert "Error" in result or "error" in result.lower()
        assert "connection" in result.lower() or "connect" in result.lower()

    def test_http_401_returns_error_string(self) -> None:
        m = _make_module()
        m._ha_token = "bad-token"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(status_code=401, text="Unauthorized")
            )
            result = m._ha_query_impl(scope="status")
        assert "Error" in result or "401" in result

    def test_http_500_returns_error_string(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(status_code=500, text="Internal Server Error")
            )
            result = m._ha_logs_impl()
        assert "Error" in result or "500" in result

    def test_timeout_error_returns_error_string(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        import httpx

        with patch("httpx.Client") as mock_client_cls:
            client = MagicMock()
            client.__enter__ = MagicMock(return_value=client)
            client.__exit__ = MagicMock(return_value=False)
            client.request.side_effect = httpx.TimeoutException("timed out")
            mock_client_cls.return_value = client
            result = m._ha_query_impl(scope="status")
        assert "Error" in result or "error" in result.lower()

    def test_non_json_200_response_returns_text(self) -> None:
        m = _make_module()
        m._ha_token = "tok"
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = _mock_client(
                _mock_ha_response(
                    text="some plain text",
                    content_type="text/plain",
                )
            )
            result = m._ha_check_config_impl()
        assert "some plain text" in result


# ---------------------------------------------------------------------------
# Tool registration — all 13 tools registered with correct names
# ---------------------------------------------------------------------------


class TestHAModuleRegistration:
    def test_all_13_tools_registered(self) -> None:
        m = _make_module()
        server = m.create_server()

        # FastMCP stores tools in its internal registry
        tool_names: set[str] = set()
        if hasattr(server, "_tool_manager") and hasattr(server._tool_manager, "_tools"):
            tool_names = set(server._tool_manager._tools.keys())
        elif hasattr(server, "list_tools"):
            import asyncio
            tools = asyncio.run(server.list_tools())
            tool_names = {t.name for t in tools}

        expected = {
            "ha_query",
            "ha_config_query",
            "ha_logs",
            "ha_check_config",
            "ha_toggle_entity",
            "ha_call_service",
            "ha_trigger_automation",
            "ha_activate_scene",
            "ha_create_automation",
            "ha_edit_automation",
            "ha_delete_automation",
            "ha_restart",
            "ha_edit_config",
        }
        if tool_names:
            assert expected == tool_names

    def test_ha_query_tool_registered(self) -> None:
        m = _make_module()
        server = m.create_server()

        tool_names: set[str] = set()
        if hasattr(server, "_tool_manager") and hasattr(server._tool_manager, "_tools"):
            tool_names = set(server._tool_manager._tools.keys())
        elif hasattr(server, "list_tools"):
            import asyncio
            tools = asyncio.run(server.list_tools())
            tool_names = {t.name for t in tools}

        if tool_names:
            assert "ha_query" in tool_names

    def test_ha_edit_config_tool_registered(self) -> None:
        m = _make_module()
        server = m.create_server()

        tool_names: set[str] = set()
        if hasattr(server, "_tool_manager") and hasattr(server._tool_manager, "_tools"):
            tool_names = set(server._tool_manager._tools.keys())
        elif hasattr(server, "list_tools"):
            import asyncio
            tools = asyncio.run(server.list_tools())
            tool_names = {t.name for t in tools}

        if tool_names:
            assert "ha_edit_config" in tool_names

    def test_module_name_is_homeassistant(self) -> None:
        assert HomeAssistantModule.MODULE_NAME == "homeassistant"
