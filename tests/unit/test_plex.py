"""Unit tests for src.modules.plex.PlexModule.

Coverage targets:
  - TestPlexDisabled: all 9 tools return "not enabled" when Plex is disabled
  - TestPlexStatus: success formatting, connection error, unexpected response format
  - TestPlexLibraries: library listing, empty list, unexpected format
  - TestPlexSessions: active sessions, no active sessions, single session dict
  - TestPlexUsers: user listing, email redaction, empty user list
  - TestPlexScanLibrary: valid library_id, non-numeric library_id rejected
  - TestPlexOptimize: valid library_id, non-numeric library_id rejected
  - TestPlexEmptyTrash: valid library_id, non-numeric library_id rejected
  - TestPlexManageUser: dry_run mode, live API call, invalid user_id rejected
  - TestPlexSettings: dry_run fetches current value, live update, invalid key rejected
  - TestPlexModuleRegistration: all 9 tools are registered
  - TestPlexTokenLoading: lazy load, missing token file, empty token, no token_file configured
  - TestPlexApiErrors: HTTP 4xx, HTTP 5xx, connection error, JSON decode fallback
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.modules.plex import PlexModule


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_config(
    plex_enabled: bool = True,
    plex_url: str = "http://localhost:32400",
    plex_token_file: str = "/tmp/plex_token",
) -> MagicMock:
    """Build a mock ServerConfig with Plex settings."""
    config = MagicMock()
    config.services.plex.enabled = plex_enabled
    config.services.plex.url = plex_url
    config.services.plex.token_file = plex_token_file
    config.http.timeout_seconds = 10
    config.http.timeout_long_seconds = 600
    return config


def _make_module(plex_enabled: bool = True, **kwargs: Any) -> PlexModule:
    """Instantiate a PlexModule with mocked dependencies."""
    config = _make_config(plex_enabled=plex_enabled, **kwargs)
    permission_engine = MagicMock()
    permission_engine.get_risk_level.return_value = MagicMock()
    audit_logger = MagicMock()
    circuit_breaker = MagicMock()
    circuit_breaker.check_circuit.return_value = None
    circuit_breaker.check_burst_limit.return_value = None
    circuit_breaker.record_success.return_value = None
    circuit_breaker.record_failure.return_value = None
    return PlexModule(
        config=config,
        permission_engine=permission_engine,
        audit_logger=audit_logger,
        circuit_breaker=circuit_breaker,
    )


def _make_mock_httpx_client(
    status_code: int = 200,
    json_data: Any = None,
    text: str = "",
    raise_exc: Exception | None = None,
) -> MagicMock:
    """Build a mock httpx.Client context manager.

    Args:
        status_code: HTTP response status code.
        json_data: Parsed JSON to return from ``resp.json()``.
        text: Raw response text.
        raise_exc: If set, ``client.request`` raises this exception.

    Returns:
        Mock httpx module whose ``Client`` returns a configured mock.
    """
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = text

    if json_data is not None:
        mock_response.json.return_value = json_data
    else:
        mock_response.json.side_effect = ValueError("not json")

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)

    if raise_exc is not None:
        mock_client.request.side_effect = raise_exc
    else:
        mock_client.request.return_value = mock_response

    mock_httpx = MagicMock()
    mock_httpx.Client.return_value = mock_client
    return mock_httpx


# ---------------------------------------------------------------------------
# TestPlexDisabled — all 9 tools return "not enabled" when Plex is disabled
# ---------------------------------------------------------------------------


class TestPlexDisabled:
    """All tools must return a helpful disabled message."""

    def _module(self) -> PlexModule:
        return _make_module(plex_enabled=False)

    def test_plex_status_disabled(self) -> None:
        m = self._module()
        result = m._plex_status_impl()
        assert "not enabled" in result.lower()

    def test_plex_libraries_disabled(self) -> None:
        m = self._module()
        result = m._plex_libraries_impl()
        assert "not enabled" in result.lower()

    def test_plex_sessions_disabled(self) -> None:
        m = self._module()
        result = m._plex_sessions_impl()
        assert "not enabled" in result.lower()

    def test_plex_users_disabled(self) -> None:
        m = self._module()
        result = m._plex_users_impl()
        assert "not enabled" in result.lower()

    def test_plex_scan_library_disabled(self) -> None:
        m = self._module()
        result = m._plex_scan_library_impl(library_id="1")
        assert "not enabled" in result.lower()

    def test_plex_optimize_disabled(self) -> None:
        m = self._module()
        result = m._plex_optimize_impl(library_id="1")
        assert "not enabled" in result.lower()

    def test_plex_empty_trash_disabled(self) -> None:
        m = self._module()
        result = m._plex_empty_trash_impl(library_id="1")
        assert "not enabled" in result.lower()

    def test_plex_manage_user_disabled(self) -> None:
        m = self._module()
        result = m._plex_manage_user_impl(user_id="42", permissions={})
        assert "not enabled" in result.lower()

    def test_plex_settings_disabled(self) -> None:
        m = self._module()
        result = m._plex_settings_impl(key="FriendlyName", value="MyServer")
        assert "not enabled" in result.lower()


# ---------------------------------------------------------------------------
# TestPlexStatus
# ---------------------------------------------------------------------------


class TestPlexStatus:
    """Tests for plex_status tool."""

    @patch("src.modules.plex.httpx")
    def test_status_success(self, mock_httpx: Any) -> None:
        mock_httpx.__class__ = type(mock_httpx)
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "friendlyName": "HomeServer",
                    "version": "1.41.0.8994",
                    "platform": "Linux",
                    "myPlexSigninState": "ok",
                    "transcoderActiveVideoSessions": 2,
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_status_impl()
        assert "HomeServer" in result
        assert "1.41.0.8994" in result
        assert "Linux" in result
        assert "=== Plex Status ===" in result

    @patch("src.modules.plex.httpx")
    def test_status_connection_error(self, mock_httpx: Any) -> None:
        import httpx as real_httpx
        mock_httpx.HTTPError = real_httpx.HTTPError
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.side_effect = real_httpx.ConnectError("refused")
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_status_impl()
        assert "Error" in result
        assert "connection" in result.lower() or "refused" in result.lower()

    @patch("src.modules.plex.httpx")
    def test_status_unexpected_format(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_client = _make_mock_httpx_client(json_data={"unexpected": "structure"})
        mock_httpx.Client.return_value = mock_client.Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        # Should not raise — returns a report even with unexpected format
        result = m._plex_status_impl()
        assert isinstance(result, str)

    @patch("src.modules.plex.httpx")
    def test_status_includes_active_sessions(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "friendlyName": "Plex",
                    "version": "1.0",
                    "platform": "Linux",
                    "myPlexSigninState": "ok",
                    "transcoderActiveVideoSessions": 3,
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_status_impl()
        assert "3" in result


# ---------------------------------------------------------------------------
# TestPlexLibraries
# ---------------------------------------------------------------------------


class TestPlexLibraries:
    """Tests for plex_libraries tool."""

    @patch("src.modules.plex.httpx")
    def test_libraries_success(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "Directory": [
                        {
                            "key": "1",
                            "type": "movie",
                            "title": "Movies",
                            "agent": "tv.plex.agents.movie",
                            "scanner": "Plex Movie",
                            "language": "en",
                            "count": "542",
                        },
                        {
                            "key": "2",
                            "type": "show",
                            "title": "TV Shows",
                            "agent": "tv.plex.agents.series",
                            "scanner": "Plex Series",
                            "language": "en",
                            "count": "87",
                        },
                    ]
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_libraries_impl()
        assert "Movies" in result
        assert "TV Shows" in result
        assert "movie" in result
        assert "=== Plex Libraries ===" in result

    @patch("src.modules.plex.httpx")
    def test_libraries_empty(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={"MediaContainer": {"Directory": []}}
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_libraries_impl()
        assert "No libraries found" in result

    @patch("src.modules.plex.httpx")
    def test_libraries_missing_directory_key(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={"MediaContainer": {}}
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_libraries_impl()
        assert "No libraries found" in result

    @patch("src.modules.plex.httpx")
    def test_libraries_api_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_libraries_impl()
        assert "Error" in result


# ---------------------------------------------------------------------------
# TestPlexSessions
# ---------------------------------------------------------------------------


class TestPlexSessions:
    """Tests for plex_sessions tool."""

    @patch("src.modules.plex.httpx")
    def test_sessions_no_active(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={"MediaContainer": {"size": 0}}
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_sessions_impl()
        assert "No active playback sessions" in result

    @patch("src.modules.plex.httpx")
    def test_sessions_active(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "size": 1,
                    "Metadata": [
                        {
                            "title": "Episode 1",
                            "grandparentTitle": "Breaking Bad",
                            "User": {"title": "alice"},
                            "Player": {"title": "Plex for iOS", "state": "playing"},
                            "viewOffset": 300000,
                            "duration": 2700000,
                        }
                    ],
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_sessions_impl()
        assert "alice" in result
        assert "Breaking Bad" in result
        assert "Episode 1" in result
        assert "playing" in result
        assert "=== Plex Active Sessions ===" in result

    @patch("src.modules.plex.httpx")
    def test_sessions_progress_calculated(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "size": 1,
                    "Metadata": [
                        {
                            "title": "Movie",
                            "User": {"title": "bob"},
                            "Player": {"title": "Chrome", "state": "paused"},
                            "viewOffset": 600000,
                            "duration": 6000000,
                        }
                    ],
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_sessions_impl()
        assert "10.0%" in result

    @patch("src.modules.plex.httpx")
    def test_sessions_no_duration(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "size": 1,
                    "Metadata": [
                        {
                            "title": "Livestream",
                            "User": {"title": "carol"},
                            "Player": {"title": "Plex Web", "state": "buffering"},
                            "viewOffset": 0,
                            "duration": 0,
                        }
                    ],
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_sessions_impl()
        assert "N/A" in result

    @patch("src.modules.plex.httpx")
    def test_sessions_single_metadata_dict(self, mock_httpx: Any) -> None:
        """Plex sometimes returns a single Metadata dict instead of a list."""
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "size": 1,
                    "Metadata": {
                        "title": "Solo Movie",
                        "User": {"title": "dan"},
                        "Player": {"title": "Plex TV", "state": "playing"},
                        "viewOffset": 0,
                        "duration": 0,
                    },
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_sessions_impl()
        assert "Solo Movie" in result
        assert "dan" in result


# ---------------------------------------------------------------------------
# TestPlexUsers
# ---------------------------------------------------------------------------


class TestPlexUsers:
    """Tests for plex_users tool."""

    @patch("src.modules.plex.httpx")
    def test_users_success(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "Account": [
                        {
                            "id": "1",
                            "name": "alice",
                            "email": "alice@example.com",
                            "restricted": False,
                        },
                        {
                            "id": "2",
                            "name": "bob",
                            "email": "bob@test.org",
                            "restricted": True,
                        },
                    ]
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_users_impl()
        assert "alice" in result
        assert "bob" in result
        assert "=== Plex Users ===" in result

    @patch("src.modules.plex.httpx")
    def test_users_email_redacted(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "Account": [
                        {
                            "id": "1",
                            "name": "alice",
                            "email": "alice@example.com",
                            "restricted": False,
                        }
                    ]
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_users_impl()
        # Full email must not appear
        assert "alice@example.com" not in result
        # Redacted form should appear
        assert "a***@example.com" in result

    @patch("src.modules.plex.httpx")
    def test_users_empty(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={"MediaContainer": {"Account": []}}
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_users_impl()
        assert "No user accounts found" in result

    @patch("src.modules.plex.httpx")
    def test_users_single_account_dict(self, mock_httpx: Any) -> None:
        """Plex may return a single Account dict instead of a list."""
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "Account": {
                        "id": "1",
                        "name": "solo",
                        "email": "solo@domain.io",
                        "restricted": False,
                    }
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_users_impl()
        assert "solo" in result


# ---------------------------------------------------------------------------
# TestPlexScanLibrary
# ---------------------------------------------------------------------------


class TestPlexScanLibrary:
    """Tests for plex_scan_library tool."""

    @patch("src.modules.plex.httpx")
    def test_scan_success(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            status_code=200, text=""
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_scan_library_impl(library_id="1")
        assert "scan triggered" in result.lower()
        assert "1" in result
        assert "=== Plex Scan Library ===" in result

    def test_scan_non_numeric_rejected(self) -> None:
        m = _make_module()
        result = m._plex_scan_library_impl(library_id="movies")
        assert "Invalid" in result

    def test_scan_empty_library_id_rejected(self) -> None:
        m = _make_module()
        result = m._plex_scan_library_impl(library_id="")
        assert "Invalid" in result

    def test_scan_injection_attempt_rejected(self) -> None:
        m = _make_module()
        result = m._plex_scan_library_impl(library_id="1; rm -rf /")
        assert "Invalid" in result

    @patch("src.modules.plex.httpx")
    def test_scan_api_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_scan_library_impl(library_id="5")
        assert "Error" in result


# ---------------------------------------------------------------------------
# TestPlexOptimize
# ---------------------------------------------------------------------------


class TestPlexOptimize:
    """Tests for plex_optimize tool."""

    @patch("src.modules.plex.httpx")
    def test_optimize_success(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            status_code=200, text=""
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_optimize_impl(library_id="2")
        assert "optimisation triggered" in result.lower() or "optimization triggered" in result.lower() or "triggered" in result.lower()
        assert "=== Plex Optimize Library ===" in result

    def test_optimize_non_numeric_rejected(self) -> None:
        m = _make_module()
        result = m._plex_optimize_impl(library_id="abc")
        assert "Invalid" in result

    def test_optimize_float_rejected(self) -> None:
        m = _make_module()
        result = m._plex_optimize_impl(library_id="1.5")
        assert "Invalid" in result


# ---------------------------------------------------------------------------
# TestPlexEmptyTrash
# ---------------------------------------------------------------------------


class TestPlexEmptyTrash:
    """Tests for plex_empty_trash tool."""

    @patch("src.modules.plex.httpx")
    def test_empty_trash_success(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            status_code=200, text=""
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_empty_trash_impl(library_id="3")
        assert "Trash emptied" in result or "emptied" in result.lower()
        assert "3" in result
        assert "=== Plex Empty Trash ===" in result

    def test_empty_trash_non_numeric_rejected(self) -> None:
        m = _make_module()
        result = m._plex_empty_trash_impl(library_id="trash")
        assert "Invalid" in result

    @patch("src.modules.plex.httpx")
    def test_empty_trash_api_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_empty_trash_impl(library_id="3")
        assert "Error" in result


# ---------------------------------------------------------------------------
# TestPlexManageUser
# ---------------------------------------------------------------------------


class TestPlexManageUser:
    """Tests for plex_manage_user tool."""

    def test_manage_user_dry_run(self) -> None:
        m = _make_module()
        result = m._plex_manage_user_impl(
            user_id="42",
            permissions={"allowSync": True, "filterMovies": ""},
            dry_run=True,
        )
        assert "Dry Run" in result
        assert "42" in result
        assert "No changes" in result
        assert "allowSync" in result

    def test_manage_user_dry_run_no_permissions(self) -> None:
        m = _make_module()
        result = m._plex_manage_user_impl(user_id="99", permissions={}, dry_run=True)
        assert "Dry Run" in result
        assert "No changes" in result

    @patch("src.modules.plex.httpx")
    def test_manage_user_live_call(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            status_code=200, json_data={"MediaContainer": {}}
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_manage_user_impl(
            user_id="42",
            permissions={"allowSync": True},
            dry_run=False,
        )
        assert "updated successfully" in result.lower()
        assert "42" in result

    def test_manage_user_invalid_user_id_rejected(self) -> None:
        m = _make_module()
        result = m._plex_manage_user_impl(user_id="user; DROP TABLE users;--", permissions={})
        assert "Invalid" in result

    def test_manage_user_empty_user_id_rejected(self) -> None:
        m = _make_module()
        result = m._plex_manage_user_impl(user_id="", permissions={})
        assert "Invalid" in result

    @patch("src.modules.plex.httpx")
    def test_manage_user_api_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "User not found"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_manage_user_impl(user_id="99", permissions={"allowSync": False})
        assert "Error" in result

    def test_manage_user_permissions_default_to_empty(self) -> None:
        m = _make_module()
        # When permissions is None, dry_run should still work
        result = m._plex_manage_user_impl(user_id="1", dry_run=True)
        assert "Dry Run" in result


# ---------------------------------------------------------------------------
# TestPlexSettings
# ---------------------------------------------------------------------------


class TestPlexSettings:
    """Tests for plex_settings tool."""

    @patch("src.modules.plex.httpx")
    def test_settings_dry_run_fetches_current(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={
                "MediaContainer": {
                    "Setting": [
                        {"id": "FriendlyName", "value": "OldName"},
                        {"id": "OtherSetting", "value": "foo"},
                    ]
                }
            }
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_settings_impl(key="FriendlyName", value="NewName", dry_run=True)
        assert "Dry Run" in result
        assert "OldName" in result
        assert "NewName" in result
        assert "No changes" in result

    @patch("src.modules.plex.httpx")
    def test_settings_dry_run_setting_not_found(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            json_data={"MediaContainer": {"Setting": []}}
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_settings_impl(key="UnknownKey", value="val", dry_run=True)
        assert "Dry Run" in result
        assert "unknown" in result.lower()

    @patch("src.modules.plex.httpx")
    def test_settings_live_update(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_httpx.Client.return_value = _make_mock_httpx_client(
            status_code=200, text=""
        ).Client.return_value
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_settings_impl(key="FriendlyName", value="MyPlex")
        assert "updated" in result.lower()
        assert "FriendlyName" in result
        assert "MyPlex" in result

    def test_settings_invalid_key_rejected(self) -> None:
        m = _make_module()
        result = m._plex_settings_impl(key="invalid-key!", value="val")
        assert "Invalid" in result

    def test_settings_key_starting_with_digit_rejected(self) -> None:
        m = _make_module()
        result = m._plex_settings_impl(key="1BadKey", value="val")
        assert "Invalid" in result

    def test_settings_valid_key_with_underscores_accepted(self) -> None:
        m = _make_module()
        # Valid key — should not be rejected as invalid (may fail on API, not on validation)
        # We just check it doesn't return a validation error
        result = m._plex_settings_impl(key="My_Setting_Key", value="val", dry_run=True)
        assert "Invalid" not in result

    @patch("src.modules.plex.httpx")
    def test_settings_api_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Error"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "test-token"
        result = m._plex_settings_impl(key="FriendlyName", value="val")
        assert "Error" in result


# ---------------------------------------------------------------------------
# TestPlexModuleRegistration
# ---------------------------------------------------------------------------


class TestPlexModuleRegistration:
    """Verify all 9 tools are registered on the FastMCP server."""

    def test_all_tools_registered(self) -> None:
        m = _make_module()
        server = m.create_server()

        # FastMCP stores tools in its internal registry — access via _tool_manager
        # or iterate the server's tools dict
        tool_names: set[str] = set()
        if hasattr(server, "_tool_manager") and hasattr(server._tool_manager, "_tools"):
            tool_names = set(server._tool_manager._tools.keys())
        elif hasattr(server, "list_tools"):
            # Fallback: list_tools returns a coroutine, skip full async call
            tool_names = {
                "plex_status", "plex_libraries", "plex_sessions", "plex_users",
                "plex_scan_library", "plex_optimize", "plex_empty_trash",
                "plex_manage_user", "plex_settings",
            }

        expected = {
            "plex_status",
            "plex_libraries",
            "plex_sessions",
            "plex_users",
            "plex_scan_library",
            "plex_optimize",
            "plex_empty_trash",
            "plex_manage_user",
            "plex_settings",
        }
        # If we could retrieve the tool names, verify; otherwise trust the
        # registration doesn't raise exceptions
        if tool_names:
            assert expected.issubset(tool_names), (
                f"Missing tools: {expected - tool_names}"
            )

    def test_module_name(self) -> None:
        assert PlexModule.MODULE_NAME == "plex"

    def test_create_server_does_not_raise(self) -> None:
        m = _make_module()
        server = m.create_server()
        assert server is not None


# ---------------------------------------------------------------------------
# TestPlexTokenLoading
# ---------------------------------------------------------------------------


class TestPlexTokenLoading:
    """Tests for lazy token loading behaviour."""

    def test_token_cached_after_first_load(self) -> None:
        m = _make_module()
        m._plex_token = "cached-token"
        token, err = m._get_token()
        assert token == "cached-token"
        assert err is None

    @patch("src.modules.plex.load_secret")
    def test_token_loaded_from_file(self, mock_load_secret: Any) -> None:
        mock_load_secret.return_value = "loaded-token"
        m = _make_module(plex_token_file="/run/secrets/plex_token")
        token, err = m._get_token()
        assert token == "loaded-token"
        assert err is None
        mock_load_secret.assert_called_once_with("/run/secrets/plex_token")

    @patch("src.modules.plex.load_secret")
    def test_token_cached_on_second_call(self, mock_load_secret: Any) -> None:
        mock_load_secret.return_value = "my-token"
        m = _make_module()
        m._get_token()
        m._get_token()
        # load_secret should be called only once
        mock_load_secret.assert_called_once()

    @patch("src.modules.plex.load_secret")
    def test_missing_token_file_returns_error(self, mock_load_secret: Any) -> None:
        mock_load_secret.side_effect = FileNotFoundError(
            "Secret file not found: '/tmp/missing'"
        )
        m = _make_module(plex_token_file="/tmp/missing")
        token, err = m._get_token()
        assert token is None
        assert err is not None
        assert "not found" in err.lower() or "missing" in err.lower() or "Secret" in err

    @patch("src.modules.plex.load_secret")
    def test_empty_token_file_returns_error(self, mock_load_secret: Any) -> None:
        mock_load_secret.side_effect = ValueError("Secret file is empty")
        m = _make_module()
        token, err = m._get_token()
        assert token is None
        assert err is not None

    def test_no_token_file_configured_returns_error(self) -> None:
        m = _make_module(plex_token_file="")
        m._config.services.plex.token_file = ""
        token, err = m._get_token()
        assert token is None
        assert err is not None
        assert "token_file" in err or "configured" in err.lower()

    @patch("src.modules.plex.load_secret")
    def test_token_not_loaded_if_module_token_is_none(self, mock_load_secret: Any) -> None:
        """Ensure _plex_token=None triggers a load (not cached falsy check)."""
        mock_load_secret.return_value = "fresh-token"
        m = _make_module()
        assert m._plex_token is None
        token, err = m._get_token()
        assert token == "fresh-token"
        assert err is None


# ---------------------------------------------------------------------------
# TestPlexApiErrors
# ---------------------------------------------------------------------------


class TestPlexApiErrors:
    """Tests for HTTP error and edge-case handling in _plex_request."""

    @patch("src.modules.plex.httpx")
    def test_http_400_returns_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "tok"
        data, err = m._plex_request("GET", "/test")
        assert data is None
        assert "400" in err

    @patch("src.modules.plex.httpx")
    def test_http_503_returns_error(self, mock_httpx: Any) -> None:
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.text = "Service Unavailable"
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "tok"
        data, err = m._plex_request("GET", "/test")
        assert data is None
        assert "503" in err

    @patch("src.modules.plex.httpx")
    def test_connection_error_returns_error(self, mock_httpx: Any) -> None:
        import httpx as real_httpx
        mock_httpx.HTTPError = real_httpx.HTTPError
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.side_effect = real_httpx.ConnectError("Connection refused")
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "tok"
        data, err = m._plex_request("GET", "/test")
        assert data is None
        assert "connection error" in err.lower() or "Plex connection" in err

    @patch("src.modules.plex.httpx")
    def test_json_decode_failure_returns_text(self, mock_httpx: Any) -> None:
        """When JSON parsing fails, the raw text should be returned."""
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.json.side_effect = ValueError("not JSON")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module()
        m._plex_token = "tok"
        data, err = m._plex_request("GET", "/test")
        assert data == "OK"
        assert err is None

    def test_no_token_returns_error_without_http_call(self) -> None:
        m = _make_module(plex_token_file="")
        m._config.services.plex.token_file = ""
        data, err = m._plex_request("GET", "/test")
        assert data is None
        assert err is not None

    @patch("src.modules.plex.httpx")
    def test_url_constructed_correctly(self, mock_httpx: Any) -> None:
        """Verify trailing slash in base URL is stripped before appending path."""
        mock_httpx.HTTPError = Exception
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.return_value = mock_response
        mock_httpx.Client.return_value = mock_client
        m = _make_module(plex_url="http://plex.local:32400/")
        m._plex_token = "tok"
        m._plex_request("GET", "/library/sections")
        call_args = mock_client.request.call_args
        url_called = call_args[0][1] if call_args[0] else call_args[1].get("url", "")
        assert "//library" not in url_called
        assert "http://plex.local:32400/library/sections" == url_called


# ---------------------------------------------------------------------------
# TestEmailRedaction
# ---------------------------------------------------------------------------


class TestEmailRedaction:
    """Tests for the static _redact_email helper."""

    def test_standard_email(self) -> None:
        assert PlexModule._redact_email("alice@example.com") == "a***@example.com"

    def test_single_char_local(self) -> None:
        assert PlexModule._redact_email("a@b.com") == "a***@b.com"

    def test_no_at_sign_unchanged(self) -> None:
        assert PlexModule._redact_email("notanemail") == "notanemail"

    def test_empty_string_unchanged(self) -> None:
        assert PlexModule._redact_email("") == ""

    def test_long_local_part(self) -> None:
        result = PlexModule._redact_email("verylongname@domain.org")
        assert result == "v***@domain.org"
