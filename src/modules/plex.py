"""Plex Media Server management module for claude-home-server.

Provides 9 MCP tools split across three risk tiers:

**Read tools** (safe, non-mutating):
* ``plex_status`` — server identity, version, platform, active streams.
* ``plex_libraries`` — list all media libraries.
* ``plex_sessions`` — active playback sessions.
* ``plex_users`` — managed and shared users.

**Moderate tools** (state-changing but reversible):
* ``plex_scan_library`` — trigger an async library scan.
* ``plex_optimize`` — trigger library optimisation.
* ``plex_empty_trash`` — empty a library's trash.

**Elevated tools** (high-impact):
* ``plex_manage_user`` — modify permissions for a managed/shared user.
* ``plex_settings`` — update a Plex server preference.

Security notes
--------------
* The Plex authentication token is read from a file path configured in
  ``config.services.plex.token_file`` and is never included in any output.
* All HTTP communication goes through ``httpx``.
* Every tool validates its inputs via the Pydantic models defined in
  :mod:`src.safety.input_sanitizer`.
* Responses from Plex are nested under the ``"MediaContainer"`` key; the
  module unwraps that before presenting data.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pydantic

from src.config import load_secret
from src.modules.base import BaseModule
from src.safety.input_sanitizer import (
    PlexLibraryInput,
    PlexSettingsInput,
    PlexUserManageInput,
)


class PlexModule(BaseModule):
    """Plex Media Server management module.

    All tools check ``config.services.plex.enabled`` before executing.
    The Plex token is loaded lazily from the file path given in
    ``config.services.plex.token_file`` on first use and cached for the
    lifetime of the module instance.

    Registered tools:
    * ``plex_status``
    * ``plex_libraries``
    * ``plex_sessions``
    * ``plex_users``
    * ``plex_scan_library``
    * ``plex_optimize``
    * ``plex_empty_trash``
    * ``plex_manage_user``
    * ``plex_settings``
    """

    MODULE_NAME = "plex"

    def __init__(
        self,
        config: Any,
        permission_engine: Any,
        audit_logger: Any,
        circuit_breaker: Any = None,
    ) -> None:
        super().__init__(config, permission_engine, audit_logger, circuit_breaker)
        self._plex_token: str | None = None  # Lazy-loaded on first use

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def _register_tools(self) -> None:
        """Register all 9 Plex tools on the module's FastMCP server."""
        # Read tools
        self._register_tool(
            "plex_status",
            self._plex_status_impl,
            (
                "Query Plex Media Server status and identity. "
                "Returns server name, version, platform, and active stream count. "
                "No parameters required."
            ),
        )
        self._register_tool(
            "plex_libraries",
            self._plex_libraries_impl,
            (
                "List all Plex media libraries. "
                "Returns library title, type, key, agent, scanner, language, and item count. "
                "No parameters required."
            ),
        )
        self._register_tool(
            "plex_sessions",
            self._plex_sessions_impl,
            (
                "List active Plex playback sessions. "
                "Returns per-session: user, title, player, state, and progress. "
                "Returns a message when no sessions are active. "
                "No parameters required."
            ),
        )
        self._register_tool(
            "plex_users",
            self._plex_users_impl,
            (
                "List Plex managed and shared users. "
                "Returns per-user: id, name, email (partially redacted), and restricted status. "
                "No parameters required."
            ),
        )

        # Moderate tools
        self._register_tool(
            "plex_scan_library",
            self._plex_scan_library_impl,
            (
                "Trigger an asynchronous scan of a Plex library. "
                "library_id: numeric library section ID (e.g. '1'). "
                "The scan runs in the background; returns a confirmation immediately."
            ),
        )
        self._register_tool(
            "plex_optimize",
            self._plex_optimize_impl,
            (
                "Trigger optimisation (bundle generation) for a Plex library. "
                "library_id: numeric library section ID. "
                "Optimisation runs in the background; returns a confirmation immediately."
            ),
        )
        self._register_tool(
            "plex_empty_trash",
            self._plex_empty_trash_impl,
            (
                "Empty the trash for a Plex library. "
                "library_id: numeric library section ID. "
                "Removes items previously marked for deletion. "
                "Returns a confirmation immediately."
            ),
        )

        # Elevated tools
        self._register_tool(
            "plex_manage_user",
            self._plex_manage_user_impl,
            (
                "Modify permissions for a Plex managed or shared user. "
                "user_id: Plex user ID (alphanumeric). "
                "permissions: dict of permission keys and values to apply. "
                "dry_run: if true, show what would change without making any API call. "
                "ELEVATED: modifies user access control settings."
            ),
        )
        self._register_tool(
            "plex_settings",
            self._plex_settings_impl,
            (
                "Update a Plex server preference. "
                "key: preference name (alphanumeric + underscore, must start with a letter). "
                "value: new value for the preference. "
                "dry_run: if true, show the current value and what would change without updating. "
                "ELEVATED: modifies server-wide configuration."
            ),
        )

    # ------------------------------------------------------------------
    # Read tools
    # ------------------------------------------------------------------

    def _plex_status_impl(self) -> str:
        """Return a formatted status report for the Plex server.

        Queries the root endpoint (``/``) which returns the server identity
        block wrapped in ``MediaContainer``.

        Returns:
            Formatted plain-text status report.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        data, err = self._plex_request("GET", "/")
        if err:
            return f"Error querying Plex status: {err}"

        container = self._unwrap_media_container(data)
        parts = ["=== Plex Status ==="]

        if not isinstance(container, dict):
            parts.append(f"Unexpected response format:\n{json.dumps(data, indent=2, default=str)}")
            return "\n".join(parts)

        name = container.get("friendlyName", "unknown")
        version = container.get("version", "unknown")
        platform = container.get("platform", "unknown")
        signin_state = container.get("myPlexSigninState", "unknown")

        # Active streams can be found in the root container as well
        active_sessions = container.get("transcoderActiveVideoSessions", 0)

        parts.append(f"Name:         {name}")
        parts.append(f"Version:      {version}")
        parts.append(f"Platform:     {platform}")
        parts.append(f"MyPlex State: {signin_state}")
        parts.append(f"Active Transcoder Sessions: {active_sessions}")

        return "\n".join(parts)

    def _plex_libraries_impl(self) -> str:
        """Return a formatted list of all Plex media libraries.

        Queries ``/library/sections`` and renders each library's title, type,
        section key, agent, scanner, language, and item count.

        Returns:
            Formatted plain-text library listing.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        data, err = self._plex_request("GET", "/library/sections")
        if err:
            return f"Error querying Plex libraries: {err}"

        container = self._unwrap_media_container(data)
        parts = ["=== Plex Libraries ==="]

        if not isinstance(container, dict):
            parts.append(f"Unexpected response format:\n{json.dumps(data, indent=2, default=str)}")
            return "\n".join(parts)

        directories = container.get("Directory", [])
        if not directories:
            parts.append("No libraries found.")
            return "\n".join(parts)

        if not isinstance(directories, list):
            directories = [directories]

        parts.append(
            f"{'Key':<6} {'Type':<12} {'Language':<10} {'Items':<8} Title"
        )
        parts.append("-" * 70)

        for lib in directories:
            if not isinstance(lib, dict):
                continue
            key = str(lib.get("key", "?"))
            lib_type = str(lib.get("type", "?"))
            language = str(lib.get("language", "?"))
            count = str(lib.get("count", "?"))
            title = str(lib.get("title", "?"))
            parts.append(f"{key:<6} {lib_type:<12} {language:<10} {count:<8} {title}")

            agent = lib.get("agent", "")
            scanner = lib.get("scanner", "")
            if agent or scanner:
                parts.append(f"       Agent: {agent}  Scanner: {scanner}")

        return "\n".join(parts)

    def _plex_sessions_impl(self) -> str:
        """Return a formatted list of active Plex playback sessions.

        Queries ``/status/sessions`` and renders each session's user, media
        title, player, playback state, and progress.

        Returns:
            Formatted plain-text session listing, or a message when idle.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        data, err = self._plex_request("GET", "/status/sessions")
        if err:
            return f"Error querying Plex sessions: {err}"

        container = self._unwrap_media_container(data)
        parts = ["=== Plex Active Sessions ==="]

        if not isinstance(container, dict):
            parts.append(f"Unexpected response format:\n{json.dumps(data, indent=2, default=str)}")
            return "\n".join(parts)

        total = container.get("size", 0)
        if total == 0:
            parts.append("No active playback sessions.")
            return "\n".join(parts)

        metadata_list = container.get("Metadata", [])
        if not isinstance(metadata_list, list):
            metadata_list = [metadata_list]

        for i, session in enumerate(metadata_list, start=1):
            if not isinstance(session, dict):
                continue

            title = session.get("title", "Unknown")
            grandparent_title = session.get("grandparentTitle", "")
            full_title = f"{grandparent_title} — {title}" if grandparent_title else title

            # User info is nested under User key
            user_info = session.get("User", {})
            user = user_info.get("title", "Unknown") if isinstance(user_info, dict) else "Unknown"

            # Player info nested under Player key
            player_info = session.get("Player", {})
            if isinstance(player_info, dict):
                player = player_info.get("title", "Unknown")
                state = player_info.get("state", "unknown")
            else:
                player = "Unknown"
                state = "unknown"

            # Progress calculation
            view_offset = session.get("viewOffset", 0)
            duration = session.get("duration", 0)
            if duration and duration > 0:
                progress_pct = round((view_offset / duration) * 100, 1)
                progress_str = f"{progress_pct}%"
            else:
                progress_str = "N/A"

            parts.append(f"\n[Session {i}]")
            parts.append(f"  User:     {user}")
            parts.append(f"  Title:    {full_title}")
            parts.append(f"  Player:   {player}")
            parts.append(f"  State:    {state}")
            parts.append(f"  Progress: {progress_str}")

        return "\n".join(parts)

    def _plex_users_impl(self) -> str:
        """Return a formatted list of Plex managed and shared users.

        Queries ``/accounts`` and renders each user's id, name, redacted
        email, and restricted status.

        Returns:
            Formatted plain-text user listing.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        data, err = self._plex_request("GET", "/accounts")
        if err:
            return f"Error querying Plex users: {err}"

        container = self._unwrap_media_container(data)
        parts = ["=== Plex Users ==="]

        if not isinstance(container, dict):
            parts.append(f"Unexpected response format:\n{json.dumps(data, indent=2, default=str)}")
            return "\n".join(parts)

        accounts = container.get("Account", [])
        if not accounts:
            parts.append("No user accounts found.")
            return "\n".join(parts)

        if not isinstance(accounts, list):
            accounts = [accounts]

        parts.append(f"{'ID':<10} {'Restricted':<12} {'Name':<24} Email")
        parts.append("-" * 70)

        for acct in accounts:
            if not isinstance(acct, dict):
                continue
            user_id = str(acct.get("id", "?"))
            name = str(acct.get("name", "?"))
            email = self._redact_email(str(acct.get("email", "")))
            restricted = "yes" if acct.get("restricted") else "no"
            parts.append(f"{user_id:<10} {restricted:<12} {name:<24} {email}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Moderate tools
    # ------------------------------------------------------------------

    def _plex_scan_library_impl(self, library_id: str) -> str:
        """Trigger an asynchronous scan of a Plex library section.

        Args:
            library_id: Numeric library section ID string.

        Returns:
            Confirmation message or error string.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        try:
            params = PlexLibraryInput(library_id=library_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        _, err = self._plex_request("GET", f"/library/sections/{params.library_id}/refresh")
        if err:
            return f"Error triggering library scan: {err}"

        return (
            f"=== Plex Scan Library ===\n"
            f"Library scan triggered for section {params.library_id}.\n"
            f"The scan runs asynchronously in the background."
        )

    def _plex_optimize_impl(self, library_id: str) -> str:
        """Trigger optimisation (bundle generation) for a Plex library.

        Args:
            library_id: Numeric library section ID string.

        Returns:
            Confirmation message or error string.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        try:
            params = PlexLibraryInput(library_id=library_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        _, err = self._plex_request("PUT", f"/library/sections/{params.library_id}/optimize")
        if err:
            return f"Error triggering library optimisation: {err}"

        return (
            f"=== Plex Optimize Library ===\n"
            f"Optimisation triggered for section {params.library_id}.\n"
            f"The optimisation runs asynchronously in the background."
        )

    def _plex_empty_trash_impl(self, library_id: str) -> str:
        """Empty the trash for a Plex library section.

        Args:
            library_id: Numeric library section ID string.

        Returns:
            Confirmation message or error string.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        try:
            params = PlexLibraryInput(library_id=library_id)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        _, err = self._plex_request("PUT", f"/library/sections/{params.library_id}/emptyTrash")
        if err:
            return f"Error emptying library trash: {err}"

        return (
            f"=== Plex Empty Trash ===\n"
            f"Trash emptied for section {params.library_id}."
        )

    # ------------------------------------------------------------------
    # Elevated tools
    # ------------------------------------------------------------------

    def _plex_manage_user_impl(
        self,
        user_id: str,
        permissions: dict[str, object] | None = None,
        dry_run: bool = False,
    ) -> str:
        """Modify permissions for a Plex managed or shared user.

        Args:
            user_id: Plex user ID (alphanumeric).
            permissions: Dict of permission keys and values to apply.
            dry_run: When True, show what would change without making any
                API call.

        Returns:
            Result message, dry-run description, or error string.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        if permissions is None:
            permissions = {}

        try:
            params = PlexUserManageInput(
                user_id=user_id,
                permissions=permissions,
                dry_run=dry_run,
            )
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        if params.dry_run:
            perm_summary = (
                json.dumps(params.permissions, indent=2)
                if params.permissions
                else "(no permissions specified)"
            )
            return (
                f"=== Plex Manage User (Dry Run): {params.user_id} ===\n"
                f"Would send PUT /accounts/{params.user_id} with:\n"
                f"{perm_summary}\n"
                f"No changes have been made."
            )

        _, err = self._plex_request(
            "PUT",
            f"/accounts/{params.user_id}",
            json_data=params.permissions if params.permissions else None,
        )
        if err:
            return f"Error updating user permissions: {err}"

        perm_summary = (
            json.dumps(params.permissions, indent=2)
            if params.permissions
            else "(no permissions specified)"
        )
        return (
            f"=== Plex Manage User: {params.user_id} ===\n"
            f"Permissions updated successfully.\n"
            f"Applied:\n{perm_summary}"
        )

    def _plex_settings_impl(
        self,
        key: str,
        value: str,
        dry_run: bool = False,
    ) -> str:
        """Update a Plex server preference.

        In dry-run mode, retrieves the current value of the preference from
        ``/:/prefs`` and shows the proposed change without applying it.

        Args:
            key: Preference name (alphanumeric + underscore, letter-start).
            value: New value for the preference.
            dry_run: When True, show current and proposed value without
                updating.

        Returns:
            Result message, dry-run description, or error string.
        """
        if not self._config.services.plex.enabled:
            return "Plex is not enabled in the server configuration."

        try:
            params = PlexSettingsInput(key=key, value=value, dry_run=dry_run)
        except pydantic.ValidationError as exc:
            return f"Invalid parameters: {exc}"

        if params.dry_run:
            # Fetch current preferences for comparison
            current_value = "unknown"
            prefs_data, prefs_err = self._plex_request("GET", "/:/prefs")
            if not prefs_err and isinstance(prefs_data, dict):
                prefs_container = self._unwrap_media_container(prefs_data)
                if isinstance(prefs_container, dict):
                    settings_list = prefs_container.get("Setting", [])
                    if not isinstance(settings_list, list):
                        settings_list = [settings_list]
                    for setting in settings_list:
                        if isinstance(setting, dict) and setting.get("id") == params.key:
                            current_value = str(setting.get("value", "unknown"))
                            break

            return (
                f"=== Plex Settings (Dry Run): {params.key} ===\n"
                f"Current value: {current_value}\n"
                f"Proposed value: {params.value}\n"
                f"Would send PUT /:/prefs?{params.key}={params.value}\n"
                f"No changes have been made."
            )

        _, err = self._plex_request("PUT", "/:/prefs", params={params.key: params.value})
        if err:
            return f"Error updating Plex setting: {err}"

        return (
            f"=== Plex Settings: {params.key} ===\n"
            f"Setting '{params.key}' updated to '{params.value}'."
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self) -> tuple[str | None, str | None]:
        """Lazy-load and cache the Plex authentication token.

        Reads the token from the file path configured in
        ``config.services.plex.token_file`` on first call and caches it for
        subsequent calls.

        Returns:
            A 2-tuple of ``(token, error)``.  On success ``error`` is ``None``.
            On failure ``token`` is ``None`` and ``error`` describes the
            problem.
        """
        if self._plex_token is not None:
            return self._plex_token, None

        token_file = self._config.services.plex.token_file
        if not token_file:
            return None, "No token_file configured for Plex"

        try:
            self._plex_token = load_secret(token_file)
            return self._plex_token, None
        except (FileNotFoundError, ValueError) as exc:
            return None, str(exc)

    def _plex_request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
        timeout: int | None = None,
    ) -> tuple[dict[str, Any] | list[Any] | str | None, str | None]:
        """Make an authenticated HTTP request to the Plex API.

        Adds the ``X-Plex-Token`` and ``Accept: application/json`` headers
        automatically.  The token is loaded lazily via :meth:`_get_token`.

        Args:
            method: HTTP method (``"GET"``, ``"PUT"``, etc.).
            path: API path, e.g. ``"/library/sections"``.
            params: Optional query-string parameters dict.
            json_data: Optional JSON body.
            timeout: Override the configured timeout in seconds.

        Returns:
            A 2-tuple of ``(data, error)``.  On success ``error`` is ``None``
            and ``data`` is the parsed JSON response (or raw text if JSON
            parsing fails).  On failure ``data`` is ``None`` and ``error``
            contains a human-readable description.
        """
        token, err = self._get_token()
        if err:
            return None, err

        url = self._config.services.plex.url.rstrip("/") + path
        t = timeout or self._config.http.timeout_seconds

        try:
            with httpx.Client(timeout=t) as client:
                headers = {
                    "X-Plex-Token": token,
                    "Accept": "application/json",
                }
                resp = client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_data,
                )
                if resp.status_code >= 400:
                    return None, (
                        f"Plex API error: HTTP {resp.status_code} — {resp.text[:500]}"
                    )
                try:
                    return resp.json(), None
                except Exception:  # noqa: BLE001
                    return resp.text, None
        except httpx.HTTPError as exc:
            return None, f"Plex connection error: {exc}"

    def _unwrap_media_container(self, data: Any) -> Any:
        """Unwrap the Plex ``MediaContainer`` envelope if present.

        Plex API responses are typically structured as::

            {"MediaContainer": { ... actual data ... }}

        This helper returns the inner dict when the envelope is present, or
        ``data`` unchanged when it is not.

        Args:
            data: Parsed JSON response from the Plex API.

        Returns:
            The ``MediaContainer`` contents, or the original ``data``.
        """
        if isinstance(data, dict) and "MediaContainer" in data:
            return data["MediaContainer"]
        return data

    @staticmethod
    def _redact_email(email: str) -> str:
        """Partially redact an email address for safe display.

        Preserves the first character of the local part, the domain, and
        replaces the rest of the local part with ``***``.  For example,
        ``alice@example.com`` becomes ``a***@example.com``.

        Args:
            email: Email address string.

        Returns:
            Partially redacted email, or the original string if it does not
            look like a valid email address.
        """
        if not email or "@" not in email:
            return email
        local, _, domain = email.partition("@")
        if not local:
            return email
        redacted_local = local[0] + "***"
        return f"{redacted_local}@{domain}"
