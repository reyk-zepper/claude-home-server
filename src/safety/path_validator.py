"""Path validation security component for claude-home-server.

This module is the filesystem security boundary. ALL file access must pass
through PathValidator before any I/O occurs. It resolves symlinks, checks
hardcoded denylists, pattern-blocks sensitive file types, and enforces an
explicit allowlist with default-deny semantics.

CRITICAL: Never bypass this module. Never add config overrides that can
          change the hardcoded blocklist.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Hardcoded blocklist — NOT overridable via config, enforced before allowlist
# ---------------------------------------------------------------------------

HARDCODED_BLOCKLIST: list[str] = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/root",
    "/proc",
    "/sys",
    "/dev",
]

# Patterns matched against the basename and full resolved path.
# fnmatch semantics (glob-style, case-sensitive).
HARDCODED_BLOCKED_PATTERNS: list[str] = [
    "*.pem",
    "*.key",
    "*id_rsa*",
    "*id_ed25519*",
    "*id_ecdsa*",
    "*id_dsa*",
    ".env",
    "*.env",
    ".env.*",
]

# Every component of the resolved path is checked against these segments.
# A file *anywhere* under a directory named ".ssh" or "secrets" is denied.
HARDCODED_BLOCKED_PATH_SEGMENTS: list[str] = [
    ".ssh",
    "secrets",
]

# OS limit for path length (POSIX PATH_MAX = 4096)
_MAX_PATH_CHARS = 4096


class PathValidationError(Exception):
    """Raised when path validation fails.

    The message is intentionally vague to avoid leaking filesystem layout
    information to callers that might forward it to untrusted consumers.
    """


class PathValidator:
    """Validates filesystem paths against an allowlist/blocklist policy.

    Security model (checked in this priority order):
      1. Input sanity (null bytes, empty string, excessive length)
      2. Hardcoded blocklist  — always wins, not configurable
      3. Hardcoded file-name patterns (*.pem, *.key, .env, …)
      4. Hardcoded path-segment rules (.ssh, secrets)
      5. User-supplied extra blocklist
      6. User-supplied allowlist
      7. Default: DENY

    All path resolution uses ``os.path.realpath()`` so symlinks, ``..``
    components, and double-slashes are collapsed before any comparison.

    Args:
        allowed_paths: Directories (or files) that are explicitly permitted.
            Paths are realpath-resolved at construction time.
        blocked_paths: Optional extra directories/files to deny in addition
            to the hardcoded blocklist. Also resolved at construction time.
    """

    def __init__(
        self,
        allowed_paths: list[str],
        blocked_paths: list[str] | None = None,
    ) -> None:
        self._allowed: list[str] = [os.path.realpath(p) for p in allowed_paths]
        self._blocked: list[str] = [os.path.realpath(p) for p in (blocked_paths or [])]

        # Pre-resolve the hardcoded blocklist once so we don't redo it on
        # every call. Note: on a real Ubuntu server these paths exist, but we
        # fall back to the literal string when they don't (e.g., in tests).
        self._hardcoded_resolved: list[str] = [
            os.path.realpath(p) for p in HARDCODED_BLOCKLIST
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, path: str) -> bool:
        """Return True only when the path passes every security check.

        Args:
            path: Absolute or relative path to validate.

        Returns:
            True if the path is within an allowed location and not blocked.
            False in all other cases — including on any validation error.
        """
        return self._validate(path) is not None

    def validate_or_raise(self, path: str) -> str:
        """Validate path and return the resolved real path.

        The resolved path is obtained from a single ``realpath()`` call —
        the same value that was checked.  This avoids a TOCTOU window that
        would exist if ``realpath()`` were called a second time after
        validation.

        Args:
            path: Path to validate.

        Returns:
            The ``os.path.realpath``-resolved version of *path*.

        Raises:
            PathValidationError: If the path is not allowed for any reason.
        """
        real = self._validate(path)
        if real is None:
            # Deliberately keep the error message generic — we must not reveal
            # *why* exactly the path was rejected (blocklist membership, etc.).
            raise PathValidationError(f"Access denied: {path!r}")
        return real

    def _validate(self, path: str) -> str | None:
        """Core validation logic — returns the resolved path or ``None``.

        Resolves the path exactly once via ``_safe_realpath`` and runs all
        checks against that single resolved value.

        Args:
            path: Raw path string to validate.

        Returns:
            The resolved real path if all checks pass, ``None`` otherwise.
        """
        try:
            real = self._safe_realpath(path)
        except PathValidationError:
            return None

        # Priority 1 — hardcoded blocklist
        if self._is_hardcoded_blocked(real):
            return None

        # Priority 2 — hardcoded filename/extension patterns
        if self._matches_blocked_pattern(real):
            return None

        # Priority 3 — hardcoded path segment rules
        if self._has_blocked_segment(real):
            return None

        # Priority 4 — user-supplied extra blocklist
        if self._is_user_blocked(real):
            return None

        # Priority 5 — user allowlist; default deny if not found
        if not self._is_user_allowed(real):
            return None

        return real

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safe_realpath(self, path: str) -> str:
        """Resolve path to its real absolute path with pre-flight sanity checks.

        Args:
            path: Input path string.

        Returns:
            Resolved real path string.

        Raises:
            PathValidationError: If the path fails any sanity check.
        """
        if not path:
            raise PathValidationError("Path must not be empty")

        if "\x00" in path:
            raise PathValidationError("Path must not contain null bytes")

        if len(path) > _MAX_PATH_CHARS:
            raise PathValidationError(
                f"Path exceeds maximum length of {_MAX_PATH_CHARS} characters"
            )

        return os.path.realpath(path)

    def _is_hardcoded_blocked(self, real_path: str) -> bool:
        """Check whether *real_path* is under a hardcoded-blocked location.

        Args:
            real_path: Already-resolved absolute path.

        Returns:
            True if the path is blocked by the hardcoded list.
        """
        for blocked in self._hardcoded_resolved:
            # Exact match OR the path is a descendant of the blocked prefix.
            # We append os.sep to the prefix so "/proc" doesn't accidentally
            # block "/proc_data".
            if real_path == blocked or real_path.startswith(blocked + os.sep):
                return True
        return False

    def _matches_blocked_pattern(self, real_path: str) -> bool:
        """Check if the basename matches any blocked filename pattern.

        Patterns are matched against the basename only. ``fnmatch`` patterns
        like ``*.pem`` do not cross ``/`` boundaries, so matching against the
        full absolute path would be ineffective (and was removed as dead code).

        Args:
            real_path: Already-resolved absolute path.

        Returns:
            True if the basename matches a blocked pattern.
        """
        basename = os.path.basename(real_path)
        for pattern in HARDCODED_BLOCKED_PATTERNS:
            if fnmatch.fnmatch(basename, pattern):
                return True
        return False

    def _has_blocked_segment(self, real_path: str) -> bool:
        """Check whether any component of *real_path* is a blocked segment.

        Splits on ``os.sep`` and checks each non-empty part individually.
        This blocks paths like ``/home/user/.ssh/config`` because ``.ssh``
        appears as a path component.

        Args:
            real_path: Already-resolved absolute path.

        Returns:
            True if the path contains a blocked segment.
        """
        parts = [p for p in real_path.split(os.sep) if p]
        for segment in HARDCODED_BLOCKED_PATH_SEGMENTS:
            if segment in parts:
                return True
        return False

    def _is_user_blocked(self, real_path: str) -> bool:
        """Check against the user-supplied extra blocklist.

        Args:
            real_path: Already-resolved absolute path.

        Returns:
            True if the path is covered by the user blocklist.
        """
        for blocked in self._blocked:
            if real_path == blocked or real_path.startswith(blocked + os.sep):
                return True
        return False

    def _is_user_allowed(self, real_path: str) -> bool:
        """Check whether *real_path* falls within any allowed location.

        Args:
            real_path: Already-resolved absolute path.

        Returns:
            True only if the path is explicitly covered by the allowlist.
        """
        for allowed in self._allowed:
            if real_path == allowed or real_path.startswith(allowed + os.sep):
                return True
        return False
