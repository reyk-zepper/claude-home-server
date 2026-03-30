"""Structured, append-only audit logger for all tool invocations.

Each log entry is a JSON object written to a dedicated audit file.  The logger
uses a *bound* structlog instance so global structlog configuration is never
touched — existing logging pipelines in the process remain unaffected.

Design decisions
----------------
* No global structlog.configure() call — uses a private ``BoundLogger`` chain.
* Falls back to ``sys.stderr`` when the target log directory is not writable,
  so the server can still start in restricted environments.
* Sensitive parameter keys (tokens, passwords, file contents) are redacted
  before being written to disk.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Any, TextIO

import structlog
import structlog.dev
import structlog.processors
import structlog.stdlib

from src.permissions import RiskLevel

# Keys whose values are replaced with a sentinel before logging
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {"content", "token", "password", "secret", "api_key", "auth", "authorization"}
)
_MAX_PARAM_VALUE_LEN = 500
_REDACTED = "***REDACTED***"


def _open_log_file(log_path: Path) -> TextIO:
    """Open *log_path* in append mode, creating parent directories as needed.

    Falls back to ``sys.stderr`` when the directory cannot be created or the
    file cannot be opened (e.g. permission denied in non-root environments).

    Args:
        log_path: Absolute path to the desired audit log file.

    Returns:
        An open, writable ``TextIO`` stream.
    """
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        return log_path.open("a", encoding="utf-8", buffering=1)  # line-buffered
    except OSError:
        # Log the problem to stderr so operators can see it, then continue
        traceback.print_exc(file=sys.stderr)
        print(
            f"[audit] WARNING: cannot open {log_path} — falling back to stderr",
            file=sys.stderr,
        )
        return sys.stderr


def _build_processor_chain() -> list[Any]:
    """Return a structlog processor chain that emits ISO-timestamped JSON.

    Returns:
        List of structlog processor callables.
    """
    return [
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.JSONRenderer(),
    ]


class AuditLogger:
    """Append-only structured audit logger for all MCP tool invocations.

    Uses a *private* structlog ``PrintLogger`` so it never touches global
    structlog configuration.  Each ``AuditLogger`` instance writes to its own
    file handle.

    Args:
        log_path: Path to the audit log file.  Defaults to the standard
            production path.  Accepts ``str`` or ``pathlib.Path``.

    Example::

        logger = AuditLogger("/tmp/test-audit.log")
        logger.log_startup()
        logger.log_tool_call(
            tool="docker_restart",
            risk_level=RiskLevel.MODERATE,
            parameters={"container": "homeassistant"},
            result_status="success",
            duration_ms=142.7,
        )
    """

    def __init__(
        self,
        log_path: str | Path = "/var/log/claude-home-server/audit.log",
    ) -> None:
        self._log_path = Path(log_path)
        self._file: TextIO = _open_log_file(self._log_path)
        # Build a completely isolated structlog pipeline
        self._logger: structlog.BoundLogger = structlog.wrap_logger(
            structlog.PrintLogger(file=self._file),
            processors=_build_processor_chain(),
            wrapper_class=structlog.BoundLogger,
            context_class=dict,
        )

    # ------------------------------------------------------------------
    # Public logging API
    # ------------------------------------------------------------------

    def log_tool_call(
        self,
        tool: str,
        risk_level: RiskLevel,
        parameters: dict[str, Any],
        result_status: str,
        duration_ms: float,
        error_message: str | None = None,
    ) -> None:
        """Log a single tool invocation to the audit log.

        Sensitive parameter values are redacted and long string values are
        truncated before the record is written.

        Args:
            tool: Tool name (e.g. ``"docker_restart"``).
            risk_level: The effective ``RiskLevel`` at call time.
            parameters: Raw tool parameters dict from the MCP caller.
            result_status: One of ``"success"``, ``"error"``, ``"denied"``,
                or ``"dry_run"``.
            duration_ms: Wall-clock execution time in milliseconds.
            error_message: Optional error description when *result_status* is
                ``"error"`` or ``"denied"``.
        """
        safe_params = self._sanitize_params(parameters)
        self._logger.info(
            "tool_call",
            tool=tool,
            risk_level=risk_level.value,
            parameters=safe_params,
            result_status=result_status,
            duration_ms=round(duration_ms, 2),
            error=error_message,
        )

    def log_startup(self) -> None:
        """Emit a server-startup audit event."""
        self._logger.info("server_startup")

    def log_shutdown(self) -> None:
        """Emit a server-shutdown audit event."""
        self._logger.info("server_shutdown")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sanitize_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *params* with sensitive values redacted.

        Rules applied (in order):
        1. Keys whose lowercase form appears in ``_SENSITIVE_KEYS`` → ``"***REDACTED***"``.
        2. String values longer than ``_MAX_PARAM_VALUE_LEN`` characters are
           truncated with a ``"...[truncated]"`` suffix.
        3. All other values are passed through unchanged.

        Args:
            params: Raw parameter mapping from the tool caller.

        Returns:
            A new dict safe for inclusion in audit records.
        """
        sanitized: dict[str, Any] = {}
        for key, value in params.items():
            if key.lower() in _SENSITIVE_KEYS:
                sanitized[key] = _REDACTED
            elif isinstance(value, str) and len(value) > _MAX_PARAM_VALUE_LEN:
                sanitized[key] = value[:_MAX_PARAM_VALUE_LEN] + "...[truncated]"
            else:
                sanitized[key] = value
        return sanitized

    def close(self) -> None:
        """Flush and close the underlying log file if it is not stderr.

        Safe to call multiple times.
        """
        if self._file is not sys.stderr:
            try:
                self._file.flush()
                self._file.close()
            except OSError:
                pass
