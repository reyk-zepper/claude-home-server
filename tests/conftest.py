"""Shared pytest fixtures for claude-home-server test suite.

Provides lightweight instances of the four core infrastructure objects that
every module test needs:

* ``default_config`` — a ``ServerConfig`` built from defaults (no YAML file
  required), safe to use in any environment.
* ``permission_engine`` — a ``PermissionEngine`` with no overrides, applying
  only the built-in risk-level registry.
* ``audit_logger`` — an ``AuditLogger`` writing to a temporary file inside
  ``pytest``'s ``tmp_path`` directory; never touches ``/var/log``.
* ``circuit_breaker`` — a ``CircuitBreaker`` with default thresholds, reset
  between every test via the fixture's function scope.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit import AuditLogger
from src.config import ServerConfig
from src.permissions import PermissionEngine
from src.utils.circuit_breaker import CircuitBreaker


@pytest.fixture
def default_config() -> ServerConfig:
    """Return a ``ServerConfig`` populated entirely from safe defaults.

    No YAML file is read; all service integrations are disabled by default
    so tests that exercise discovery or health checks can stub out external
    calls without worrying about real service configuration.

    Returns:
        A default-initialised ``ServerConfig``.
    """
    return ServerConfig()


@pytest.fixture
def permission_engine() -> PermissionEngine:
    """Return a ``PermissionEngine`` with no user overrides.

    All tool risk levels reflect the built-in ``DEFAULT_TOOL_LEVELS`` registry
    in ``src.permissions``.

    Returns:
        A ``PermissionEngine`` instance with no overrides active.
    """
    return PermissionEngine()


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    """Return an ``AuditLogger`` writing to a temporary test file.

    The log file is created under pytest's ``tmp_path`` directory and is
    automatically cleaned up when the test session ends.

    Args:
        tmp_path: pytest built-in fixture providing a temporary directory
            unique to the test invocation.

    Returns:
        An ``AuditLogger`` instance writing to ``<tmp_path>/audit.log``.
    """
    return AuditLogger(str(tmp_path / "audit.log"))


@pytest.fixture
def circuit_breaker() -> CircuitBreaker:
    """Return a freshly initialised ``CircuitBreaker`` with default thresholds.

    Function scope ensures every test starts with a clean failure counter and
    empty burst window — no state leaks between tests.

    Returns:
        A ``CircuitBreaker`` instance with:
        * ``max_consecutive_failures=3``
        * ``burst_limit_critical=5``
        * ``burst_window_minutes=5``
    """
    return CircuitBreaker()
