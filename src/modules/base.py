"""Base class for all MCP tool modules in claude-home-server.

Every module inherits from ``BaseModule`` which provides:

* A dedicated ``FastMCP`` sub-server instance to register tools on.
* ``_wrap_tool`` — wraps every tool function with audit logging, circuit
  breaker checks, and output filtering so individual modules never have to
  repeat that boilerplate.
* ``_register_tool`` — convenience helper that wraps and registers a callable
  in one call.

Modules implement ``_register_tools`` and call ``_register_tool`` for each
tool they expose.  The parent ``create_server`` method calls
``_register_tools`` and returns the configured ``FastMCP`` instance for
mounting onto the root server.
"""

from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable

from fastmcp import FastMCP

from src.audit import AuditLogger
from src.permissions import PermissionEngine, RiskLevel
from src.safety.output_filter import OutputFilter
from src.utils.circuit_breaker import CircuitBreaker, BurstLimitExceeded, CircuitBreakerOpen


class BaseModule:
    """Base class for all MCP tool modules.

    Subclasses must:

    1. Set a unique ``MODULE_NAME`` class attribute.
    2. Implement ``_register_tools`` to register all tools via
       ``_register_tool``.

    Args:
        config: The ``ServerConfig`` instance (typed as ``Any`` to avoid
            circular imports at module level).
        permission_engine: Shared ``PermissionEngine`` for risk-level lookups.
        audit_logger: Shared ``AuditLogger`` for structured audit records.
        circuit_breaker: Optional pre-configured ``CircuitBreaker``.  A fresh
            default instance is created when not supplied.

    Example::

        class MyModule(BaseModule):
            MODULE_NAME = "my_module"

            def _register_tools(self) -> None:
                self._register_tool("my_tool", self._my_tool_impl, "Does a thing")

            def _my_tool_impl(self, param: str) -> str:
                return f"result: {param}"
    """

    MODULE_NAME: str = "base"

    def __init__(
        self,
        config: Any,  # ServerConfig — Any avoids circular import at module level
        permission_engine: PermissionEngine,
        audit_logger: AuditLogger,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self._config = config
        self._permissions = permission_engine
        self._audit = audit_logger
        self._circuit_breaker = circuit_breaker or CircuitBreaker()
        self._output_filter = OutputFilter()
        self._server: FastMCP = FastMCP(self.MODULE_NAME)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_server(self) -> FastMCP:
        """Register all tools and return the module's ``FastMCP`` instance.

        Called once by the root server factory.  Subsequent calls return the
        same ``FastMCP`` instance with tools already registered.

        Returns:
            A configured ``FastMCP`` sub-server ready to be mounted.
        """
        self._register_tools()
        return self._server

    # ------------------------------------------------------------------
    # Protected helpers — used by subclasses
    # ------------------------------------------------------------------

    def _register_tools(self) -> None:
        """Override in subclasses to register module-specific tools.

        Raises:
            NotImplementedError: Always, when not overridden.
        """
        raise NotImplementedError

    def _wrap_tool(self, tool_name: str, func: Callable[..., Any]) -> Callable[..., str]:
        """Wrap a tool function with cross-cutting concerns.

        The wrapper applies, in order:

        1. Circuit breaker check — raises if the tool's circuit is open.
        2. Burst limit check — raises if the risk-level call rate is exceeded.
        3. Tool execution.
        4. Output filtering (text or dict).
        5. Success recording and audit logging.

        On ``CircuitBreakerOpen`` or ``BurstLimitExceeded`` the call is
        logged with status ``"denied"`` and ``[BLOCKED] …`` is returned
        to Claude.  On any other exception the failure is recorded, the
        call is logged with status ``"error"``, and ``[ERROR] …`` is
        returned so Claude can report the problem.

        Args:
            tool_name: The canonical tool name used for audit and permission
                lookups.
            func: The raw implementation callable.

        Returns:
            A new callable with identical signature that always returns a
            ``str``.
        """

        @wraps(func)
        def wrapper(**kwargs: Any) -> str:
            start = time.monotonic()
            risk_level: RiskLevel = self._permissions.get_risk_level(tool_name)

            try:
                self._circuit_breaker.check_circuit(tool_name)
                self._circuit_breaker.check_burst_limit(risk_level)

                raw_result = func(**kwargs)

                if isinstance(raw_result, str):
                    result: str = self._output_filter.filter_text(raw_result)
                elif isinstance(raw_result, dict):
                    result = str(self._output_filter.filter_dict(raw_result))
                else:
                    result = str(raw_result)

                self._circuit_breaker.record_success(tool_name)
                duration = (time.monotonic() - start) * 1000
                self._audit.log_tool_call(
                    tool=tool_name,
                    risk_level=risk_level,
                    parameters=kwargs,
                    result_status="success",
                    duration_ms=duration,
                )
                return result

            except (CircuitBreakerOpen, BurstLimitExceeded) as exc:
                duration = (time.monotonic() - start) * 1000
                self._audit.log_tool_call(
                    tool=tool_name,
                    risk_level=risk_level,
                    parameters=kwargs,
                    result_status="denied",
                    duration_ms=duration,
                    error_message=str(exc),
                )
                return f"[BLOCKED] {exc}"

            except Exception as exc:  # noqa: BLE001
                self._circuit_breaker.record_failure(tool_name)
                duration = (time.monotonic() - start) * 1000
                self._audit.log_tool_call(
                    tool=tool_name,
                    risk_level=risk_level,
                    parameters=kwargs,
                    result_status="error",
                    duration_ms=duration,
                    error_message=str(exc),
                )
                return f"[ERROR] {type(exc).__name__}: {exc}"

        return wrapper

    def _register_tool(
        self,
        name: str,
        func: Callable[..., Any],
        description: str,
    ) -> None:
        """Wrap *func* and register it as an MCP tool on the module's server.

        Sets ``__name__`` and ``__doc__`` on the wrapper so FastMCP picks up
        the intended tool name and description when it introspects the
        callable.

        Args:
            name: Tool name exposed to Claude (e.g. ``"docker_restart"``).
            func: The raw implementation to wrap.
            description: Human-readable description shown to Claude in the
                tool list.
        """
        wrapped = self._wrap_tool(name, func)
        wrapped.__name__ = name
        wrapped.__doc__ = description
        self._server.tool(wrapped)
