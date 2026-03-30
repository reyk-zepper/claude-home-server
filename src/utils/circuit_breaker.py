"""Circuit breaker with failure tracking and burst-rate protection.

Two independent protection mechanisms are combined in a single class:

**Circuit Breaker** — per-tool failure counting.
    After ``max_consecutive_failures`` consecutive errors the circuit opens and
    ``check_circuit`` raises ``CircuitBreakerOpen`` until ``reset`` is called.

**Burst Limiter** — per-risk-level call-rate guard.
    ``CRITICAL``-risk tools have a sliding-window limit of
    ``burst_limit_critical`` calls per ``burst_window_minutes`` minutes.
    ``check_burst_limit`` raises ``BurstLimitExceeded`` when the window is full.

Both mechanisms use ``time.monotonic()`` for all time comparisons so they
are unaffected by wall-clock adjustments (NTP, DST, etc.).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from src.permissions import RiskLevel

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class CircuitBreakerOpen(Exception):
    """Raised when a tool's circuit is open due to repeated failures.

    Args:
        tool_name: The tool whose circuit is open.
        failure_count: Number of consecutive failures that tripped the breaker.
    """

    def __init__(self, tool_name: str, failure_count: int) -> None:
        self.tool_name = tool_name
        self.failure_count = failure_count
        super().__init__(
            f"Circuit open for '{tool_name}' after {failure_count} consecutive failures"
        )


class BurstLimitExceeded(Exception):
    """Raised when a risk-level's burst call limit is exceeded.

    Args:
        risk_level: The ``RiskLevel`` whose window is saturated.
        limit: Maximum calls allowed in the current window.
        window_minutes: Duration of the sliding window in minutes.
    """

    def __init__(self, risk_level: RiskLevel, limit: int, window_minutes: int) -> None:
        self.risk_level = risk_level
        self.limit = limit
        self.window_minutes = window_minutes
        super().__init__(
            f"Burst limit of {limit} calls/{window_minutes}min exceeded for "
            f"risk level '{risk_level.value}'"
        )


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Combined circuit breaker and burst-rate limiter.

    Args:
        max_consecutive_failures: Number of back-to-back failures before a
            tool's circuit opens.  Defaults to 3.
        burst_limit_critical: Maximum ``CRITICAL``-risk calls allowed inside
            the sliding time window.  Defaults to 5.
        burst_window_minutes: Width of the sliding window in minutes.
            Defaults to 5.

    Example::

        cb = CircuitBreaker()
        cb.check_circuit("docker_restart")   # fine initially
        cb.record_failure("docker_restart")
        cb.record_failure("docker_restart")
        cb.record_failure("docker_restart")
        # raises CircuitBreakerOpen:
        cb.check_circuit("docker_restart")
    """

    def __init__(
        self,
        max_consecutive_failures: int = 3,
        burst_limit_critical: int = 5,
        burst_window_minutes: int = 5,
    ) -> None:
        self._max_failures: int = max_consecutive_failures
        self._burst_limit_critical: int = burst_limit_critical
        self._burst_window_seconds: float = burst_window_minutes * 60.0
        self._burst_window_minutes: int = burst_window_minutes

        # Per-tool consecutive failure counters
        self._failure_counts: dict[str, int] = defaultdict(int)

        # Per-risk-level sliding-window call timestamps (monotonic)
        self._critical_timestamps: deque[float] = deque()

    # ------------------------------------------------------------------
    # Circuit-breaker API
    # ------------------------------------------------------------------

    def record_success(self, tool_name: str) -> None:
        """Reset the consecutive failure counter for *tool_name*.

        Args:
            tool_name: The tool that completed successfully.
        """
        self._failure_counts[tool_name] = 0

    def record_failure(self, tool_name: str) -> None:
        """Increment the consecutive failure counter for *tool_name*.

        Args:
            tool_name: The tool that failed.
        """
        self._failure_counts[tool_name] += 1

    def check_circuit(self, tool_name: str) -> None:
        """Raise ``CircuitBreakerOpen`` if *tool_name*'s circuit is open.

        The circuit is open when the number of consecutive failures reaches
        ``max_consecutive_failures``.

        Args:
            tool_name: The tool to check.

        Raises:
            CircuitBreakerOpen: When the circuit is open for *tool_name*.
        """
        count = self._failure_counts[tool_name]
        if count >= self._max_failures:
            raise CircuitBreakerOpen(tool_name, count)

    # ------------------------------------------------------------------
    # Burst-limiter API
    # ------------------------------------------------------------------

    def check_burst_limit(self, risk_level: RiskLevel) -> None:
        """Raise ``BurstLimitExceeded`` if the burst window for *risk_level* is full.

        Currently only ``CRITICAL`` risk-level calls are rate-limited.  All
        other risk levels pass through unconditionally.  Stale timestamps
        (outside the current window) are evicted before the check so the
        deque never grows without bound.

        Calling this method also records the current timestamp so each
        successful check counts toward the burst window.

        Args:
            risk_level: The risk level of the tool about to be invoked.

        Raises:
            BurstLimitExceeded: When the ``CRITICAL`` burst limit is exceeded.
        """
        if risk_level != RiskLevel.CRITICAL:
            return

        now: float = time.monotonic()
        cutoff: float = now - self._burst_window_seconds

        # Evict entries older than the window boundary
        while self._critical_timestamps and self._critical_timestamps[0] < cutoff:
            self._critical_timestamps.popleft()

        if len(self._critical_timestamps) >= self._burst_limit_critical:
            raise BurstLimitExceeded(
                risk_level,
                self._burst_limit_critical,
                self._burst_window_minutes,
            )

        # Record this invocation in the window
        self._critical_timestamps.append(now)

    # ------------------------------------------------------------------
    # Management API
    # ------------------------------------------------------------------

    def reset(self, tool_name: str | None = None) -> None:
        """Reset circuit state for a specific tool or all tools.

        When *tool_name* is ``None``, all failure counters and the burst
        timestamp window are cleared.

        Args:
            tool_name: Tool to reset, or ``None`` to reset everything.
        """
        if tool_name is None:
            self._failure_counts.clear()
            self._critical_timestamps.clear()
        else:
            self._failure_counts[tool_name] = 0

    def get_status(self) -> dict[str, object]:
        """Return a snapshot of current circuit-breaker state.

        Returns a dict suitable for health-check or monitoring endpoints.
        It includes per-tool failure counts, the list of open circuits, and
        the current critical-burst window occupancy.

        Returns:
            A plain ``dict`` with keys:
            * ``failure_counts`` — mapping of tool name to consecutive failure count.
            * ``open_circuits`` — list of tool names whose circuits are open.
            * ``critical_burst_window_used`` — calls recorded in the current window.
            * ``critical_burst_limit`` — configured burst limit for CRITICAL tools.
        """
        now: float = time.monotonic()
        cutoff: float = now - self._burst_window_seconds
        active_critical = sum(1 for ts in self._critical_timestamps if ts >= cutoff)

        return {
            "failure_counts": dict(self._failure_counts),
            "open_circuits": [
                name
                for name, count in self._failure_counts.items()
                if count >= self._max_failures
            ],
            "critical_burst_window_used": active_critical,
            "critical_burst_limit": self._burst_limit_critical,
        }
