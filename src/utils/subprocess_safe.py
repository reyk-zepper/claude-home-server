"""Hardened subprocess execution utilities.

CRITICAL INVARIANTS — never violate:
* ``shell=False`` on every ``subprocess`` call — no shell injection possible.
* Environment is always replaced with ``CLEAN_ENV`` (plus optional extras) —
  no leaked credentials or injected vars from the parent process.
* ``stdin`` is always ``subprocess.DEVNULL`` — no interactive prompts.
* Output is capped at ``max_output`` bytes — no OOM from runaway processes.
* A hard ``timeout`` is applied on every call — no zombie processes.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

CLEAN_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/opt/claude-home-server",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

DEFAULT_TIMEOUT: int = 30
DEFAULT_MAX_OUTPUT: int = 1_000_000  # 1 MB
DEFAULT_CWD: str = "/opt/claude-home-server"

_TRUNCATION_MARKER: str = "\n[OUTPUT TRUNCATED]"

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Immutable record of a completed (or timed-out) subprocess invocation.

    Attributes:
        stdout: Decoded standard output, possibly truncated.
        stderr: Decoded standard error, possibly truncated.
        returncode: Process exit code, or ``-1`` when execution was blocked
            before the process was started.
        timed_out: ``True`` when the process was killed due to timeout.
        truncated: ``True`` when at least one output stream was capped at
            ``max_output`` bytes.
    """

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    truncated: bool


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_and_cap(raw: bytes, max_output: int) -> tuple[str, bool]:
    """Decode *raw* bytes as UTF-8 and enforce the output size cap.

    Args:
        raw: Raw bytes from a subprocess stream.
        max_output: Maximum number of characters to retain.

    Returns:
        A 2-tuple of ``(decoded_text, was_truncated)``.
    """
    text = raw.decode("utf-8", errors="replace")
    if len(text) > max_output:
        return text[:max_output] + _TRUNCATION_MARKER, True
    return text, False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def safe_run(
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    cwd: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> CommandResult:
    """Execute a command safely without a shell.

    Guarantees:
    * ``shell=False`` — the first element of *args* is exec'd directly.
    * Environment is ``CLEAN_ENV`` merged with *extra_env* (if given).
    * ``stdin`` is ``/dev/null``.
    * Working directory defaults to ``DEFAULT_CWD`` when *cwd* is ``None``.
    * Combined stdout+stderr capped at *max_output* characters each.
    * Process is forcefully killed after *timeout* seconds.

    Args:
        args: Command and its arguments as a list — never pass a shell string.
        timeout: Seconds before the process is killed.  Defaults to 30.
        max_output: Maximum characters retained from each output stream.
            Defaults to 1 MB.
        cwd: Working directory for the subprocess.  Defaults to
            ``DEFAULT_CWD``.
        extra_env: Additional environment variables merged on top of
            ``CLEAN_ENV``.  Keys present in both are taken from *extra_env*.

    Returns:
        A ``CommandResult`` with decoded stdout, stderr, return code,
        and metadata flags.
    """
    env: dict[str, str] = {**CLEAN_ENV, **(extra_env or {})}
    effective_cwd: str = cwd if cwd is not None else DEFAULT_CWD

    try:
        proc = subprocess.run(  # noqa: S603  (shell=False guaranteed by design)
            args,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=effective_cwd,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Partial output may be attached to the exception
        raw_stdout: bytes = exc.stdout or b""
        raw_stderr: bytes = exc.stderr or b""
        stdout, out_trunc = _decode_and_cap(raw_stdout, max_output)
        stderr, err_trunc = _decode_and_cap(raw_stderr, max_output)
        return CommandResult(
            stdout=stdout,
            stderr=stderr,
            returncode=-1,
            timed_out=True,
            truncated=out_trunc or err_trunc,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            stdout="",
            stderr=f"Command not found: {exc}",
            returncode=-1,
            timed_out=False,
            truncated=False,
        )
    except PermissionError as exc:
        return CommandResult(
            stdout="",
            stderr=f"Permission denied: {exc}",
            returncode=-1,
            timed_out=False,
            truncated=False,
        )

    stdout, out_trunc = _decode_and_cap(proc.stdout, max_output)
    stderr, err_trunc = _decode_and_cap(proc.stderr, max_output)

    return CommandResult(
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode,
        timed_out=False,
        truncated=out_trunc or err_trunc,
    )


def safe_run_sudo(
    wrapper_script: str,
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> CommandResult:
    """Execute a privileged MCP wrapper script via ``sudo``.

    Only scripts whose path begins with ``/usr/local/bin/mcp-`` are permitted.
    Any other path is rejected immediately — no subprocess is spawned.

    Args:
        wrapper_script: Absolute path to the wrapper script.  Must start with
            ``/usr/local/bin/mcp-``.
        args: Additional positional arguments forwarded to the script.
        timeout: Seconds before the process is killed.  Defaults to 30.

    Returns:
        A ``CommandResult``.  When the script path is rejected, ``returncode``
        is ``-1`` and ``stderr`` contains the rejection reason.
    """
    resolved = os.path.realpath(wrapper_script)
    if not resolved.startswith("/usr/local/bin/mcp-"):
        return CommandResult(
            stdout="",
            stderr=f"Unauthorized wrapper script path: {wrapper_script}",
            returncode=-1,
            timed_out=False,
            truncated=False,
        )
    return safe_run(["sudo", resolved, *args], timeout=timeout)
