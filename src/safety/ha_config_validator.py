"""Home Assistant YAML configuration validator for claude-home-server.

Analyses a parsed or raw HA YAML configuration for dangerous directives and
patterns, returning a list of :class:`HAConfigViolation` objects.  The
validator is intentionally *standalone* — it can operate on a raw YAML string
or an already-parsed ``dict`` so callers can run it before any file is written.

Security model
--------------
Two classes of problems are identified:

**Critical violations** — directives that grant arbitrary code/command
execution or SSRF risk and MUST block the operation:

* ``shell_command:``  — arbitrary shell execution via HA integrations
* ``command_line:``   — command execution sensors and switches
* ``python_script:``  — arbitrary Python code evaluation
* ``rest_command:``   — SSRF risk; can reach internal services

**Warnings** — patterns that are not inherently exploitable but indicate
misconfiguration or potential security concerns that should be surfaced:

* ``custom_components`` references — unvetted third-party code
* Plaintext secrets (passwords/tokens/keys) in configuration values
* ``packages:`` directive — can install arbitrary pip packages
* ``panel_iframe:`` with non-local URLs — external iframe embedding

Graceful handling
-----------------
* Malformed YAML → returns a critical violation describing the parse error.
* Empty content → returns a critical violation.
* Non-dict top-level → returns a critical violation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HAConfigViolation:
    """A single security violation found while validating an HA config.

    Attributes:
        directive: The YAML key or pattern that triggered the violation.
        severity: Either ``"critical"`` (must block) or ``"warning"``
            (should surface to the operator).
        message: Human-readable description of what was found and why it
            matters.
        line_hint: Optional context hint (e.g. the offending YAML fragment).
    """

    directive: str
    severity: str  # "critical" | "warning"
    message: str
    line_hint: str = ""


@dataclass
class HAValidationResult:
    """Aggregated result of an HA configuration validation pass.

    Attributes:
        violations: All violations found, ordered as discovered.
    """

    violations: list[HAConfigViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Return True only when there are no critical violations."""
        return not any(v.severity == "critical" for v in self.violations)

    @property
    def critical_count(self) -> int:
        """Number of critical violations."""
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def warning_count(self) -> int:
        """Number of warning violations."""
        return sum(1 for v in self.violations if v.severity == "warning")

    def format_report(self) -> str:
        """Format a human-readable multi-line validation report.

        Returns:
            A plain-text report string suitable for returning to Claude.
        """
        if not self.violations:
            return "=== HA Config Validation: PASSED ===\nNo security violations found."

        status = "PASSED" if self.passed else "BLOCKED"
        lines = [
            f"=== HA Config Validation: {status} ===",
            f"Critical violations: {self.critical_count}",
            f"Warnings: {self.warning_count}",
            "",
        ]

        for viol in self.violations:
            symbol = "[CRITICAL]" if viol.severity == "critical" else "[WARNING]"
            hint = f" (near: {viol.line_hint!r})" if viol.line_hint else ""
            lines.append(f"  {symbol} {viol.directive}: {viol.message}{hint}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

# Regex to detect plaintext secret-like values.  Matches any value string
# that looks like it directly embeds a credential (as opposed to referencing
# secrets.yaml via the HA !secret tag).
_SECRET_VALUE_RE: re.Pattern[str] = re.compile(
    r"(password|token|secret|api_key|access_key|auth_key|private_key)\s*[:=]\s*.{4,}",
    re.IGNORECASE,
)

# Plaintext secret patterns checked in YAML string values.  We look for dict
# keys whose names suggest a credential and whose values are non-empty strings
# (rather than !secret references which would show up as None after safe_load
# since PyYAML's safe_load does not handle custom tags without a loader).
_SECRET_KEY_PATTERNS: tuple[str, ...] = (
    "password",
    "token",
    "secret",
    "api_key",
    "access_key",
    "auth_key",
    "private_key",
)


def _looks_like_plaintext_secret(key: str, value: Any) -> bool:
    """Return True when a key/value pair looks like a plaintext secret.

    We only flag string values — non-string values (ints, bools) are rarely
    secrets in YAML configs.  We also skip very short values (<= 3 chars)
    since they are unlikely to be real credentials.

    Args:
        key: The YAML key string.
        value: The associated value.

    Returns:
        True if the pair appears to be a plaintext credential.
    """
    if not isinstance(value, str):
        return False
    if len(value) <= 3:
        return False
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in _SECRET_KEY_PATTERNS)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class HAConfigValidator:
    """Validate Home Assistant YAML configuration for dangerous patterns.

    Example::

        validator = HAConfigValidator()
        result = validator.validate(yaml_string)
        if not result.passed:
            print(result.format_report())
    """

    # Directives that always block (critical) — arbitrary code / command execution
    BLOCKED_DIRECTIVES: tuple[str, ...] = (
        "shell_command",
        "command_line",
        "python_script",
        "rest_command",
    )

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    def validate(self, yaml_content: str) -> HAValidationResult:
        """Validate raw HA YAML content.

        Parses the YAML string first, then delegates to :meth:`validate_dict`.
        Returns a result with a critical violation when the content is empty,
        malformed, or not a mapping at the top level.

        Args:
            yaml_content: Raw YAML string to validate.

        Returns:
            An :class:`HAValidationResult` with all violations found.
        """
        result = HAValidationResult()

        if not yaml_content or not yaml_content.strip():
            result.violations.append(
                HAConfigViolation(
                    directive="<content>",
                    severity="critical",
                    message="Configuration content is empty.",
                )
            )
            return result

        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            result.violations.append(
                HAConfigViolation(
                    directive="<yaml>",
                    severity="critical",
                    message=f"YAML parse error: {exc}",
                    line_hint=str(exc)[:120],
                )
            )
            return result

        if not isinstance(data, dict):
            result.violations.append(
                HAConfigViolation(
                    directive="<document>",
                    severity="critical",
                    message=(
                        "HA configuration must be a YAML mapping at the top level, "
                        f"got {type(data).__name__!r}."
                    ),
                )
            )
            return result

        return self.validate_dict(data)

    def validate_dict(self, data: dict[str, Any]) -> HAValidationResult:
        """Validate an already-parsed HA configuration dict.

        Args:
            data: Python dict produced by ``yaml.safe_load`` of an HA config
                file.  The dict must be a top-level mapping.

        Returns:
            An :class:`HAValidationResult` with all violations found.
        """
        result = HAValidationResult()

        if not isinstance(data, dict):
            result.violations.append(
                HAConfigViolation(
                    directive="<document>",
                    severity="critical",
                    message="Configuration must be a dict.",
                )
            )
            return result

        self._check_blocked_directives(data, result)
        self._check_custom_components(data, result)
        self._check_packages(data, result)
        self._check_panel_iframe(data, result)
        self._check_plaintext_secrets(data, result)

        return result

    # ---------------------------------------------------------------------------
    # Critical checks
    # ---------------------------------------------------------------------------

    def _check_blocked_directives(
        self,
        data: dict[str, Any],
        result: HAValidationResult,
    ) -> None:
        """Block any top-level use of known dangerous HA directives.

        Checks both the top-level dict keys and one level deeper (for platform-
        style configs like ``sensor: - platform: command_line``).

        Args:
            data: Top-level parsed config dict.
            result: Violation accumulator.
        """
        for directive in self.BLOCKED_DIRECTIVES:
            if directive in data:
                result.violations.append(
                    HAConfigViolation(
                        directive=directive,
                        severity="critical",
                        message=self._blocked_directive_message(directive),
                    )
                )

        # Also check platform-style list entries:
        # sensor:
        #   - platform: command_line
        #     ...
        for key, value in data.items():
            if not isinstance(value, list):
                continue
            for idx, item in enumerate(value):
                if not isinstance(item, dict):
                    continue
                platform = item.get("platform", "")
                if str(platform) in self.BLOCKED_DIRECTIVES:
                    result.violations.append(
                        HAConfigViolation(
                            directive=f"{key}[{idx}].platform={platform}",
                            severity="critical",
                            message=self._blocked_directive_message(str(platform)),
                            line_hint=f"platform: {platform}",
                        )
                    )

    def _blocked_directive_message(self, directive: str) -> str:
        """Return a human-readable message for a blocked directive.

        Args:
            directive: The blocked directive name.

        Returns:
            Description of the risk.
        """
        messages: dict[str, str] = {
            "shell_command": (
                "shell_command allows arbitrary shell command execution. "
                "This is a critical security risk — remove this directive."
            ),
            "command_line": (
                "command_line executes arbitrary system commands. "
                "This is a critical security risk — remove this directive."
            ),
            "python_script": (
                "python_script allows arbitrary Python code execution. "
                "This is a critical security risk — remove this directive."
            ),
            "rest_command": (
                "rest_command can perform SSRF attacks against internal services. "
                "This is a critical security risk — remove this directive."
            ),
        }
        return messages.get(
            directive,
            f"{directive!r} is a blocked directive and is not permitted.",
        )

    # ---------------------------------------------------------------------------
    # Warning checks
    # ---------------------------------------------------------------------------

    def _check_custom_components(
        self,
        data: dict[str, Any],
        result: HAValidationResult,
    ) -> None:
        """Warn when custom_components are referenced.

        Args:
            data: Top-level parsed config dict.
            result: Violation accumulator.
        """
        if "custom_components" in data:
            result.violations.append(
                HAConfigViolation(
                    directive="custom_components",
                    severity="warning",
                    message=(
                        "custom_components references unvetted third-party code. "
                        "Ensure all custom components are from trusted sources "
                        "and have been reviewed for security issues."
                    ),
                )
            )

        # Also scan string values that reference the custom_components directory
        self._scan_values_for_pattern(
            data,
            pattern="custom_components",
            directive="custom_components (reference)",
            message=(
                "A configuration value references 'custom_components'. "
                "Verify this is intentional and the component is trusted."
            ),
            result=result,
            severity="warning",
            skip_top_key="custom_components",  # Already reported above
        )

    def _check_packages(
        self,
        data: dict[str, Any],
        result: HAValidationResult,
    ) -> None:
        """Warn when the packages directive is present.

        The ``packages:`` directive can install arbitrary pip packages into
        the HA virtual environment, which is a privilege escalation vector.

        Args:
            data: Top-level parsed config dict.
            result: Violation accumulator.
        """
        if "packages" in data:
            result.violations.append(
                HAConfigViolation(
                    directive="packages",
                    severity="warning",
                    message=(
                        "The 'packages' directive can install arbitrary Python packages "
                        "into the Home Assistant virtual environment. "
                        "Only use packages from trusted sources."
                    ),
                    line_hint=str(data["packages"])[:80],
                )
            )

    def _check_panel_iframe(
        self,
        data: dict[str, Any],
        result: HAValidationResult,
    ) -> None:
        """Warn when panel_iframe uses non-local URLs.

        Args:
            data: Top-level parsed config dict.
            result: Violation accumulator.
        """
        panel_iframe = data.get("panel_iframe")
        if not isinstance(panel_iframe, dict):
            return

        for panel_name, panel_cfg in panel_iframe.items():
            if not isinstance(panel_cfg, dict):
                continue
            url = panel_cfg.get("url", "")
            if isinstance(url, str) and not self._is_local_url(url):
                result.violations.append(
                    HAConfigViolation(
                        directive=f"panel_iframe.{panel_name}.url",
                        severity="warning",
                        message=(
                            f"panel_iframe URL {url!r} points to an external resource. "
                            "External iframes can be a phishing or data exfiltration risk. "
                            "Verify this URL is intentional."
                        ),
                        line_hint=url[:80],
                    )
                )

    def _check_plaintext_secrets(
        self,
        data: dict[str, Any],
        result: HAValidationResult,
    ) -> None:
        """Warn when plaintext credentials are found in configuration values.

        HA best practice is to use ``!secret`` references to ``secrets.yaml``
        rather than embedding credentials directly.  This check walks the full
        config tree looking for dict keys matching common credential patterns
        whose values are non-empty strings (a ``!secret`` reference would be
        loaded as ``None`` by ``yaml.safe_load`` since it uses a custom tag).

        Args:
            data: Top-level parsed config dict.
            result: Violation accumulator.
        """
        self._walk_for_secrets(data, path="", result=result)

    # ---------------------------------------------------------------------------
    # Tree-walking helpers
    # ---------------------------------------------------------------------------

    def _walk_for_secrets(
        self,
        node: Any,
        path: str,
        result: HAValidationResult,
    ) -> None:
        """Recursively walk the config tree looking for plaintext secrets.

        Args:
            node: Current node in the config tree (dict, list, or scalar).
            path: Dot-notation path for reporting (e.g. ``"mqtt.password"``).
            result: Violation accumulator.
        """
        if isinstance(node, dict):
            for key, value in node.items():
                full_path = f"{path}.{key}" if path else str(key)
                if _looks_like_plaintext_secret(str(key), value):
                    result.violations.append(
                        HAConfigViolation(
                            directive=full_path,
                            severity="warning",
                            message=(
                                f"Possible plaintext secret in {full_path!r}. "
                                "Use 'secret: !secret <name>' in secrets.yaml "
                                "instead of embedding credentials directly in config files."
                            ),
                            line_hint=f"{key}: {str(value)[:40]}",
                        )
                    )
                else:
                    self._walk_for_secrets(value, full_path, result)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                self._walk_for_secrets(item, f"{path}[{idx}]", result)
        # Scalars — nothing to recurse into

    def _scan_values_for_pattern(
        self,
        data: dict[str, Any],
        pattern: str,
        directive: str,
        message: str,
        result: HAValidationResult,
        severity: str = "warning",
        skip_top_key: str | None = None,
    ) -> None:
        """Scan all string values in the top-level dict for a substring pattern.

        This is a shallow scan (one level) intended for quick reference checks
        like ``custom_components`` appearing in file paths.

        Args:
            data: Dict to scan.
            pattern: Substring to look for in string values.
            directive: The directive name to use in any violation.
            message: The message for any violation found.
            result: Violation accumulator.
            severity: Violation severity.
            skip_top_key: Top-level key to skip (already reported elsewhere).
        """
        for key, value in data.items():
            if skip_top_key and key == skip_top_key:
                continue
            if isinstance(value, str) and pattern in value:
                # Only add if not already reported for this directive
                existing = {v.directive for v in result.violations}
                if directive not in existing:
                    result.violations.append(
                        HAConfigViolation(
                            directive=directive,
                            severity=severity,
                            message=message,
                            line_hint=f"{key}: {value[:60]}",
                        )
                    )

    # ---------------------------------------------------------------------------
    # Small helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _is_local_url(url: str) -> bool:
        """Return True when the URL refers to a local/internal address.

        Considers ``localhost``, ``127.x.x.x``, ``192.168.x.x``,
        ``10.x.x.x``, ``172.16-31.x.x``, and relative paths as local.

        Args:
            url: URL string to check.

        Returns:
            True if the URL is local.
        """
        if not url:
            return True
        if url.startswith("/"):
            return True  # Relative path

        local_patterns = (
            "localhost",
            "127.",
            "192.168.",
            "10.",
            "http://localhost",
            "https://localhost",
            "http://127.",
            "https://127.",
        )
        url_lower = url.lower()
        if any(url_lower.startswith(p) or p in url_lower for p in local_patterns):
            return True

        # 172.16.0.0/12 range
        if re.match(r"https?://172\.(1[6-9]|2\d|3[01])\.", url_lower):
            return True

        return False
