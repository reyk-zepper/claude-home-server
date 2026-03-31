"""Unit tests for src.safety.ha_config_validator.

Coverage targets:
  - Every blocked directive individually (shell_command, command_line, python_script, rest_command)
  - Platform-style usage of blocked directives (sensor platform: command_line)
  - Custom components warning
  - Packages directive warning
  - panel_iframe with external URLs warning
  - panel_iframe with local URLs does NOT warn
  - Plaintext secret detection (password, token, api_key, etc.)
  - Clean / valid config passes with no violations
  - Malformed YAML → critical violation
  - Empty content → critical violation
  - Non-dict top-level → critical violation
  - validate_dict with non-dict input → critical violation
  - HAValidationResult properties: passed, critical_count, warning_count
  - HAValidationResult.format_report for clean, blocked, and warnings-only cases
  - HAConfigViolation is a frozen dataclass (immutable)
  - Multiple blocked directives detected in one pass
  - Nested secret detection (deep walk)
"""
from __future__ import annotations

import pytest

from src.safety.ha_config_validator import (
    HAConfigValidator,
    HAConfigViolation,
    HAValidationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validator() -> HAConfigValidator:
    """Return a fresh HAConfigValidator instance."""
    return HAConfigValidator()


def _critical(result: HAValidationResult) -> list[HAConfigViolation]:
    return [v for v in result.violations if v.severity == "critical"]


def _warnings(result: HAValidationResult) -> list[HAConfigViolation]:
    return [v for v in result.violations if v.severity == "warning"]


# ---------------------------------------------------------------------------
# HAValidationResult properties
# ---------------------------------------------------------------------------


class TestValidationResult:
    def test_passed_when_no_violations(self) -> None:
        result = HAValidationResult()
        assert result.passed is True

    def test_passed_false_when_critical_present(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(
                    directive="shell_command",
                    severity="critical",
                    message="blocked",
                )
            ]
        )
        assert result.passed is False

    def test_passed_true_with_only_warnings(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(
                    directive="custom_components",
                    severity="warning",
                    message="risky",
                )
            ]
        )
        assert result.passed is True

    def test_critical_count_zero(self) -> None:
        assert HAValidationResult().critical_count == 0

    def test_critical_count_two(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(directive="a", severity="critical", message="x"),
                HAConfigViolation(directive="b", severity="warning", message="y"),
                HAConfigViolation(directive="c", severity="critical", message="z"),
            ]
        )
        assert result.critical_count == 2

    def test_warning_count_zero(self) -> None:
        assert HAValidationResult().warning_count == 0

    def test_warning_count_one(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(directive="a", severity="warning", message="w"),
            ]
        )
        assert result.warning_count == 1

    def test_format_report_clean(self) -> None:
        result = HAValidationResult()
        report = result.format_report()
        assert "PASSED" in report
        assert "No security violations" in report

    def test_format_report_blocked(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(
                    directive="shell_command",
                    severity="critical",
                    message="arbitrary shell",
                )
            ]
        )
        report = result.format_report()
        assert "BLOCKED" in report
        assert "[CRITICAL]" in report
        assert "shell_command" in report

    def test_format_report_warnings_only(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(
                    directive="custom_components",
                    severity="warning",
                    message="unvetted",
                )
            ]
        )
        report = result.format_report()
        assert "PASSED" in report
        assert "[WARNING]" in report
        assert "custom_components" in report

    def test_format_report_includes_line_hint(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(
                    directive="shell_command",
                    severity="critical",
                    message="blocked",
                    line_hint="shell_command: echo hi",
                )
            ]
        )
        report = result.format_report()
        assert "shell_command: echo hi" in report

    def test_format_report_counts(self) -> None:
        result = HAValidationResult(
            violations=[
                HAConfigViolation(directive="a", severity="critical", message="x"),
                HAConfigViolation(directive="b", severity="warning", message="y"),
            ]
        )
        report = result.format_report()
        assert "Critical violations: 1" in report
        assert "Warnings: 1" in report


# ---------------------------------------------------------------------------
# HAConfigViolation dataclass
# ---------------------------------------------------------------------------


class TestHAConfigViolation:
    def test_violation_is_frozen(self) -> None:
        v = HAConfigViolation(directive="x", severity="critical", message="m")
        with pytest.raises((AttributeError, TypeError)):
            v.directive = "y"  # type: ignore[misc]

    def test_violation_default_line_hint(self) -> None:
        v = HAConfigViolation(directive="x", severity="critical", message="m")
        assert v.line_hint == ""

    def test_violation_with_line_hint(self) -> None:
        v = HAConfigViolation(
            directive="x", severity="critical", message="m", line_hint="hint"
        )
        assert v.line_hint == "hint"


# ---------------------------------------------------------------------------
# Blocked directives — shell_command
# ---------------------------------------------------------------------------


class TestShellCommand:
    def test_shell_command_is_blocked(self) -> None:
        result = _validator().validate("shell_command:\n  test: 'echo hello'")
        assert not result.passed
        assert result.critical_count >= 1

    def test_shell_command_violation_names_directive(self) -> None:
        result = _validator().validate("shell_command:\n  test: 'echo hello'")
        directives = [v.directive for v in _critical(result)]
        assert any("shell_command" in d for d in directives)

    def test_shell_command_message_describes_risk(self) -> None:
        result = _validator().validate("shell_command:\n  test: 'echo hello'")
        msg = _critical(result)[0].message.lower()
        assert "shell" in msg or "execution" in msg

    def test_shell_command_empty_value_still_blocked(self) -> None:
        result = _validator().validate("shell_command: {}")
        assert not result.passed


# ---------------------------------------------------------------------------
# Blocked directives — command_line
# ---------------------------------------------------------------------------


class TestCommandLine:
    def test_command_line_top_level_is_blocked(self) -> None:
        yaml_content = (
            "command_line:\n"
            "  - name: CPU temp\n"
            "    command: 'cat /sys/class/thermal/thermal_zone0/temp'\n"
        )
        result = _validator().validate(yaml_content)
        assert not result.passed
        assert result.critical_count >= 1

    def test_command_line_platform_in_sensor_is_blocked(self) -> None:
        yaml_content = (
            "sensor:\n"
            "  - platform: command_line\n"
            "    name: CPU\n"
            "    command: 'cat /proc/loadavg'\n"
        )
        result = _validator().validate(yaml_content)
        assert not result.passed
        directives = [v.directive for v in _critical(result)]
        assert any("command_line" in d for d in directives)

    def test_command_line_platform_violation_includes_hint(self) -> None:
        yaml_content = (
            "sensor:\n"
            "  - platform: command_line\n"
            "    command: 'ls'\n"
        )
        result = _validator().validate(yaml_content)
        crits = _critical(result)
        assert crits
        assert any(v.line_hint for v in crits)

    def test_command_line_violation_message_describes_risk(self) -> None:
        result = _validator().validate("command_line:\n  - name: t\n    command: ls")
        assert not result.passed
        msg = _critical(result)[0].message.lower()
        assert "command" in msg or "execution" in msg


# ---------------------------------------------------------------------------
# Blocked directives — python_script
# ---------------------------------------------------------------------------


class TestPythonScript:
    def test_python_script_is_blocked(self) -> None:
        result = _validator().validate("python_script: true\n")
        assert not result.passed

    def test_python_script_message_mentions_python(self) -> None:
        result = _validator().validate("python_script:\n")
        msg = _critical(result)[0].message.lower()
        assert "python" in msg

    def test_python_script_platform_in_sensor(self) -> None:
        # python_script is not typically a sensor platform, but we still
        # cover the general platform check mechanism.
        yaml_content = "sensor:\n  - platform: python_script\n    name: test\n"
        result = _validator().validate(yaml_content)
        assert not result.passed


# ---------------------------------------------------------------------------
# Blocked directives — rest_command
# ---------------------------------------------------------------------------


class TestRestCommand:
    def test_rest_command_is_blocked(self) -> None:
        yaml_content = (
            "rest_command:\n"
            "  example:\n"
            "    url: http://internal.service/api\n"
            "    method: GET\n"
        )
        result = _validator().validate(yaml_content)
        assert not result.passed
        assert result.critical_count >= 1

    def test_rest_command_violation_names_directive(self) -> None:
        result = _validator().validate("rest_command:\n  x:\n    url: http://x.x\n")
        directives = [v.directive for v in _critical(result)]
        assert any("rest_command" in d for d in directives)

    def test_rest_command_message_mentions_ssrf(self) -> None:
        result = _validator().validate("rest_command:\n  x:\n    url: http://x.x\n")
        msg = _critical(result)[0].message.lower()
        assert "ssrf" in msg or "internal" in msg or "command" in msg


# ---------------------------------------------------------------------------
# Multiple blocked directives in one config
# ---------------------------------------------------------------------------


class TestMultipleBlockedDirectives:
    def test_two_blocked_directives_both_reported(self) -> None:
        yaml_content = (
            "shell_command:\n  x: 'echo hi'\n"
            "python_script: true\n"
        )
        result = _validator().validate(yaml_content)
        assert not result.passed
        assert result.critical_count >= 2

    def test_three_blocked_directives(self) -> None:
        yaml_content = (
            "shell_command:\n  x: 'echo hi'\n"
            "command_line:\n  - name: t\n    command: ls\n"
            "rest_command:\n  y:\n    url: http://x.x\n"
        )
        result = _validator().validate(yaml_content)
        assert result.critical_count >= 3


# ---------------------------------------------------------------------------
# Custom components warning
# ---------------------------------------------------------------------------


class TestCustomComponents:
    def test_custom_components_produces_warning(self) -> None:
        yaml_content = (
            "custom_components:\n"
            "  myintegration:\n"
            "    key: value\n"
        )
        result = _validator().validate(yaml_content)
        # Warning, not critical
        assert result.passed
        assert result.warning_count >= 1

    def test_custom_components_warning_names_directive(self) -> None:
        result = _validator().validate("custom_components:\n  x: {}\n")
        directives = [v.directive for v in _warnings(result)]
        assert any("custom_components" in d for d in directives)

    def test_custom_components_message_mentions_unvetted(self) -> None:
        result = _validator().validate("custom_components:\n  x: {}\n")
        msg = _warnings(result)[0].message.lower()
        assert "unvetted" in msg or "third-party" in msg or "trusted" in msg


# ---------------------------------------------------------------------------
# Packages directive warning
# ---------------------------------------------------------------------------


class TestPackagesDirective:
    def test_packages_produces_warning(self) -> None:
        yaml_content = "packages:\n  - some-lib\n"
        result = _validator().validate(yaml_content)
        assert result.passed
        assert result.warning_count >= 1

    def test_packages_warning_names_directive(self) -> None:
        result = _validator().validate("packages:\n  - foo\n")
        directives = [v.directive for v in _warnings(result)]
        assert any("packages" in d for d in directives)

    def test_packages_message_mentions_pip(self) -> None:
        result = _validator().validate("packages:\n  - foo\n")
        msg = _warnings(result)[0].message.lower()
        assert "package" in msg or "pip" in msg or "install" in msg


# ---------------------------------------------------------------------------
# panel_iframe with external URLs warning
# ---------------------------------------------------------------------------


class TestPanelIframe:
    def test_external_url_produces_warning(self) -> None:
        yaml_content = (
            "panel_iframe:\n"
            "  external_panel:\n"
            "    title: External\n"
            "    url: https://example.com\n"
        )
        result = _validator().validate(yaml_content)
        assert result.passed
        assert result.warning_count >= 1

    def test_external_url_warning_names_panel(self) -> None:
        yaml_content = (
            "panel_iframe:\n"
            "  mypanel:\n"
            "    url: https://evil.example.com/page\n"
        )
        result = _validator().validate(yaml_content)
        directives = [v.directive for v in _warnings(result)]
        assert any("panel_iframe" in d for d in directives)

    def test_local_url_does_not_warn(self) -> None:
        yaml_content = (
            "panel_iframe:\n"
            "  localpanel:\n"
            "    title: Local\n"
            "    url: http://localhost:3000\n"
        )
        result = _validator().validate(yaml_content)
        panel_warnings = [v for v in _warnings(result) if "panel_iframe" in v.directive]
        assert len(panel_warnings) == 0

    def test_192_168_url_does_not_warn(self) -> None:
        yaml_content = (
            "panel_iframe:\n"
            "  local:\n"
            "    url: http://192.168.1.100:8080\n"
        )
        result = _validator().validate(yaml_content)
        panel_warnings = [v for v in _warnings(result) if "panel_iframe" in v.directive]
        assert len(panel_warnings) == 0

    def test_no_panel_iframe_key_no_warning(self) -> None:
        result = _validator().validate("homeassistant:\n  name: Home\n")
        panel_warnings = [v for v in _warnings(result) if "panel_iframe" in v.directive]
        assert len(panel_warnings) == 0


# ---------------------------------------------------------------------------
# Plaintext secrets warning
# ---------------------------------------------------------------------------


class TestPlaintextSecrets:
    def test_password_in_value_warns(self) -> None:
        yaml_content = (
            "mqtt:\n"
            "  host: localhost\n"
            "  username: user\n"
            "  password: mysecretpassword\n"
        )
        result = _validator().validate(yaml_content)
        assert result.passed
        secret_warnings = [v for v in _warnings(result) if "password" in v.directive.lower()]
        assert len(secret_warnings) >= 1

    def test_token_in_value_warns(self) -> None:
        yaml_content = "integration:\n  token: abc123xyz\n"
        result = _validator().validate(yaml_content)
        token_warnings = [v for v in _warnings(result) if "token" in v.directive.lower()]
        assert len(token_warnings) >= 1

    def test_api_key_in_value_warns(self) -> None:
        yaml_content = "myservice:\n  api_key: supersecretapikey123\n"
        result = _validator().validate(yaml_content)
        key_warnings = [v for v in _warnings(result) if "api_key" in v.directive.lower()]
        assert len(key_warnings) >= 1

    def test_short_value_does_not_warn(self) -> None:
        # Values <= 3 chars are unlikely to be real credentials
        yaml_content = "integration:\n  token: yes\n"
        result = _validator().validate(yaml_content)
        # 'yes' is only 3 chars — should not trigger
        token_warnings = [
            v for v in _warnings(result)
            if "token" in v.directive.lower() and "yes" in (v.line_hint or "")
        ]
        assert len(token_warnings) == 0

    def test_nested_secret_detected(self) -> None:
        yaml_content = (
            "deep:\n"
            "  nested:\n"
            "    password: secretvalue\n"
        )
        result = _validator().validate(yaml_content)
        secret_warnings = [v for v in _warnings(result) if "password" in v.directive.lower()]
        assert len(secret_warnings) >= 1

    def test_non_string_value_does_not_warn(self) -> None:
        # Integer/bool values for secret-key-named fields should not warn
        yaml_content = "config:\n  timeout: 30\n"
        result = _validator().validate(yaml_content)
        # 'timeout' is not a secret key name, but even if it were, it's int
        assert result.warning_count == 0


# ---------------------------------------------------------------------------
# Clean config passes
# ---------------------------------------------------------------------------


class TestCleanConfig:
    def test_minimal_config_passes(self) -> None:
        yaml_content = (
            "homeassistant:\n"
            "  name: Home\n"
            "  unit_system: metric\n"
        )
        result = _validator().validate(yaml_content)
        assert result.passed

    def test_automation_include_passes(self) -> None:
        # HA commonly uses !include which yaml.safe_load ignores (returns None)
        # but the top-level dict itself is clean
        yaml_content = (
            "homeassistant:\n"
            "  name: My Home\n"
            "  unit_system: imperial\n"
            "automation: []\n"
            "scene: []\n"
        )
        result = _validator().validate(yaml_content)
        assert result.passed

    def test_light_and_switch_config_passes(self) -> None:
        yaml_content = (
            "light:\n"
            "  - platform: hue\n"
            "    host: 192.168.1.50\n"
            "switch:\n"
            "  - platform: mqtt\n"
            "    name: Plug 1\n"
            "    command_topic: home/switch/plug1/set\n"
        )
        result = _validator().validate(yaml_content)
        # light.hue and switch.mqtt are benign platforms
        assert result.passed

    def test_logger_config_passes(self) -> None:
        yaml_content = (
            "logger:\n"
            "  default: info\n"
            "  logs:\n"
            "    homeassistant.components: warning\n"
        )
        result = _validator().validate(yaml_content)
        assert result.passed

    def test_clean_config_format_report_passes(self) -> None:
        result = _validator().validate("homeassistant:\n  name: Home\n")
        report = result.format_report()
        assert "PASSED" in report


# ---------------------------------------------------------------------------
# Edge cases — malformed YAML / empty / non-dict
# ---------------------------------------------------------------------------


class TestMalformedYAML:
    def test_invalid_yaml_returns_critical(self) -> None:
        yaml_content = "key: [\nunclosed bracket"
        result = _validator().validate(yaml_content)
        assert not result.passed
        assert result.critical_count >= 1

    def test_invalid_yaml_violation_mentions_parse_error(self) -> None:
        yaml_content = "key: [\nunclosed"
        result = _validator().validate(yaml_content)
        msg = _critical(result)[0].message.lower()
        assert "yaml" in msg or "parse" in msg or "error" in msg

    def test_tabs_in_yaml_returns_critical(self) -> None:
        # YAML does not allow tabs for indentation
        yaml_content = "key:\n\tvalue: bad"
        result = _validator().validate(yaml_content)
        assert not result.passed


class TestEmptyContent:
    def test_empty_string_returns_critical(self) -> None:
        result = _validator().validate("")
        assert not result.passed
        assert result.critical_count >= 1

    def test_whitespace_only_returns_critical(self) -> None:
        result = _validator().validate("   \n\t\n  ")
        assert not result.passed
        assert result.critical_count >= 1

    def test_empty_violation_mentions_empty(self) -> None:
        result = _validator().validate("")
        msg = _critical(result)[0].message.lower()
        assert "empty" in msg


class TestNonDictTopLevel:
    def test_list_top_level_returns_critical(self) -> None:
        result = _validator().validate("- item1\n- item2\n")
        assert not result.passed
        assert result.critical_count >= 1

    def test_scalar_top_level_returns_critical(self) -> None:
        result = _validator().validate("just a string\n")
        assert not result.passed

    def test_non_dict_violation_mentions_mapping(self) -> None:
        result = _validator().validate("- item1\n")
        msg = _critical(result)[0].message.lower()
        assert "mapping" in msg or "dict" in msg


class TestValidateDictDirectly:
    def test_validate_dict_clean(self) -> None:
        result = _validator().validate_dict({"homeassistant": {"name": "Home"}})
        assert result.passed

    def test_validate_dict_blocked_directive(self) -> None:
        result = _validator().validate_dict({"shell_command": {"x": "echo hi"}})
        assert not result.passed

    def test_validate_dict_non_dict_input(self) -> None:
        result = _validator().validate_dict(["not", "a", "dict"])  # type: ignore[arg-type]
        assert not result.passed
        assert result.critical_count >= 1

    def test_validate_dict_empty_dict_passes(self) -> None:
        result = _validator().validate_dict({})
        assert result.passed
