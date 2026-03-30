"""Unit tests for src.safety.output_filter.

Coverage targets:
  - Sensitive env var filtering (PASSWORD, SECRET, TOKEN, KEY, etc.)
  - Non-sensitive env vars are kept intact
  - Nested dict key filtering (recursive walk)
  - Text truncation with [TRUNCATED] marker
  - Case-insensitive key matching
  - Empty and edge-case inputs
  - Inline sensitive pattern redaction in free-form text
  - List values inside dicts are walked for nested dicts
"""
from __future__ import annotations

import pytest

from src.safety.output_filter import MASK, OutputFilter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def flt() -> OutputFilter:
    """Default OutputFilter with 50 000-byte limit."""
    return OutputFilter()


@pytest.fixture()
def small_flt() -> OutputFilter:
    """OutputFilter with a tiny 20-byte limit for truncation tests."""
    return OutputFilter(max_output_bytes=20)


# ---------------------------------------------------------------------------
# filter_env_vars
# ---------------------------------------------------------------------------


class TestFilterEnvVars:
    """Tests for OutputFilter.filter_env_vars."""

    @pytest.mark.parametrize(
        "key",
        [
            "PASSWORD",
            "DB_PASSWORD",
            "MY_PASSWORD",
            "SECRET",
            "APP_SECRET",
            "MY_SECRET_KEY",
            "TOKEN",
            "AUTH_TOKEN",
            "ACCESS_TOKEN",
            "KEY",
            "API_KEY",
            "PRIVATE_KEY",
            "CREDENTIAL",
            "AWS_CREDENTIAL",
            "AUTH",
            "OAUTH_AUTH",
            "APIKEY",
            "PRIVATE",
            "PRIVATE_DATA",
        ],
    )
    def test_sensitive_key_value_is_masked(
        self, flt: OutputFilter, key: str
    ) -> None:
        lines = [f"{key}=super_secret_value"]
        result = flt.filter_env_vars(lines)
        assert result == [f"{key}={MASK}"]

    @pytest.mark.parametrize(
        "line",
        [
            "HOME=/home/user",
            "USER=alice",
            "SHELL=/bin/bash",
            "LANG=en_US.UTF-8",
            "PATH=/usr/bin:/bin",
            "TERM=xterm-256color",
            "DISPLAY=:0",
        ],
    )
    def test_non_sensitive_var_is_kept_intact(
        self, flt: OutputFilter, line: str
    ) -> None:
        result = flt.filter_env_vars([line])
        assert result == [line]

    def test_multiple_lines_mixed_sensitivity(self, flt: OutputFilter) -> None:
        lines = [
            "HOME=/home/alice",
            "DB_PASSWORD=hunter2",
            "USER=alice",
            "SECRET_TOKEN=abc123",
            "SHELL=/bin/zsh",
        ]
        result = flt.filter_env_vars(lines)
        assert result[0] == "HOME=/home/alice"
        assert result[1] == f"DB_PASSWORD={MASK}"
        assert result[2] == "USER=alice"
        assert result[3] == f"SECRET_TOKEN={MASK}"
        assert result[4] == "SHELL=/bin/zsh"

    def test_empty_list_returns_empty_list(self, flt: OutputFilter) -> None:
        assert flt.filter_env_vars([]) == []

    def test_line_without_equals_is_passed_through(self, flt: OutputFilter) -> None:
        lines = ["# This is a comment", "", "BARE_WORD"]
        result = flt.filter_env_vars(lines)
        assert result == lines

    def test_value_with_equals_sign_is_handled(self, flt: OutputFilter) -> None:
        """KEY=value=with=equals must mask only the first equals boundary."""
        lines = ["DB_PASSWORD=abc=def=ghi"]
        result = flt.filter_env_vars(lines)
        assert result == [f"DB_PASSWORD={MASK}"]

    def test_empty_value_is_masked(self, flt: OutputFilter) -> None:
        lines = ["SECRET="]
        result = flt.filter_env_vars(lines)
        assert result == [f"SECRET={MASK}"]

    def test_case_insensitive_matching(self, flt: OutputFilter) -> None:
        lines = ["password=lower", "PASSWORD=upper", "Password=mixed"]
        result = flt.filter_env_vars(lines)
        assert all(line.endswith(MASK) for line in result)

    def test_key_with_leading_whitespace_is_handled(self, flt: OutputFilter) -> None:
        """Whitespace in key names should still match sensitive patterns."""
        lines = [" PASSWORD=stripped"]
        result = flt.filter_env_vars(lines)
        assert result == [f" PASSWORD={MASK}"]


# ---------------------------------------------------------------------------
# filter_dict
# ---------------------------------------------------------------------------


class TestFilterDict:
    """Tests for OutputFilter.filter_dict."""

    def test_top_level_sensitive_key_is_masked(self, flt: OutputFilter) -> None:
        data = {"username": "alice", "password": "hunter2"}
        result = flt.filter_dict(data)
        assert result["username"] == "alice"
        assert result["password"] == MASK

    def test_nested_sensitive_key_is_masked(self, flt: OutputFilter) -> None:
        data = {
            "db": {
                "host": "localhost",
                "password": "secret123",
                "port": 5432,
            }
        }
        result = flt.filter_dict(data)
        assert result["db"]["host"] == "localhost"
        assert result["db"]["password"] == MASK
        assert result["db"]["port"] == 5432

    def test_deeply_nested_sensitive_key_is_masked(self, flt: OutputFilter) -> None:
        data = {"level1": {"level2": {"level3": {"api_key": "mykey"}}}}
        result = flt.filter_dict(data)
        assert result["level1"]["level2"]["level3"]["api_key"] == MASK

    def test_non_sensitive_keys_are_preserved(self, flt: OutputFilter) -> None:
        data = {"host": "localhost", "port": 5432, "database": "mydb"}
        result = flt.filter_dict(data)
        assert result == data

    def test_list_of_dicts_is_walked(self, flt: OutputFilter) -> None:
        data = {
            "users": [
                {"name": "alice", "password": "pw1"},
                {"name": "bob", "token": "tok2"},
            ]
        }
        result = flt.filter_dict(data)
        assert result["users"][0]["name"] == "alice"
        assert result["users"][0]["password"] == MASK
        assert result["users"][1]["name"] == "bob"
        assert result["users"][1]["token"] == MASK

    def test_list_of_primitives_is_kept(self, flt: OutputFilter) -> None:
        data = {"tags": ["web", "prod", "v2"]}
        result = flt.filter_dict(data)
        assert result["tags"] == ["web", "prod", "v2"]

    def test_empty_dict_returns_empty_dict(self, flt: OutputFilter) -> None:
        assert flt.filter_dict({}) == {}

    def test_case_insensitive_key_matching(self, flt: OutputFilter) -> None:
        data = {
            "PASSWORD": "pw",
            "Password": "pw",
            "password": "pw",
            "PassWord": "pw",
        }
        result = flt.filter_dict(data)
        assert all(v == MASK for v in result.values())

    def test_original_dict_is_not_mutated(self, flt: OutputFilter) -> None:
        original = {"password": "secret", "name": "alice"}
        flt.filter_dict(original)
        assert original["password"] == "secret"

    def test_none_values_are_preserved_for_non_sensitive_keys(
        self, flt: OutputFilter
    ) -> None:
        data = {"host": None, "port": None}
        result = flt.filter_dict(data)
        assert result == data

    def test_integer_values_are_preserved(self, flt: OutputFilter) -> None:
        data = {"count": 42, "limit": 100}
        result = flt.filter_dict(data)
        assert result == data

    def test_sensitive_key_with_any_value_type_is_masked(
        self, flt: OutputFilter
    ) -> None:
        """Even numeric or None values under a sensitive key must be masked."""
        data = {"api_key": None, "secret": 12345, "token": ["list", "value"]}
        result = flt.filter_dict(data)
        assert result["api_key"] == MASK
        assert result["secret"] == MASK
        assert result["token"] == MASK


# ---------------------------------------------------------------------------
# truncate
# ---------------------------------------------------------------------------


class TestTruncate:
    def test_short_text_is_not_truncated(self, flt: OutputFilter) -> None:
        text = "Hello, world!"
        assert flt.truncate(text) == text

    def test_text_at_exact_limit_is_not_truncated(self) -> None:
        flt = OutputFilter(max_output_bytes=10)
        text = "1234567890"  # exactly 10 bytes
        assert flt.truncate(text) == text

    def test_text_over_limit_gets_truncated_marker(
        self, small_flt: OutputFilter
    ) -> None:
        text = "A" * 100
        result = small_flt.truncate(text)
        assert result.endswith("[TRUNCATED]")

    def test_truncated_result_fits_within_limit(
        self, small_flt: OutputFilter
    ) -> None:
        text = "A" * 100
        result = small_flt.truncate(text)
        assert len(result.encode("utf-8")) <= 20

    def test_empty_string_is_not_truncated(self, flt: OutputFilter) -> None:
        assert flt.truncate("") == ""

    def test_marker_appears_exactly_once(self, small_flt: OutputFilter) -> None:
        text = "B" * 200
        result = small_flt.truncate(text)
        assert result.count("[TRUNCATED]") == 1

    def test_multibyte_chars_do_not_produce_invalid_utf8(
        self, flt: OutputFilter
    ) -> None:
        """Truncation on a multi-byte boundary must not produce mojibake."""
        flt_small = OutputFilter(max_output_bytes=5)
        text = "こんにちは"  # each char is 3 bytes in UTF-8
        result = flt_small.truncate(text)
        # Result must be decodable (no UnicodeDecodeError)
        result.encode("utf-8")
        assert result.endswith("[TRUNCATED]")


# ---------------------------------------------------------------------------
# filter_text
# ---------------------------------------------------------------------------


class TestFilterText:
    def test_empty_string_is_returned_as_is(self, flt: OutputFilter) -> None:
        assert flt.filter_text("") == ""

    def test_text_without_secrets_is_unchanged(self, flt: OutputFilter) -> None:
        text = "Server started on port 8080. All systems nominal."
        result = flt.filter_text(text)
        assert result == text

    def test_inline_password_is_redacted(self, flt: OutputFilter) -> None:
        text = "password=super_secret_value"
        result = flt.filter_text(text)
        assert "super_secret_value" not in result
        assert MASK in result

    def test_inline_token_is_redacted(self, flt: OutputFilter) -> None:
        text = "token=eyJhbGciOiJIUzI1NiJ9.payload.signature"
        result = flt.filter_text(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_bearer_token_is_redacted(self, flt: OutputFilter) -> None:
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        result = flt.filter_text(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_pem_private_key_block_is_redacted(self, flt: OutputFilter) -> None:
        text = (
            "some output\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4\n"
            "-----END RSA PRIVATE KEY-----\n"
            "more output"
        )
        result = flt.filter_text(text)
        assert "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn" not in result

    def test_text_is_truncated_when_over_limit(self) -> None:
        flt_small = OutputFilter(max_output_bytes=50)
        text = "x" * 1000
        result = flt_small.filter_text(text)
        assert result.endswith("[TRUNCATED]")
        assert len(result.encode("utf-8")) <= 50

    def test_aws_secret_is_redacted(self, flt: OutputFilter) -> None:
        text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = flt.filter_text(text)
        assert "wJalrXUtnFEMI" not in result


# ---------------------------------------------------------------------------
# Integration: chaining filter_dict and filter_env_vars
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_realistic_env_dump(self, flt: OutputFilter) -> None:
        lines = [
            "PATH=/usr/bin:/bin",
            "HOME=/root",
            "DB_PASSWORD=verysecret",
            "POSTGRES_USER=admin",
            "POSTGRES_PASSWORD=pg_secret",
            "APP_PORT=8080",
            "REDIS_URL=redis://localhost:6379",
            "SECRET_KEY=django-insecure-abc123",
        ]
        result = flt.filter_env_vars(lines)
        # Preserved
        assert "PATH=/usr/bin:/bin" in result
        assert "HOME=/root" in result
        assert "APP_PORT=8080" in result
        assert "REDIS_URL=redis://localhost:6379" in result
        # Masked
        assert f"DB_PASSWORD={MASK}" in result
        assert f"POSTGRES_PASSWORD={MASK}" in result
        assert f"SECRET_KEY={MASK}" in result

    def test_realistic_api_response(self, flt: OutputFilter) -> None:
        response = {
            "status": "ok",
            "data": {
                "user": "alice",
                "api_key": "sk-live-abc123xyz",
                "preferences": {
                    "theme": "dark",
                    "auth_token": "tok_secret_789",
                },
            },
            "meta": {"version": "2.1"},
        }
        result = flt.filter_dict(response)
        assert result["status"] == "ok"
        assert result["data"]["user"] == "alice"
        assert result["data"]["api_key"] == MASK
        assert result["data"]["preferences"]["theme"] == "dark"
        assert result["data"]["preferences"]["auth_token"] == MASK
        assert result["meta"]["version"] == "2.1"
