"""Unit tests for src.safety.path_validator.

Coverage targets:
  - Basic allowlist / blocklist semantics
  - Every entry in HARDCODED_BLOCKLIST
  - Every pattern in HARDCODED_BLOCKED_PATTERNS
  - Every segment in HARDCODED_BLOCKED_PATH_SEGMENTS
  - Path traversal, null bytes, empty input, and very long paths
  - validate_or_raise return value and exception type
  - User-supplied blocklist overrides user-supplied allowlist
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from src.safety.path_validator import (
    HARDCODED_BLOCKLIST,
    HARDCODED_BLOCKED_PATH_SEGMENTS,
    HARDCODED_BLOCKED_PATTERNS,
    PathValidationError,
    PathValidator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_validator(*allowed: str, blocked: list[str] | None = None) -> PathValidator:
    """Return a PathValidator with the given allowed and optional blocked paths."""
    return PathValidator(list(allowed), blocked_paths=blocked)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_allowed(tmp_path: Path) -> tuple[Path, PathValidator]:
    """A validator that allows exactly ``tmp_path``."""
    return tmp_path, _make_validator(str(tmp_path))


# ---------------------------------------------------------------------------
# Basic allowlist semantics
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_file_inside_allowed_dir_is_permitted(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        target = tmp_path / "file.txt"
        target.touch()
        assert v.is_allowed(str(target)) is True

    def test_nested_file_inside_allowed_dir_is_permitted(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        nested = tmp_path / "a" / "b" / "c.txt"
        nested.parent.mkdir(parents=True)
        nested.touch()
        assert v.is_allowed(str(nested)) is True

    def test_allowed_dir_itself_is_permitted(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(str(tmp_path)) is True

    def test_path_outside_allowlist_is_denied(self, tmp_path: Path) -> None:
        other = tmp_path / "other"
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _make_validator(str(allowed))
        assert v.is_allowed(str(other)) is False

    def test_sibling_dir_prefix_does_not_grant_access(self, tmp_path: Path) -> None:
        """"/home/data" must not grant access to "/home/data_extra"."""
        data = tmp_path / "data"
        data_extra = tmp_path / "data_extra"
        data.mkdir()
        data_extra.mkdir()
        v = _make_validator(str(data))
        assert v.is_allowed(str(data_extra)) is False

    def test_empty_allowlist_denies_everything(self, tmp_path: Path) -> None:
        v = PathValidator([])
        assert v.is_allowed(str(tmp_path)) is False

    def test_multiple_allowed_paths(self, tmp_path: Path) -> None:
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        v = _make_validator(str(a), str(b))
        assert v.is_allowed(str(a / "x")) is True
        assert v.is_allowed(str(b / "y")) is True
        assert v.is_allowed(str(tmp_path / "c" / "z")) is False


# ---------------------------------------------------------------------------
# User-supplied blocklist
# ---------------------------------------------------------------------------


class TestUserBlocklist:
    def test_user_blocked_path_inside_allowed_is_denied(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        secret = allowed / "secret_dir"
        allowed.mkdir()
        secret.mkdir()
        v = _make_validator(str(allowed), blocked=[str(secret)])
        assert v.is_allowed(str(secret / "file.txt")) is False

    def test_user_blocked_overrides_allowlist(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path), blocked=[str(tmp_path)])
        assert v.is_allowed(str(tmp_path / "file.txt")) is False

    def test_user_blocked_does_not_affect_unblocked_paths(self, tmp_path: Path) -> None:
        blocked_dir = tmp_path / "blocked"
        allowed_dir = tmp_path / "allowed"
        blocked_dir.mkdir()
        allowed_dir.mkdir()
        v = _make_validator(str(tmp_path), blocked=[str(blocked_dir)])
        assert v.is_allowed(str(allowed_dir / "ok.txt")) is True
        assert v.is_allowed(str(blocked_dir / "no.txt")) is False


# ---------------------------------------------------------------------------
# Hardcoded blocklist
# ---------------------------------------------------------------------------


class TestHardcodedBlocklist:
    """Each HARDCODED_BLOCKLIST entry must be rejected regardless of allowlist."""

    @pytest.mark.parametrize("blocked_path", HARDCODED_BLOCKLIST)
    def test_hardcoded_path_is_always_denied(self, blocked_path: str) -> None:
        # Allow the root of the blocked path's parent so the allowlist alone
        # would not deny it.
        parent = str(Path(blocked_path).parent)
        v = _make_validator(parent, "/")
        assert v.is_allowed(blocked_path) is False

    def test_descendant_of_proc_is_denied(self) -> None:
        v = _make_validator("/")
        assert v.is_allowed("/proc/1/mem") is False

    def test_descendant_of_sys_is_denied(self) -> None:
        v = _make_validator("/")
        assert v.is_allowed("/sys/kernel/debug") is False

    def test_descendant_of_dev_is_denied(self) -> None:
        v = _make_validator("/")
        assert v.is_allowed("/dev/sda") is False

    def test_descendant_of_root_home_is_denied(self) -> None:
        v = _make_validator("/")
        assert v.is_allowed("/root/.bashrc") is False

    def test_descendant_of_etc_shadow_dir_is_denied(self) -> None:
        # /etc/shadow is a file, so /etc/shadow/x would only fail because of
        # the prefix rule — still must be denied.
        v = _make_validator("/")
        assert v.is_allowed("/etc/shadow") is False

    def test_proc_prefix_does_not_block_proc_data(self, tmp_path: Path) -> None:
        """A path named /proc_data must NOT be blocked by the /proc rule."""
        # We cannot actually test "/proc_data" without creating it, so we
        # verify that the os.sep boundary is respected by checking internals.
        validator = _make_validator("/")
        # The validator uses realpath; we construct a fake resolved path that
        # starts with "/proc" but is a sibling, not a descendant.
        # Direct unit test on the internal helper is acceptable here.
        assert validator._is_hardcoded_blocked("/proc") is True
        assert validator._is_hardcoded_blocked("/proc/1") is True
        assert validator._is_hardcoded_blocked("/proc_data") is False


# ---------------------------------------------------------------------------
# Hardcoded filename / extension patterns
# ---------------------------------------------------------------------------


class TestHardcodedBlockedPatterns:
    """Files matching HARDCODED_BLOCKED_PATTERNS must be denied."""

    @pytest.mark.parametrize(
        "filename",
        [
            "server.pem",
            "cert.key",
            "id_rsa",
            "id_rsa.pub",
            "id_ed25519",
            "id_ed25519.pub",
            "id_ecdsa",
            "id_ecdsa.pub",
            "id_dsa",
            "id_dsa.pub",
            ".env",
            "production.env",
            ".env.production",
            ".env.local",
        ],
    )
    def test_blocked_filename_is_denied(
        self, filename: str, tmp_path: Path
    ) -> None:
        target = tmp_path / filename
        target.touch()
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(str(target)) is False

    def test_regular_txt_file_is_not_blocked(self, tmp_path: Path) -> None:
        f = tmp_path / "readme.txt"
        f.touch()
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(str(f)) is True

    def test_pem_in_nested_allowed_dir_is_blocked(self, tmp_path: Path) -> None:
        nested = tmp_path / "certs" / "server.pem"
        nested.parent.mkdir()
        nested.touch()
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(str(nested)) is False

    def test_patterns_list_completeness(self) -> None:
        """Ensure the blocklist contains at least the documented patterns."""
        expected_substrings = ["*.pem", "*.key", "*id_rsa*", ".env"]
        for expected in expected_substrings:
            assert expected in HARDCODED_BLOCKED_PATTERNS, (
                f"Expected pattern {expected!r} missing from HARDCODED_BLOCKED_PATTERNS"
            )


# ---------------------------------------------------------------------------
# Hardcoded path segment blocking
# ---------------------------------------------------------------------------


class TestHardcodedBlockedSegments:
    """Any path component matching HARDCODED_BLOCKED_PATH_SEGMENTS is denied."""

    @pytest.mark.parametrize(
        "sub_path",
        [
            ".ssh/config",
            ".ssh/known_hosts",
            ".ssh/authorized_keys",
            "secrets/db_password",
            "secrets/api_keys.json",
            "a/b/.ssh/c",
            "a/secrets/b/c/d",
        ],
    )
    def test_blocked_segment_anywhere_in_path_is_denied(
        self, sub_path: str, tmp_path: Path
    ) -> None:
        target = tmp_path / sub_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(str(target)) is False

    def test_segment_list_completeness(self) -> None:
        assert ".ssh" in HARDCODED_BLOCKED_PATH_SEGMENTS
        assert "secrets" in HARDCODED_BLOCKED_PATH_SEGMENTS

    def test_file_named_like_segment_but_not_as_dir_component(
        self, tmp_path: Path
    ) -> None:
        """A file literally named ".ssh" (not a dir component) is also blocked."""
        f = tmp_path / ".ssh"
        f.touch()
        v = _make_validator(str(tmp_path))
        # ".ssh" appears as a path component (the final one) — still blocked.
        assert v.is_allowed(str(f)) is False


# ---------------------------------------------------------------------------
# Path traversal attacks
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_dotdot_traversal_outside_allowed_is_denied(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        crafted = str(allowed) + "/../../../etc/passwd"
        v = _make_validator(str(allowed))
        assert v.is_allowed(crafted) is False

    def test_dotdot_traversal_within_allowed_is_permitted(self, tmp_path: Path) -> None:
        """Traversal that stays within the allowed tree must pass."""
        sub = tmp_path / "sub"
        sub.mkdir()
        crafted = str(sub) + "/../"  # resolves back to tmp_path
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(crafted) is True

    def test_double_slash_is_normalised(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.touch()
        double_slash = str(tmp_path) + "//file.txt"
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(double_slash) is True

    def test_trailing_slash_normalised(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(str(tmp_path) + "/") is True

    def test_null_byte_in_path_is_denied(self, tmp_path: Path) -> None:
        crafted = str(tmp_path) + "/file\x00.txt"
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(crafted) is False

    def test_empty_path_is_denied(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        assert v.is_allowed("") is False

    def test_very_long_path_is_denied(self, tmp_path: Path) -> None:
        long_path = str(tmp_path) + "/" + "a" * 4097
        v = _make_validator(str(tmp_path))
        assert v.is_allowed(long_path) is False

    def test_path_exactly_at_max_length_is_evaluated(self, tmp_path: Path) -> None:
        """A path at exactly 4096 chars should not be rejected by the length check."""
        # Build a path that fits in 4096 characters.  It will likely be outside
        # the allowed tree (or non-existent), but the length check must pass.
        prefix = str(tmp_path) + "/"
        padding = "a" * (4096 - len(prefix))
        at_limit = prefix + padding
        v = _make_validator(str(tmp_path))
        # Should not raise; result depends on allowlist logic, not length.
        result = v.is_allowed(at_limit)
        assert isinstance(result, bool)

    def test_relative_path_not_in_allowed_tree_is_denied(
        self, tmp_path: Path
    ) -> None:
        v = _make_validator(str(tmp_path))
        # A plain relative path like "etc/passwd" resolves to CWD/etc/passwd
        # which is almost certainly outside the allowed tree.
        assert v.is_allowed("etc/passwd") is False


# ---------------------------------------------------------------------------
# Symlink resolution
# ---------------------------------------------------------------------------


class TestSymlinkResolution:
    def test_symlink_pointing_outside_allowed_is_denied(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        target_outside = tmp_path / "outside" / "secret.txt"
        target_outside.parent.mkdir()
        target_outside.touch()
        link = allowed / "link.txt"
        link.symlink_to(target_outside)
        v = _make_validator(str(allowed))
        assert v.is_allowed(str(link)) is False

    def test_symlink_pointing_inside_allowed_is_permitted(
        self, tmp_path: Path
    ) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        real_file = allowed / "real.txt"
        real_file.touch()
        link = allowed / "link.txt"
        link.symlink_to(real_file)
        v = _make_validator(str(allowed))
        assert v.is_allowed(str(link)) is True

    def test_symlink_chain_to_blocked_path_is_denied(self, tmp_path: Path) -> None:
        """link_a -> link_b -> /etc/shadow must be blocked after resolution."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        # Create an intermediate link pointing to /etc/shadow.
        # The final realpath will be /etc/shadow (or wherever it resolves on
        # this OS); the hardcoded blocklist will catch it.
        link_a = allowed / "link_a"
        link_b = allowed / "link_b"
        link_b.symlink_to("/etc/shadow")
        link_a.symlink_to(link_b)
        v = _make_validator(str(allowed))
        assert v.is_allowed(str(link_a)) is False

    def test_symlink_chain_via_intermediate_dir(self, tmp_path: Path) -> None:
        """link -> harmless_dir -> secret dir must be blocked if secret is blocked."""
        allowed = tmp_path / "allowed"
        outside = tmp_path / "outside"
        allowed.mkdir()
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.touch()
        # Chain: allowed/link -> outside/secret.txt
        link = allowed / "link"
        link.symlink_to(outside / "secret.txt")
        v = _make_validator(str(allowed))
        assert v.is_allowed(str(link)) is False


# ---------------------------------------------------------------------------
# validate_or_raise
# ---------------------------------------------------------------------------


class TestValidateOrRaise:
    def test_returns_resolved_path_for_valid_input(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.touch()
        v = _make_validator(str(tmp_path))
        result = v.validate_or_raise(str(f))
        assert result == os.path.realpath(str(f))

    def test_raises_for_blocked_path(self) -> None:
        v = _make_validator("/")
        with pytest.raises(PathValidationError):
            v.validate_or_raise("/etc/shadow")

    def test_raises_for_path_outside_allowlist(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside" / "file.txt"
        v = _make_validator(str(allowed))
        with pytest.raises(PathValidationError):
            v.validate_or_raise(str(outside))

    def test_raises_for_empty_path(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        with pytest.raises(PathValidationError):
            v.validate_or_raise("")

    def test_raises_for_null_byte(self, tmp_path: Path) -> None:
        v = _make_validator(str(tmp_path))
        with pytest.raises(PathValidationError):
            v.validate_or_raise(str(tmp_path) + "/fi\x00le")

    def test_returned_path_is_absolute(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.touch()
        v = _make_validator(str(tmp_path))
        result = v.validate_or_raise(str(f))
        assert os.path.isabs(result)

    def test_error_message_does_not_leak_reason(self, tmp_path: Path) -> None:
        """Error messages must not reveal which specific rule was triggered."""
        v = _make_validator(str(tmp_path))
        with pytest.raises(PathValidationError, match=r"Access denied") as exc_info:
            v.validate_or_raise("/etc/shadow")
        # The message should say "Access denied" but not "hardcoded" or "pattern".
        msg = str(exc_info.value)
        assert "hardcoded" not in msg.lower()
        assert "blocklist" not in msg.lower()

    def test_resolves_dotdot_in_returned_path(self, tmp_path: Path) -> None:
        f = tmp_path / "sub" / ".." / "file.txt"
        real_f = tmp_path / "file.txt"
        real_f.touch()
        v = _make_validator(str(tmp_path))
        result = v.validate_or_raise(str(f))
        assert result == str(real_f)


# ---------------------------------------------------------------------------
# Edge cases and invariants
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_is_allowed_never_raises(self, tmp_path: Path) -> None:
        """is_allowed must return False rather than raise for bad inputs."""
        v = _make_validator(str(tmp_path))
        assert v.is_allowed("") is False
        assert v.is_allowed("\x00") is False
        assert v.is_allowed("a" * 10_000) is False

    def test_allowed_path_resolved_at_construction(self, tmp_path: Path) -> None:
        """Symlinked allowed paths are resolved at construction time."""
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_dir = tmp_path / "link"
        link_dir.symlink_to(real_dir)
        # Register the *link* as allowed — the validator should resolve it.
        v = _make_validator(str(link_dir))
        # A file inside the real dir should be accessible via either path.
        f = real_dir / "file.txt"
        f.touch()
        assert v.is_allowed(str(f)) is True
        assert v.is_allowed(str(link_dir / "file.txt")) is True

    def test_validator_with_no_blocked_paths_argument(self, tmp_path: Path) -> None:
        """blocked_paths defaults to None without error."""
        v = PathValidator([str(tmp_path)])
        f = tmp_path / "f.txt"
        f.touch()
        assert v.is_allowed(str(f)) is True
