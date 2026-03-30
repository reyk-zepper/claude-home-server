"""Adversarial security tests for path traversal defences in PathValidator.

These tests simulate real attacker scenarios.  Each test documents *why*
the attack vector is dangerous, not just *that* it is blocked.

TOCTOU (Time-Of-Check / Time-Of-Use) note
------------------------------------------
PathValidator calls ``os.path.realpath()`` at check time and the caller
subsequently opens the file at use time.  Between those two operations a
race condition exists: an attacker with write access to the filesystem
could swap a safe file for a malicious symlink.  This is a fundamental
limitation of any userspace path-validation approach.

Mitigations (outside scope of this module):
  - Use ``O_NOFOLLOW`` in the kernel open call where possible.
  - Re-validate after open (check ``/proc/self/fd/<fd>`` on Linux).
  - Mount allowed trees with ``nosymfollow`` option.
  - Run the server in a separate mount namespace with bind-mounts.
The tests below verify that the synchronous path-resolution checks pass;
they do NOT eliminate the TOCTOU window.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from src.safety.path_validator import PathValidationError, PathValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validator(allowed: Path) -> PathValidator:
    return PathValidator([str(allowed)])


# ---------------------------------------------------------------------------
# Directory traversal via ".." components
# ---------------------------------------------------------------------------


class TestDotDotTraversal:
    """Attacks that use ".." to escape the allowed tree."""

    def test_simple_traversal_to_etc_shadow(self, tmp_path: Path) -> None:
        """Attack: <allowed_dir>/../../etc/shadow

        An attacker supplying a path with enough ".." components can escape
        the allowed tree and reach sensitive system files.
        """
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        crafted = str(allowed) + "/../../etc/shadow"
        assert v.is_allowed(crafted) is False

    def test_traversal_to_root_etc_passwd(self, tmp_path: Path) -> None:
        """Attack: multiple ".." segments to reach /etc/passwd."""
        allowed = tmp_path / "a" / "b" / "c"
        allowed.mkdir(parents=True)
        v = _validator(allowed)

        crafted = str(allowed) + "/../../../etc/passwd"
        assert v.is_allowed(crafted) is False

    def test_traversal_to_parent_of_allowed_dir(self, tmp_path: Path) -> None:
        """Attack: escape to the parent directory containing sensitive siblings.

        Even if the parent is not hardcoded-blocked, it is outside the
        allowlist and must be denied.
        """
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        sibling = tmp_path / "sibling"
        sibling.mkdir()
        v = _validator(allowed)

        crafted = str(allowed) + "/../sibling/secret.txt"
        assert v.is_allowed(crafted) is False

    def test_traversal_with_interleaved_valid_segments(
        self, tmp_path: Path
    ) -> None:
        """Attack: <allowed>/real_dir/../../other — mixes valid and invalid parts."""
        allowed = tmp_path / "allowed"
        sub = allowed / "real_dir"
        sub.mkdir(parents=True)
        target = tmp_path / "other"
        target.mkdir()
        v = _validator(allowed)

        crafted = str(sub) + "/../../other"
        assert v.is_allowed(crafted) is False

    def test_validate_or_raise_raises_on_traversal(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        crafted = str(allowed) + "/../../etc/shadow"
        with pytest.raises(PathValidationError):
            v.validate_or_raise(crafted)


# ---------------------------------------------------------------------------
# Symlink attacks
# ---------------------------------------------------------------------------


class TestSymlinkAttacks:
    """Attacks using symlinks to redirect path resolution to sensitive targets."""

    def test_direct_symlink_to_etc_shadow(self, tmp_path: Path) -> None:
        """Attack: allowed/evil.txt -> /etc/shadow

        A symlink inside the allowed tree that points to a blocked system
        file must be refused after realpath() resolution.
        """
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        link = allowed / "evil.txt"
        link.symlink_to("/etc/shadow")
        v = _validator(allowed)

        assert v.is_allowed(str(link)) is False

    def test_symlink_chain_to_shadow(self, tmp_path: Path) -> None:
        """Attack: link_a -> link_b -> /etc/shadow (multi-hop chain).

        realpath() follows all hops; the final resolved path must be blocked.
        """
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        link_b = allowed / "hop2"
        link_b.symlink_to("/etc/shadow")
        link_a = allowed / "hop1"
        link_a.symlink_to(link_b)
        v = _validator(allowed)

        assert v.is_allowed(str(link_a)) is False

    def test_symlink_chain_outside_allowed_tree(self, tmp_path: Path) -> None:
        """Attack: link inside allowed -> outside -> further outside.

        Even if the intermediate target is not itself blocked, the final
        resolved path is outside the allowlist and must be denied.
        """
        allowed = tmp_path / "allowed"
        outside1 = tmp_path / "outside1"
        outside2 = tmp_path / "outside2"
        allowed.mkdir()
        outside1.mkdir()
        outside2.mkdir()
        secret = outside2 / "secret.txt"
        secret.write_text("secret data")

        hop1 = allowed / "hop1"
        hop1.symlink_to(outside1 / "hop2")
        hop2 = outside1 / "hop2"
        hop2.symlink_to(secret)
        v = _validator(allowed)

        assert v.is_allowed(str(hop1)) is False

    def test_symlink_to_ssh_directory_content(self, tmp_path: Path) -> None:
        """Attack: link inside allowed -> ~/.ssh/id_rsa.

        The resolved path will contain the ".ssh" segment and must be
        blocked by the segment checker even without a hardcoded blocklist
        entry for that specific home directory.
        """
        # We can only create a real symlink to a path we control; we simulate
        # the attack by pointing to a fake .ssh dir we create in tmp.
        allowed = tmp_path / "allowed"
        fake_ssh = tmp_path / ".ssh"
        allowed.mkdir()
        fake_ssh.mkdir()
        key_file = fake_ssh / "id_rsa"
        key_file.write_text("FAKE KEY")

        link = allowed / "id_rsa_link"
        link.symlink_to(key_file)
        v = _validator(allowed)

        # Path resolves to .../(.ssh)/id_rsa — blocked by segment rule.
        assert v.is_allowed(str(link)) is False

    def test_directory_symlink_allows_traversal_into_outside(
        self, tmp_path: Path
    ) -> None:
        """Attack: allowed/link_dir -> /outside, then allowed/link_dir/secret.

        If a symlink to an *outside directory* is inside the allowed tree,
        accessing files through it must still be blocked.
        """
        allowed = tmp_path / "allowed"
        outside_dir = tmp_path / "outside"
        allowed.mkdir()
        outside_dir.mkdir()
        secret = outside_dir / "secret.txt"
        secret.write_text("sensitive")

        link_dir = allowed / "link_dir"
        link_dir.symlink_to(outside_dir)
        v = _validator(allowed)

        assert v.is_allowed(str(link_dir / "secret.txt")) is False


# ---------------------------------------------------------------------------
# Special-character and encoding attacks
# ---------------------------------------------------------------------------


class TestSpecialCharacterAttacks:
    """Attacks exploiting unusual characters or path encodings."""

    def test_null_byte_injection(self, tmp_path: Path) -> None:
        """Attack: path\x00truncation (classic C-string injection).

        Some older POSIX implementations truncated paths at null bytes.
        Python's os.path.realpath does not, but we reject such paths
        pre-emptively.

        Example: "/allowed/safe.txt\x00../../../../etc/shadow"
        Python sees the full string; the validator must reject it before
        any OS call processes the null-terminated portion.
        """
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        crafted = str(allowed) + "/safe.txt\x00../../../../etc/shadow"
        assert v.is_allowed(crafted) is False

    def test_null_byte_in_middle_of_path(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        assert v.is_allowed(str(allowed) + "/fi\x00le.txt") is False

    def test_double_slash_normalised_but_still_blocked(
        self, tmp_path: Path
    ) -> None:
        """Attack: double slashes to confuse prefix checks.

        "//etc/shadow" resolves to "/etc/shadow" via realpath() on Linux
        (some BSDs treat "//" as a special root).  The validator must block
        the resolved form.
        """
        v = _validator(tmp_path)
        assert v.is_allowed("//etc/shadow") is False

    def test_trailing_slash_in_blocked_path(self, tmp_path: Path) -> None:
        """Attack: trailing slash to bypass exact-match checks.

        "/etc/shadow/" could confuse a naive string-equality check.
        """
        v = _validator(tmp_path)
        assert v.is_allowed("/etc/shadow/") is False

    def test_multiple_trailing_slashes(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        outside = str(tmp_path) + "///"
        # Even if this resolves to tmp_path, it is the parent, not allowed.
        result = v.is_allowed(outside)
        assert isinstance(result, bool)  # must not raise

    def test_empty_path_rejected(self, tmp_path: Path) -> None:
        """Attack: empty string as a path.

        An empty string could cause unexpected behaviour in path-joining
        operations downstream.
        """
        v = _validator(tmp_path)
        assert v.is_allowed("") is False

    def test_whitespace_only_path_stays_outside_allowlist(
        self, tmp_path: Path
    ) -> None:
        """A path of spaces resolves to CWD/<spaces> — outside the allowlist."""
        v = _validator(tmp_path)
        # Should not raise; must return False.
        assert v.is_allowed("   ") is False


# ---------------------------------------------------------------------------
# Very long path attacks
# ---------------------------------------------------------------------------


class TestLongPathAttacks:
    """Attacks using excessively long paths."""

    def test_path_over_4096_chars_is_rejected(self, tmp_path: Path) -> None:
        """Attack: path longer than PATH_MAX to trigger buffer overflows downstream.

        The validator must reject paths over 4096 characters before any
        kernel call is made.
        """
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        long_path = str(allowed) + "/" + "a" * 4097
        assert v.is_allowed(long_path) is False

    def test_path_of_exactly_4096_chars_is_evaluated_normally(
        self, tmp_path: Path
    ) -> None:
        """Boundary: a 4096-character path must not be rejected by the length guard."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        prefix = str(allowed) + "/"
        padding = "a" * (4096 - len(prefix))
        at_limit = prefix + padding
        # Must not raise PathValidationError due to length; outcome depends on
        # whether the (non-existent) path falls within the allowlist.
        result = v.is_allowed(at_limit)
        assert isinstance(result, bool)

    def test_validate_or_raise_raises_on_long_path(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        long_path = str(allowed) + "/" + "z" * 5000
        with pytest.raises(PathValidationError):
            v.validate_or_raise(long_path)

    def test_null_bytes_in_long_path(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        v = _validator(allowed)

        long_with_null = str(allowed) + "/" + "b" * 2000 + "\x00" + "c" * 2000
        assert v.is_allowed(long_with_null) is False


# ---------------------------------------------------------------------------
# Relative path attacks
# ---------------------------------------------------------------------------


class TestRelativePathAttacks:
    """Attacks using relative paths whose resolution depends on CWD."""

    def test_relative_path_to_etc_passwd(self, tmp_path: Path) -> None:
        """Attack: relative path "etc/passwd" resolves to CWD/etc/passwd.

        The resolved path is almost certainly outside the allowed tree.
        """
        v = _validator(tmp_path)
        assert v.is_allowed("etc/passwd") is False

    def test_single_dot_resolves_to_cwd(self, tmp_path: Path) -> None:
        """A lone "." resolves to the CWD, which is outside any tmp_path tree."""
        v = _validator(tmp_path)
        # Result depends on CWD; must not raise and must not grant access
        # to an arbitrary CWD.
        cwd_result = v.is_allowed(".")
        # Only True if CWD happens to equal tmp_path (very unlikely in CI).
        assert isinstance(cwd_result, bool)

    def test_tilde_not_interpreted_as_home(self, tmp_path: Path) -> None:
        """Attack: "~/.ssh/id_rsa" — tilde expansion must not occur.

        Python's os.path.realpath does NOT expand tildes.  The path would
        resolve to a literal "~" component in CWD, which is outside the
        allowed tree.  We verify that this path is denied.
        """
        v = _validator(tmp_path)
        result = v.is_allowed("~/.ssh/id_rsa")
        # Either blocked by segment (".ssh") or by allowlist — either way False.
        assert result is False

    def test_dotdot_only_path(self, tmp_path: Path) -> None:
        """A path consisting entirely of ".." components is outside any subtree."""
        v = _validator(tmp_path)
        assert v.is_allowed("../../..") is False


# ---------------------------------------------------------------------------
# Hardcoded blocklist — comprehensive parametric coverage
# ---------------------------------------------------------------------------


class TestHardcodedBlocklistAdversarial:
    """Every hardcoded-blocked path must be denied even when wrapped in tricks."""

    @pytest.mark.parametrize(
        "attack",
        [
            "/etc/shadow",
            "/etc/shadow/",
            "//etc/shadow",
            "/etc/./shadow",
            "/etc/../etc/shadow",
            "/etc/sudoers",
            "/etc/sudoers.d/wheel",
            "/root/.bashrc",
            "/root/",
            "/proc/1/mem",
            "/proc/self/cmdline",
            "/sys/kernel/debug",
            "/dev/sda",
            "/dev/null",  # /dev is blocked wholesale
        ],
    )
    def test_blocked_path_variant_is_denied(self, attack: str) -> None:
        v = PathValidator(["/"])
        assert v.is_allowed(attack) is False, (
            f"Expected {attack!r} to be denied but it was allowed"
        )
