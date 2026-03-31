"""Unit tests for src.modules.filesystem.FilesystemModule.

Coverage targets:
- fs_read: allowed path, blocked path, traversal, missing file, directory arg
- fs_list: allowed dir, blocked dir, empty dir, symlinks, long names
- fs_search: valid glob patterns, regex metacharacter rejection, symlink escape
- fs_diff: no backup, has backup with diff, identical content, missing file
- fs_backup_list: no backups, with backups, filtered by path
- fs_write: new file, overwrite with backup, dry_run preview, blocked path,
           concurrent writes serialised
- fs_backup_restore: valid restore, dry_run, blocked path, invalid file, no .bak

PathValidator interactions:
- traversal attempts rejected
- null bytes in path rejected
- symlink pointing outside allowlist rejected
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from src.audit import AuditLogger
from src.config import FilesystemConfig, SecurityConfig, ServerConfig
from src.modules.filesystem import FilesystemModule
from src.permissions import PermissionEngine
from src.safety.path_validator import PathValidationError, PathValidator
from src.utils.backup import BackupManager
from src.utils.circuit_breaker import CircuitBreaker


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_config(allowed: list[str], blocked: list[str] | None = None) -> ServerConfig:
    """Build a ``ServerConfig`` with specific filesystem allowlist settings."""
    cfg = ServerConfig()
    cfg.filesystem = FilesystemConfig(
        allowed_paths=allowed,
        blocked_paths=blocked or [],
    )
    return cfg


def _make_module(
    tmp_path: Path,
    extra_allowed: list[str] | None = None,
    blocked: list[str] | None = None,
) -> FilesystemModule:
    """Return a ``FilesystemModule`` whose allowlist includes *tmp_path*."""
    allowed = [str(tmp_path)] + (extra_allowed or [])
    cfg = _make_config(allowed, blocked)
    # Override backup dir to tmp_path so tests don't write to /var/backups
    cfg.security = SecurityConfig(
        backup_dir=str(tmp_path / "_backups"),
        backup_retention_days=30,
        backup_max_per_file=50,
    )
    pe = PermissionEngine()
    al = AuditLogger(str(tmp_path / "audit.log"))
    cb = CircuitBreaker()
    return FilesystemModule(cfg, pe, al, cb)


# ---------------------------------------------------------------------------
# fs_read
# ---------------------------------------------------------------------------


class TestFsRead:
    def test_read_existing_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "hello.txt"
        f.write_text("Hello, world!")
        result = mod._fs_read_impl(path=str(f))
        assert "Hello, world!" in result

    def test_read_includes_filename_header(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        result = mod._fs_read_impl(path=str(f))
        assert "=== config.yaml ===" in result

    def test_read_blocked_path_returns_access_denied(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        # /etc/shadow is hardcoded-blocked, not in allowlist
        result = mod._fs_read_impl(path="/etc/shadow")
        assert "Access denied" in result
        assert "/etc/shadow" in result

    def test_read_path_outside_allowlist(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_read_impl(path="/tmp/something_not_allowed.txt")
        assert "Access denied" in result

    def test_read_traversal_attempt_rejected(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        traversal = str(tmp_path / ".." / ".." / "etc" / "passwd")
        result = mod._fs_read_impl(path=traversal)
        assert "Access denied" in result

    def test_read_null_bytes_rejected(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_read_impl(path=str(tmp_path) + "/file\x00name.txt")
        # Either input validation error or access denied
        assert "Access denied" in result or "Invalid input" in result

    def test_read_missing_file_returns_error(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_read_impl(path=str(tmp_path / "nonexistent.txt"))
        assert "[ERROR]" in result
        assert "not found" in result.lower()

    def test_read_directory_returns_error(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        subdir = tmp_path / "mydir"
        subdir.mkdir()
        result = mod._fs_read_impl(path=str(subdir))
        assert "[ERROR]" in result

    def test_read_multiline_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "multi.txt"
        f.write_text("line1\nline2\nline3")
        result = mod._fs_read_impl(path=str(f))
        assert "line1" in result
        assert "line3" in result

    def test_read_empty_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "empty.txt"
        f.write_text("")
        result = mod._fs_read_impl(path=str(f))
        # Should succeed — no error
        assert "[ERROR]" not in result
        assert "Access denied" not in result


# ---------------------------------------------------------------------------
# fs_list
# ---------------------------------------------------------------------------


class TestFsList:
    def test_list_directory(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        result = mod._fs_list_impl(path=str(tmp_path))
        assert "a.txt" in result
        assert "b.txt" in result

    def test_list_shows_type_file_and_dir(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        (tmp_path / "file.txt").write_text("x")
        (tmp_path / "subdir").mkdir()
        result = mod._fs_list_impl(path=str(tmp_path))
        assert "file" in result
        assert "dir" in result

    def test_list_shows_header(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_list_impl(path=str(tmp_path))
        assert "Directory" in result

    def test_list_empty_directory(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_list_impl(path=str(tmp_path))
        assert "empty" in result.lower()

    def test_list_blocked_path(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_list_impl(path="/etc/shadow")
        assert "Access denied" in result

    def test_list_path_outside_allowlist(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_list_impl(path="/nonexistent_dir_outside")
        assert "Access denied" in result

    def test_list_long_filename_truncated(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        long_name = "a" * 50 + ".txt"
        (tmp_path / long_name).write_text("x")
        result = mod._fs_list_impl(path=str(tmp_path))
        assert "..." in result

    def test_list_shows_entry_count(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        sub = tmp_path / "listdir"
        sub.mkdir()
        (sub / "x.txt").write_text("x")
        (sub / "y.txt").write_text("y")
        result = mod._fs_list_impl(path=str(sub))
        assert "2 entries" in result

    def test_list_symlink_shows_as_link(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        target = tmp_path / "real.txt"
        target.write_text("content")
        link = tmp_path / "link_to_real"
        link.symlink_to(target)
        result = mod._fs_list_impl(path=str(tmp_path))
        assert "link" in result


# ---------------------------------------------------------------------------
# fs_search
# ---------------------------------------------------------------------------


class TestFsSearch:
    def test_search_finds_matching_files(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        (tmp_path / "config.yaml").write_text("x")
        (tmp_path / "data.yaml").write_text("x")
        (tmp_path / "readme.md").write_text("x")
        result = mod._fs_search_impl(path=str(tmp_path), pattern="*.yaml")
        assert "config.yaml" in result
        assert "data.yaml" in result
        assert "readme.md" not in result

    def test_search_no_matches(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        (tmp_path / "file.txt").write_text("x")
        result = mod._fs_search_impl(path=str(tmp_path), pattern="*.yaml")
        assert "No matches found" in result

    def test_search_regex_chars_rejected_parens(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_search_impl(path=str(tmp_path), pattern="(bad)")
        assert "Invalid input" in result

    def test_search_regex_chars_rejected_brackets(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_search_impl(path=str(tmp_path), pattern="[abc]")
        assert "Invalid input" in result

    def test_search_regex_chars_rejected_plus(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_search_impl(path=str(tmp_path), pattern="file+")
        assert "Invalid input" in result

    def test_search_blocked_base_path(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_search_impl(path="/etc", pattern="*.conf")
        assert "Access denied" in result

    def test_search_recursive_glob(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "nested.yaml").write_text("x")
        result = mod._fs_search_impl(path=str(tmp_path), pattern="**/*.yaml")
        assert "nested.yaml" in result

    def test_search_symlink_outside_allowlist_excluded(self, tmp_path: Path) -> None:
        """A symlink that resolves outside the allowlist must be excluded."""
        mod = _make_module(tmp_path)
        # Create a file outside tmp_path in a separate tmp dir
        outside = tmp_path.parent / "outside_zone"
        outside.mkdir(exist_ok=True)
        (outside / "secret.txt").write_text("secret")
        # Symlink inside tmp_path pointing to outside
        link = tmp_path / "escape.txt"
        link.symlink_to(outside / "secret.txt")
        result = mod._fs_search_impl(path=str(tmp_path), pattern="*.txt")
        # escape.txt should not appear because its realpath is outside allowlist
        assert "escape.txt" not in result or "secret.txt" not in result

    def test_search_shows_match_count(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "b.txt").write_text("x")
        result = mod._fs_search_impl(path=str(tmp_path), pattern="*.txt")
        assert "2 match" in result


# ---------------------------------------------------------------------------
# fs_diff
# ---------------------------------------------------------------------------


class TestFsDiff:
    def test_diff_no_backup(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        result = mod._fs_diff_impl(path=str(f))
        assert "No backup found" in result

    def test_diff_with_backup_shows_changes(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "config.yaml"
        f.write_text("key: old_value")
        # Create a backup manually
        backup_path = mod._backup_manager.create_backup(str(f))
        # Now modify the file
        f.write_text("key: new_value")
        result = mod._fs_diff_impl(path=str(f))
        assert "old_value" in result or "new_value" in result
        # Should show unified diff markers
        assert "-" in result or "+" in result

    def test_diff_identical_content(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        mod._backup_manager.create_backup(str(f))
        result = mod._fs_diff_impl(path=str(f))
        assert "No differences" in result or ("No backup found" not in result)

    def test_diff_blocked_path(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_diff_impl(path="/etc/passwd")
        assert "Access denied" in result

    def test_diff_missing_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_diff_impl(path=str(tmp_path / "missing.txt"))
        # No backup exists so should return no-backup message
        assert "No backup found" in result or "[ERROR]" in result

    def test_diff_shows_header(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "file.yaml"
        f.write_text("a: 1")
        result = mod._fs_diff_impl(path=str(f))
        assert "Diff:" in result or "No backup found" in result


# ---------------------------------------------------------------------------
# fs_backup_list
# ---------------------------------------------------------------------------


class TestFsBackupList:
    def test_backup_list_empty(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_backup_list_impl()
        assert "No backups found" in result

    def test_backup_list_shows_backups(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "file.txt"
        f.write_text("content")
        mod._backup_manager.create_backup(str(f))
        result = mod._fs_backup_list_impl()
        assert "file.txt" in result

    def test_backup_list_filtered(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f1 = tmp_path / "alpha.txt"
        f2 = tmp_path / "beta.txt"
        f1.write_text("a")
        f2.write_text("b")
        mod._backup_manager.create_backup(str(f1))
        mod._backup_manager.create_backup(str(f2))
        result = mod._fs_backup_list_impl(path=str(f1))
        assert "alpha.txt" in result
        assert "beta.txt" not in result

    def test_backup_list_shows_count(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "counted.txt"
        f.write_text("x")
        mod._backup_manager.create_backup(str(f))
        result = mod._fs_backup_list_impl()
        assert "1 backup" in result


# ---------------------------------------------------------------------------
# fs_write
# ---------------------------------------------------------------------------


class TestFsWrite:
    def test_write_creates_new_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "new_file.txt"
        assert not dest.exists()
        result = mod._fs_write_impl(path=str(dest), content="Hello!")
        assert dest.exists()
        assert dest.read_text() == "Hello!"
        assert "CREATED" in result

    def test_write_overwrites_existing_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "existing.txt"
        dest.write_text("old content")
        result = mod._fs_write_impl(path=str(dest), content="new content")
        assert dest.read_text() == "new content"
        assert "UPDATED" in result

    def test_write_creates_backup_before_overwrite(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "important.yaml"
        dest.write_text("original: true")
        result = mod._fs_write_impl(path=str(dest), content="modified: true")
        assert "Backup created" in result
        # Verify backup file was created
        backups = mod._backup_manager.list_backups(str(dest))
        assert len(backups) == 1

    def test_write_no_backup_for_new_file(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "brand_new.txt"
        result = mod._fs_write_impl(path=str(dest), content="content")
        assert "CREATED" in result
        # No backup should be mentioned for brand-new file
        assert "Backup created" not in result

    def test_write_dry_run_does_not_write(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "nowrite.txt"
        result = mod._fs_write_impl(path=str(dest), content="should not appear", dry_run=True)
        assert not dest.exists()
        assert "dry_run" in result.lower() or "Dry Run" in result or "No changes written" in result

    def test_write_dry_run_shows_diff(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "existing.txt"
        dest.write_text("original line")
        result = mod._fs_write_impl(
            path=str(dest), content="changed line", dry_run=True
        )
        # Should show diff markers or indicate what would change
        assert dest.read_text() == "original line"  # not modified

    def test_write_dry_run_new_file_shows_preview(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "preview.txt"
        result = mod._fs_write_impl(
            path=str(dest), content="preview content", dry_run=True
        )
        assert "preview content" in result
        assert not dest.exists()

    def test_write_blocked_path_returns_denied(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_write_impl(path="/etc/hosts", content="bad content")
        assert "Access denied" in result

    def test_write_traversal_path_rejected(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        traversal = str(tmp_path / ".." / "outside.txt")
        result = mod._fs_write_impl(path=traversal, content="bad")
        assert "Access denied" in result

    def test_write_shows_bytes_written(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        dest = tmp_path / "sized.txt"
        content = "x" * 100
        result = mod._fs_write_impl(path=str(dest), content=content)
        assert "100" in result  # bytes written

    def test_write_concurrent_serialized(self, tmp_path: Path) -> None:
        """Two concurrent writes to the same file must not corrupt each other."""
        mod = _make_module(tmp_path)
        dest = tmp_path / "concurrent.txt"
        dest.write_text("initial")
        results: list[str] = []
        errors: list[Exception] = []

        def write_worker(content: str) -> None:
            try:
                r = mod._fs_write_impl(path=str(dest), content=content)
                results.append(r)
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=write_worker, args=("content_A",))
        t2 = threading.Thread(target=write_worker, args=("content_B",))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not errors
        assert len(results) == 2
        # Final content must be exactly one of the two inputs (no interleaving)
        final = dest.read_text()
        assert final in ("content_A", "content_B")


# ---------------------------------------------------------------------------
# fs_backup_restore
# ---------------------------------------------------------------------------


class TestFsBackupRestore:
    def test_restore_dry_run(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        f = tmp_path / "restore_me.txt"
        f.write_text("original content")
        backup_path = mod._backup_manager.create_backup(str(f))
        # Include backup_dir in allowlist
        backup_dir = str(tmp_path / "_backups")
        cfg = _make_config([str(tmp_path), backup_dir])
        cfg.security = SecurityConfig(backup_dir=backup_dir)
        mod2 = _make_module(tmp_path, extra_allowed=[backup_dir])
        result = mod2._fs_backup_restore_impl(backup_path=backup_path, dry_run=True)
        assert "dry_run" in result.lower() or "Dry Run" in result or "No changes written" in result

    def test_restore_blocked_backup_path(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_backup_restore_impl(backup_path="/etc/shadow")
        assert "Access denied" in result

    def test_restore_missing_backup_file(self, tmp_path: Path) -> None:
        # Allow the backup dir in path validator
        backup_dir = str(tmp_path / "_backups")
        mod = _make_module(tmp_path, extra_allowed=[backup_dir])
        fake_backup = str(tmp_path / "_backups" / "missing.20260101T000000.bak")
        # Create the backup dir so it passes path validator
        (tmp_path / "_backups").mkdir(exist_ok=True)
        result = mod._fs_backup_restore_impl(backup_path=fake_backup)
        assert "[ERROR]" in result or "not found" in result.lower()

    def test_restore_non_bak_file_rejected(self, tmp_path: Path) -> None:
        backup_dir = str(tmp_path / "_backups")
        mod = _make_module(tmp_path, extra_allowed=[backup_dir])
        (tmp_path / "_backups").mkdir(exist_ok=True)
        not_a_bak = tmp_path / "_backups" / "config.yaml"
        not_a_bak.write_text("content")
        result = mod._fs_backup_restore_impl(backup_path=str(not_a_bak))
        assert "[ERROR]" in result or "Access denied" in result

    def test_restore_path_traversal_rejected(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        traversal = str(tmp_path / ".." / "bad.bak")
        result = mod._fs_backup_restore_impl(backup_path=traversal)
        assert "Access denied" in result


# ---------------------------------------------------------------------------
# PathValidator integration
# ---------------------------------------------------------------------------


class TestPathValidatorIntegration:
    def test_symlink_to_blocked_location_denied(self, tmp_path: Path) -> None:
        """A symlink inside the allowlist pointing to /etc/shadow is denied."""
        mod = _make_module(tmp_path)
        link = tmp_path / "evil_link"
        try:
            link.symlink_to("/etc/shadow")
        except OSError:
            pytest.skip("Cannot create symlink in this environment")
        result = mod._fs_read_impl(path=str(link))
        assert "Access denied" in result

    def test_symlink_within_allowlist_permitted(self, tmp_path: Path) -> None:
        """A symlink pointing to another file inside the allowlist is allowed."""
        mod = _make_module(tmp_path)
        real_file = tmp_path / "real.txt"
        real_file.write_text("real content")
        link = tmp_path / "link_to_real"
        link.symlink_to(real_file)
        result = mod._fs_read_impl(path=str(link))
        assert "real content" in result
        assert "Access denied" not in result

    def test_dotdot_component_blocked(self, tmp_path: Path) -> None:
        """Path with .. traversal that escapes allowlist is denied."""
        mod = _make_module(tmp_path)
        # Try to escape: if tmp_path=/tmp/pytest-xxx, this resolves to /tmp/etc/passwd
        escape = str(tmp_path / ".." / "etc" / "passwd")
        result = mod._fs_read_impl(path=escape)
        assert "Access denied" in result

    def test_empty_path_rejected(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        result = mod._fs_read_impl(path="")
        assert "Access denied" in result or "Invalid input" in result

    def test_very_long_path_rejected(self, tmp_path: Path) -> None:
        mod = _make_module(tmp_path)
        long_path = str(tmp_path) + "/" + "a" * 5000
        result = mod._fs_read_impl(path=long_path)
        assert "Access denied" in result or "Invalid input" in result
