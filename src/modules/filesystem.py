"""Filesystem module — Claude's read/write interface to allowed paths.

Provides seven tools for safe filesystem access on the home server.  Every
single file operation passes through :class:`~src.safety.path_validator.PathValidator`
before any I/O occurs — there are no exceptions to this rule.

**Read tools (RiskLevel.READ)**

``fs_read``
    Read the full text content of a single file.

``fs_list``
    List the contents of a directory with name, type, size, and mtime.

``fs_search``
    Glob-based recursive file search under a validated base path.

``fs_diff``
    Unified diff between the current file and its most recent backup.

``fs_backup_list``
    List all available backup snapshots (optionally scoped to one file).

**Critical tools (RiskLevel.CRITICAL)**

``fs_write``
    Write new content to a file.  Always creates a backup first; supports
    ``dry_run`` to preview what would be written without touching disk.

``fs_backup_restore``
    Restore a file from a named backup snapshot.  Supports ``dry_run``.

Security invariants:
    * All paths are resolved via ``PathValidator.validate_or_raise`` before
      any I/O — symlink chains, ``..`` traversal, and null bytes are rejected.
    * ``PathValidationError`` is caught and surfaced as a user-friendly
      ``"Access denied: <path>"`` message; no internal detail is leaked.
    * :class:`~src.utils.backup.BackupManager` always runs
      ``create_backup()`` before ``fs_write`` overwrites an existing file.
    * ``fs_search`` validates every glob result individually to prevent
      symlink escapes from the allowlist.
"""

from __future__ import annotations

import difflib
import glob
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.modules.base import BaseModule
from src.safety.input_sanitizer import (
    FileBackupRestoreInput,
    FileDiffInput,
    FileListInput,
    FileReadInput,
    FileSearchInput,
    FileWriteInput,
)
from src.safety.path_validator import PathValidationError, PathValidator
from src.utils.backup import BackupManager

# Per-file write locks — prevents concurrent writes producing corrupt output.
_WRITE_LOCKS: dict[str, threading.Lock] = {}
_WRITE_LOCKS_META: threading.Lock = threading.Lock()


def _get_write_lock(resolved_path: str) -> threading.Lock:
    """Return (creating if needed) the per-file write lock for *resolved_path*.

    Args:
        resolved_path: The ``os.path.realpath``-resolved file path used as
            the lock key.

    Returns:
        A ``threading.Lock`` dedicated to that file path.
    """
    with _WRITE_LOCKS_META:
        if resolved_path not in _WRITE_LOCKS:
            _WRITE_LOCKS[resolved_path] = threading.Lock()
        return _WRITE_LOCKS[resolved_path]


class FilesystemModule(BaseModule):
    """Filesystem module providing safe file read/write/search/diff tools.

    This is the most security-critical module in the server.  Every operation
    is gated through :class:`~src.safety.path_validator.PathValidator` so that
    symlinks, path traversal, and blocked locations are never reachable.

    Registered tools:

    * ``fs_read`` — read file content.
    * ``fs_list`` — directory listing.
    * ``fs_search`` — glob-based file search.
    * ``fs_diff`` — current-vs-backup unified diff.
    * ``fs_backup_list`` — enumerate backup snapshots.
    * ``fs_write`` — write file with automatic pre-write backup.
    * ``fs_backup_restore`` — restore from a named backup snapshot.
    """

    MODULE_NAME = "filesystem"

    def __init__(
        self,
        config: Any,
        permission_engine: Any,
        audit_logger: Any,
        circuit_breaker: Any = None,
    ) -> None:
        super().__init__(config, permission_engine, audit_logger, circuit_breaker)
        self._path_validator = PathValidator(
            allowed_paths=config.filesystem.allowed_paths,
            blocked_paths=config.filesystem.blocked_paths,
        )
        self._backup_manager = BackupManager(
            backup_dir=config.security.backup_dir,
            retention_days=config.security.backup_retention_days,
            max_per_file=config.security.backup_max_per_file,
        )

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def _register_tools(self) -> None:
        """Register all seven filesystem tools on the module server."""
        self._register_tool(
            "fs_read",
            self._fs_read_impl,
            (
                "Read the text content of a file. "
                "The path must be within the configured allowed_paths. "
                "Returns the file content as a string, or an access-denied "
                "message when the path is outside the allowlist."
            ),
        )
        self._register_tool(
            "fs_list",
            self._fs_list_impl,
            (
                "List the contents of a directory. "
                "Returns a formatted table with name, type (file/dir), "
                "size in bytes, and last-modified timestamp for each entry."
            ),
        )
        self._register_tool(
            "fs_search",
            self._fs_search_impl,
            (
                "Search for files using a glob pattern under a base path. "
                "Only glob wildcards (* and ?) are supported — regex metacharacters "
                "are rejected. Every result path is individually validated against "
                "the allowlist so symlink escapes are blocked."
            ),
        )
        self._register_tool(
            "fs_diff",
            self._fs_diff_impl,
            (
                "Show a unified diff between the current file and its most recent "
                "backup snapshot. Returns 'No backup found' when no backup exists."
            ),
        )
        self._register_tool(
            "fs_backup_list",
            self._fs_backup_list_impl,
            (
                "List all available backup snapshots. "
                "Optionally scope the listing to a specific original file by "
                "passing its path. Returns backup path, original name, "
                "creation timestamp, and size."
            ),
        )
        self._register_tool(
            "fs_write",
            self._fs_write_impl,
            (
                "Write content to a file. "
                "CRITICAL: Always creates a backup of the existing file first. "
                "Pass dry_run=true to preview changes without modifying disk. "
                "The path must be within the configured allowed_paths."
            ),
        )
        self._register_tool(
            "fs_backup_restore",
            self._fs_backup_restore_impl,
            (
                "Restore a file from a backup snapshot. "
                "CRITICAL: Overwrites the target file with backup content. "
                "Pass dry_run=true to preview what would be restored."
            ),
        )

    # ------------------------------------------------------------------
    # READ tool implementations
    # ------------------------------------------------------------------

    def _fs_read_impl(self, path: str) -> str:
        """Read and return the content of a validated file.

        Args:
            path: Path to the file to read.

        Returns:
            File content as a string, or ``"Access denied: <path>"`` when the
            path is outside the allowlist or blocked.
        """
        # Input model validation (null bytes, length)
        try:
            validated_input = FileReadInput(path=path)
        except Exception as exc:
            return f"Invalid input: {exc}"

        # Security boundary — every file op MUST call validate_or_raise
        try:
            real_path = self._path_validator.validate_or_raise(validated_input.path)
        except PathValidationError:
            return f"Access denied: {path}"

        try:
            with open(real_path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except IsADirectoryError:
            return f"[ERROR] Path is a directory, not a file: {path}"
        except FileNotFoundError:
            return f"[ERROR] File not found: {path}"
        except PermissionError:
            return f"[ERROR] Permission denied reading: {path}"
        except OSError as exc:
            return f"[ERROR] Could not read file: {exc}"

        header = f"=== {Path(real_path).name} ==="
        return f"{header}\n{content}"

    def _fs_list_impl(self, path: str) -> str:
        """List directory contents as a formatted table.

        Args:
            path: Path to the directory to list.

        Returns:
            Formatted table of directory entries, or an error/denied message.
        """
        try:
            validated_input = FileListInput(path=path)
        except Exception as exc:
            return f"Invalid input: {exc}"

        try:
            real_path = self._path_validator.validate_or_raise(validated_input.path)
        except PathValidationError:
            return f"Access denied: {path}"

        try:
            entries = list(os.scandir(real_path))
        except NotADirectoryError:
            return f"[ERROR] Path is a file, not a directory: {path}"
        except FileNotFoundError:
            return f"[ERROR] Directory not found: {path}"
        except PermissionError:
            return f"[ERROR] Permission denied listing: {path}"
        except OSError as exc:
            return f"[ERROR] Could not list directory: {exc}"

        if not entries:
            return f"=== Directory: {path} ===\n(empty)"

        lines = [
            f"=== Directory: {path} ===",
            f"{'NAME':<40} {'TYPE':<6} {'SIZE':>12} {'MODIFIED':<20}",
            "-" * 82,
        ]

        # Sort: directories first, then files, both alphabetically
        entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))

        visible_count = 0
        for entry in entries:
            # Filter out entries whose resolved path is outside the allowlist
            # to prevent metadata leakage through symlinks pointing to
            # sensitive locations.
            entry_path = os.path.join(real_path, entry.name)
            if entry.is_symlink() and not self._path_validator.is_allowed(entry_path):
                continue

            try:
                stat = entry.stat(follow_symlinks=False)
                size = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except OSError:
                size = 0
                mtime = "unknown"

            entry_type = "dir" if entry.is_dir(follow_symlinks=False) else "file"
            if entry.is_symlink():
                entry_type = "link"

            name = entry.name
            if len(name) > 38:
                name = name[:35] + "..."

            lines.append(f"{name:<40} {entry_type:<6} {size:>12,} {mtime:<20}")
            visible_count += 1

        lines.append(f"\n{visible_count} entries")
        return "\n".join(lines)

    def _fs_search_impl(self, path: str, pattern: str) -> str:
        """Search for files matching a glob pattern under a base path.

        Every result is individually validated against the allowlist so that
        symlinks resolving outside the allowed area are silently excluded.

        Args:
            path: Base directory to search under.
            pattern: Glob pattern (e.g. ``"**/*.yaml"``).  Regex
                metacharacters are rejected by :class:`FileSearchInput`.

        Returns:
            Newline-separated list of matching allowed paths, or an error/
            denied message.
        """
        try:
            validated_input = FileSearchInput(path=path, pattern=pattern)
        except Exception as exc:
            return f"Invalid input: {exc}"

        try:
            real_base = self._path_validator.validate_or_raise(validated_input.path)
        except PathValidationError:
            return f"Access denied: {path}"

        search_pattern = os.path.join(real_base, validated_input.pattern)

        try:
            raw_matches = glob.glob(search_pattern, recursive=True)
        except Exception as exc:
            return f"[ERROR] Search failed: {exc}"

        # Validate each result individually — glob may follow symlinks that
        # escape the allowlist.
        allowed_matches = [
            m for m in raw_matches if self._path_validator.is_allowed(m)
        ]
        allowed_matches.sort()

        if not allowed_matches:
            return f"=== Search: {pattern} under {path} ===\nNo matches found."

        header = f"=== Search: {pattern} under {path} ==="
        count_line = f"{len(allowed_matches)} match(es):"
        return "\n".join([header, count_line] + allowed_matches)

    def _fs_diff_impl(self, path: str) -> str:
        """Generate a unified diff between the current file and its last backup.

        Args:
            path: Path to the file to diff.

        Returns:
            Unified diff output, ``"No backup found"`` when none exists, or an
            error/denied message.
        """
        try:
            validated_input = FileDiffInput(path=path)
        except Exception as exc:
            return f"Invalid input: {exc}"

        try:
            real_path = self._path_validator.validate_or_raise(validated_input.path)
        except PathValidationError:
            return f"Access denied: {path}"

        backups = self._backup_manager.list_backups(real_path)
        if not backups:
            return f"=== Diff: {path} ===\nNo backup found."

        latest_backup = backups[0]  # list_backups returns newest-first
        backup_file = str(latest_backup["backup_path"])
        backup_ts = str(latest_backup["created_at"])

        try:
            with open(real_path, encoding="utf-8", errors="replace") as fh:
                current_lines = fh.readlines()
        except FileNotFoundError:
            return f"[ERROR] File not found: {path}"
        except OSError as exc:
            return f"[ERROR] Could not read current file: {exc}"

        try:
            with open(backup_file, encoding="utf-8", errors="replace") as fh:
                backup_lines = fh.readlines()
        except OSError as exc:
            return f"[ERROR] Could not read backup file: {exc}"

        diff_lines = list(
            difflib.unified_diff(
                backup_lines,
                current_lines,
                fromfile=f"{path} (backup {backup_ts})",
                tofile=f"{path} (current)",
                lineterm="",
            )
        )

        header = f"=== Diff: {path} ==="
        if not diff_lines:
            return f"{header}\nNo differences — file matches latest backup."

        return "\n".join([header] + diff_lines)

    def _fs_backup_list_impl(self, path: str = "") -> str:
        """List all backup snapshots, optionally filtered to one original file.

        Args:
            path: Optional original file path to filter results.  Pass an empty
                string or omit to list all backups.

        Returns:
            Formatted table of backup snapshots.
        """
        filter_path: str | None = path if path else None
        backups = self._backup_manager.list_backups(filter_path)

        header = "=== Backup Snapshots ==="
        if filter_path:
            header = f"=== Backup Snapshots: {Path(filter_path).name} ==="

        if not backups:
            return f"{header}\nNo backups found."

        lines = [
            header,
            f"{'ORIGINAL':<35} {'CREATED':<25} {'SIZE':>12}  BACKUP PATH",
            "-" * 110,
        ]
        for rec in backups:
            orig = str(rec["original_name"])
            created = str(rec["created_at"])
            size = int(rec["size_bytes"])  # type: ignore[arg-type]
            bpath = str(rec["backup_path"])
            if len(orig) > 33:
                orig = orig[:30] + "..."
            lines.append(f"{orig:<35} {created:<25} {size:>12,}  {bpath}")

        lines.append(f"\n{len(backups)} backup(s)")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # CRITICAL tool implementations
    # ------------------------------------------------------------------

    def _fs_write_impl(self, path: str, content: str, dry_run: bool = False) -> str:
        """Write content to a file, creating a pre-write backup of any existing file.

        Args:
            path: Destination file path.
            content: Text content to write.
            dry_run: When ``True``, show a preview diff without writing anything.

        Returns:
            Confirmation message with backup path, or dry-run preview, or an
            error/denied message.
        """
        try:
            validated_input = FileWriteInput(path=path, content=content, dry_run=dry_run)
        except Exception as exc:
            return f"Invalid input: {exc}"

        try:
            real_path = self._path_validator.validate_or_raise(validated_input.path)
        except PathValidationError:
            return f"Access denied: {path}"

        current_exists = os.path.isfile(real_path)

        if validated_input.dry_run:
            lines = [f"=== Dry Run: fs_write {path} ==="]
            if current_exists:
                try:
                    with open(real_path, encoding="utf-8", errors="replace") as fh:
                        old_lines = fh.readlines()
                    new_lines = validated_input.content.splitlines(keepends=True)
                    diff_lines = list(
                        difflib.unified_diff(
                            old_lines,
                            new_lines,
                            fromfile=f"{path} (current)",
                            tofile=f"{path} (proposed)",
                            lineterm="",
                        )
                    )
                    if diff_lines:
                        lines.append("Changes that would be applied:")
                        lines.extend(diff_lines)
                    else:
                        lines.append("No changes — content is identical to current file.")
                except OSError as exc:
                    lines.append(f"Could not read current file for diff: {exc}")
            else:
                lines.append(f"Would CREATE new file: {path}")
                preview = validated_input.content[:500]
                if len(validated_input.content) > 500:
                    preview += "\n... (truncated)"
                lines.append(f"Content preview:\n{preview}")
            lines.append("\nNOTE: No changes written (dry_run=True).")
            return "\n".join(lines)

        # Acquire per-file write lock to serialise concurrent writes
        lock = _get_write_lock(real_path)
        with lock:
            # Create backup of existing file BEFORE any write
            backup_path: str | None = None
            if current_exists:
                try:
                    backup_path = self._backup_manager.create_backup(real_path)
                except Exception as exc:
                    return f"[ERROR] Could not create backup before write: {exc}"

            try:
                # Ensure parent directory exists
                Path(real_path).parent.mkdir(parents=True, exist_ok=True)
                with open(real_path, "w", encoding="utf-8") as fh:
                    fh.write(validated_input.content)
            except PermissionError:
                return f"[ERROR] Permission denied writing: {path}"
            except OSError as exc:
                return f"[ERROR] Could not write file: {exc}"

        lines = [f"=== Write: {path} ==="]
        action = "UPDATED" if current_exists else "CREATED"
        lines.append(f"File {action}: {path}")
        lines.append(f"Bytes written: {len(validated_input.content.encode('utf-8')):,}")
        if backup_path:
            lines.append(f"Backup created: {backup_path}")
        return "\n".join(lines)

    def _fs_backup_restore_impl(self, backup_path: str, dry_run: bool = False) -> str:
        """Restore a file from a backup snapshot.

        Args:
            backup_path: Path to the ``.bak`` file to restore from.
            dry_run: When ``True``, show what would be restored without writing.

        Returns:
            Confirmation message, dry-run preview, or error/denied message.
        """
        try:
            validated_input = FileBackupRestoreInput(
                backup_path=backup_path, dry_run=dry_run
            )
        except Exception as exc:
            return f"Invalid input: {exc}"

        # Validate the backup_path through the path validator as a security
        # boundary — the backup dir is expected to be in allowed_paths or will
        # be caught here.  If the backup dir is not in the allowlist the
        # operator should add it; we never bypass validation.
        try:
            real_backup = self._path_validator.validate_or_raise(
                validated_input.backup_path
            )
        except PathValidationError:
            return f"Access denied: {backup_path}"

        if not os.path.isfile(real_backup):
            return f"[ERROR] Backup file not found: {backup_path}"

        if not real_backup.endswith(".bak"):
            return f"[ERROR] Not a backup file (expected .bak suffix): {backup_path}"

        if validated_input.dry_run:
            lines = [f"=== Dry Run: fs_backup_restore {backup_path} ==="]
            lines.append(f"Would restore backup: {backup_path}")
            try:
                size = os.path.getsize(real_backup)
                lines.append(f"Backup size: {size:,} bytes")
            except OSError:
                pass
            # Show what the restore destination would be (BackupManager logic)
            backup_stem = Path(real_backup).stem  # e.g. "config.yaml.20260329T142200"
            parts = backup_stem.rsplit(".", 1)
            orig_name = parts[0] if len(parts) == 2 else backup_stem  # noqa: PLR2004
            restore_dest = str(Path(real_backup).parent.parent / orig_name)
            lines.append(f"Would restore to: {restore_dest}")
            lines.append("\nNOTE: No changes written (dry_run=True).")
            return "\n".join(lines)

        try:
            restored_path = self._backup_manager.restore_backup(real_backup)
        except Exception as exc:
            return f"[ERROR] Restore failed: {exc}"

        lines = [
            f"=== Restore Complete ===",
            f"Restored from: {backup_path}",
            f"Restored to:   {restored_path}",
        ]
        return "\n".join(lines)
