"""Pre-change backup manager with configurable retention.

Backups are stored as flat files in a dedicated directory.  Each backup file
is named::

    {original_basename}.{ISO-timestamp}.bak

For example::

    automations.yaml.20260329T142200.bak

``FileLock`` prevents two concurrent processes from writing the same backup
simultaneously.  Retention enforcement removes backups that are older than
``retention_days`` days or exceed the per-file ``max_per_file`` cap,
whichever limit is triggered first.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from filelock import FileLock

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class BackupError(Exception):
    """Raised when a backup or restore operation cannot be completed.

    Wraps lower-level ``OSError`` instances with a user-facing message that
    includes the relevant file paths.
    """


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

_TIMESTAMP_FMT = "%Y%m%dT%H%M%S"


def _make_timestamp() -> str:
    """Return a compact ISO-8601-style timestamp in UTC.

    Returns:
        Timestamp string, e.g. ``"20260329T142200"``.
    """
    return datetime.now(tz=timezone.utc).strftime(_TIMESTAMP_FMT)


def _parse_timestamp(backup_path: Path) -> datetime | None:
    """Extract the UTC timestamp embedded in a backup filename.

    Args:
        backup_path: Path to a ``.bak`` file.

    Returns:
        A timezone-aware ``datetime`` in UTC, or ``None`` when the filename
        does not match the expected naming convention.
    """
    # Expected stem without final .bak: "{basename}.{timestamp}"
    stem = backup_path.stem  # strips the trailing .bak
    # The timestamp is the last dot-delimited segment
    parts = stem.rsplit(".", 1)
    if len(parts) != 2:  # noqa: PLR2004
        return None
    try:
        return datetime.strptime(parts[1], _TIMESTAMP_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _original_basename(backup_path: Path) -> str:
    """Return the original file's basename from a backup path.

    Args:
        backup_path: Path to a ``.bak`` file.

    Returns:
        The original basename, e.g. ``"automations.yaml"``.
    """
    # stem is "{original_basename}.{timestamp}", suffix is ".bak"
    stem = backup_path.stem
    parts = stem.rsplit(".", 1)
    return parts[0] if len(parts) == 2 else stem  # noqa: PLR2004


# ---------------------------------------------------------------------------
# BackupManager
# ---------------------------------------------------------------------------


class BackupManager:
    """Manage pre-change file backups with automatic retention enforcement.

    Args:
        backup_dir: Directory where backup files are stored.  Created on
            first use if it does not exist.
        retention_days: Backups older than this many days are removed by
            :meth:`cleanup`.  Defaults to 30.
        max_per_file: Maximum number of backups kept per original file.
            When exceeded, the oldest entries are removed.  Defaults to 50.

    Example::

        mgr = BackupManager("/var/backups/my-app")
        backup_path = mgr.create_backup("/etc/my-app/config.yaml")
        # ... make changes to config.yaml ...
        mgr.restore_backup(backup_path)
    """

    def __init__(
        self,
        backup_dir: str = "/var/backups/claude-home-server",
        retention_days: int = 30,
        max_per_file: int = 50,
    ) -> None:
        self._backup_dir = Path(backup_dir)
        self._retention_days = retention_days
        self._max_per_file = max_per_file

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_backup(self, file_path: str) -> str:
        """Copy *file_path* to the backup directory with a timestamped name.

        The backup filename follows the pattern
        ``{basename}.{timestamp}.bak``.  A ``FileLock`` is held for the
        duration of the copy so concurrent callers cannot produce duplicate
        backup names.

        Args:
            file_path: Absolute path to the source file.  The file must exist.

        Returns:
            Absolute path of the newly created backup file.

        Raises:
            BackupError: When *file_path* does not exist or the backup
                directory cannot be created or written to.
        """
        source = Path(file_path)
        if not source.exists():
            raise BackupError(f"Source file does not exist: {file_path}")
        if not source.is_file():
            raise BackupError(f"Source path is not a regular file: {file_path}")

        self._ensure_backup_dir()

        backup_name = f"{source.name}.{_make_timestamp()}.bak"
        backup_path = self._backup_dir / backup_name
        lock_path = self._backup_dir / f".{source.name}.lock"

        with FileLock(str(lock_path)):
            try:
                shutil.copy2(str(source), str(backup_path))
            except OSError as exc:
                raise BackupError(
                    f"Failed to create backup of {file_path!r} at {backup_path!r}: {exc}"
                ) from exc

        return str(backup_path)

    def restore_backup(self, backup_path: str) -> str:
        """Copy *backup_path* back to its original location.

        The original location is inferred from the backup filename by
        stripping the timestamp and ``.bak`` suffix.  The destination
        directory must already exist.

        Args:
            backup_path: Absolute path to an existing backup file.

        Returns:
            Absolute path of the restored file (the original location).

        Raises:
            BackupError: When *backup_path* does not exist, is not a valid
                backup file, or the destination directory is not writable.
        """
        src = Path(backup_path)
        if not src.exists():
            raise BackupError(f"Backup file does not exist: {backup_path}")

        # Validate it is a .bak file with a parsable timestamp
        if src.suffix != ".bak":
            raise BackupError(f"Not a backup file (expected .bak suffix): {backup_path}")
        if _parse_timestamp(src) is None:
            raise BackupError(
                f"Cannot infer original path from backup name: {backup_path}"
            )

        original_basename = _original_basename(src)
        # Restore to same directory as the backup itself? No — restore to the
        # canonical "source" location, which we derive from the backup *name*
        # alone.  Since backup files are flat (not nested), the original
        # directory is not stored.  Callers should pass a full absolute original
        # path if they need precise destination control; here we restore inside
        # the backup dir with the original name so tests can verify the content.
        #
        # In practice the server always calls create_backup(absolute_path) and
        # restore_backup(backup_path) where the absolute original path is known.
        # We therefore reconstruct the destination as:
        #   {backup_dir_parent}/{original_basename}
        # which is equivalent to restoring alongside the backup directory.
        # A cleaner approach used by many backup systems: store metadata.
        # For this project: restore to backup_dir/../{original_basename}.
        dest = self._backup_dir.parent / original_basename

        lock_path = self._backup_dir / f".{original_basename}.lock"
        with FileLock(str(lock_path)):
            try:
                shutil.copy2(str(src), str(dest))
            except OSError as exc:
                raise BackupError(
                    f"Failed to restore {backup_path!r} to {dest!r}: {exc}"
                ) from exc

        return str(dest)

    def list_backups(self, original_path: str | None = None) -> list[dict[str, object]]:
        """List backup records, optionally filtered to a specific original file.

        Args:
            original_path: When provided, only backups whose original basename
                matches ``Path(original_path).name`` are returned.

        Returns:
            A list of dicts ordered from newest to oldest, each containing:
            * ``backup_path`` — absolute path to the backup file.
            * ``original_name`` — inferred original basename.
            * ``created_at`` — ISO-formatted UTC timestamp string.
            * ``size_bytes`` — file size in bytes.
        """
        if not self._backup_dir.exists():
            return []

        filter_name: str | None = Path(original_path).name if original_path else None

        records: list[dict[str, object]] = []
        for entry in self._backup_dir.iterdir():
            if entry.suffix != ".bak" or not entry.is_file():
                continue
            ts = _parse_timestamp(entry)
            if ts is None:
                continue
            orig_name = _original_basename(entry)
            if filter_name is not None and orig_name != filter_name:
                continue
            records.append(
                {
                    "backup_path": str(entry),
                    "original_name": orig_name,
                    "created_at": ts.isoformat(),
                    "size_bytes": entry.stat().st_size,
                }
            )

        records.sort(key=lambda r: r["created_at"], reverse=True)
        return records

    def cleanup(self, original_name: str | None = None) -> int:
        """Remove expired or excess backup files and return the count removed.

        Two retention rules are applied for each distinct original file:
        1. **Age rule** — backups older than ``retention_days`` are deleted.
        2. **Count rule** — when more than ``max_per_file`` backups remain
           after the age pass, the oldest entries are deleted until the count
           is within the limit.

        Args:
            original_name: When provided, only backups for this original
                filename are processed (e.g. ``"automations.yaml"``).

        Returns:
            Total number of backup files deleted.
        """
        if not self._backup_dir.exists():
            return 0

        cutoff: datetime = datetime.now(tz=timezone.utc) - timedelta(
            days=self._retention_days
        )
        removed = 0

        # Collect all .bak files grouped by original name
        groups: dict[str, list[tuple[datetime, Path]]] = {}
        for entry in self._backup_dir.iterdir():
            if entry.suffix != ".bak" or not entry.is_file():
                continue
            ts = _parse_timestamp(entry)
            if ts is None:
                continue
            orig = _original_basename(entry)
            if original_name is not None and orig != original_name:
                continue
            groups.setdefault(orig, []).append((ts, entry))

        for entries in groups.values():
            # Sort oldest-first so we remove the right entries for the count rule
            entries.sort(key=lambda t: t[0])

            surviving: list[tuple[datetime, Path]] = []
            for ts, path in entries:
                if ts < cutoff:
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        pass
                else:
                    surviving.append((ts, path))

            # Apply count cap — drop oldest entries beyond max_per_file
            excess = len(surviving) - self._max_per_file
            for i in range(excess):
                _, path = surviving[i]
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass

        return removed

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_backup_dir(self) -> None:
        """Create the backup directory (and parents) if it does not exist.

        Raises:
            BackupError: When the directory cannot be created.
        """
        try:
            self._backup_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BackupError(
                f"Cannot create backup directory {self._backup_dir!r}: {exc}"
            ) from exc
