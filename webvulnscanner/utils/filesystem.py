"""Safe filesystem primitives for scan-result storage."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path

from webvulnscanner.core.exceptions import StorageError


def resolve_within_root(
    storage_root: Path,
    candidate: Path,
    *,
    allow_root: bool = False,
) -> Path:
    """Resolve a candidate and verify that it remains below the storage root."""
    try:
        resolved_root = Path(storage_root).resolve()
        raw_candidate = Path(candidate)
        if not raw_candidate.is_absolute():
            raw_candidate = resolved_root / raw_candidate
        resolved_candidate = raw_candidate.resolve()
    except (OSError, RuntimeError) as error:
        raise _storage_error("unable to resolve a storage path", cause=error) from error

    if resolved_candidate == resolved_root:
        if allow_root:
            return resolved_candidate
        raise _storage_error("output path must be below the storage root")
    if not resolved_candidate.is_relative_to(resolved_root):
        raise _storage_error("output path escapes the configured storage root")
    return resolved_candidate


def create_directory(
    path: Path,
    *,
    storage_root: Path,
    parents: bool = False,
    exist_ok: bool = False,
) -> Path:
    """Create a directory only after storage containment validation."""
    safe_path = resolve_within_root(storage_root, path)
    try:
        safe_path.mkdir(parents=parents, exist_ok=exist_ok)
    except OSError as error:
        raise _storage_error(
            "unable to create a scan directory", cause=error
        ) from error
    return resolve_within_root(storage_root, safe_path)


def atomic_write_json(
    path: Path,
    data: object,
    *,
    storage_root: Path,
    overwrite: bool = True,
) -> Path:
    """Atomically write JSON within storage using a same-directory temporary file."""
    if path.is_symlink():
        raise _storage_error("refusing to replace a symbolic-link output path")
    destination = resolve_within_root(storage_root, path)
    parent = resolve_within_root(storage_root, destination.parent, allow_root=True)
    if not parent.is_dir():
        raise _storage_error("JSON output parent directory does not exist")
    if destination.is_symlink():
        raise _storage_error("refusing to replace a symbolic-link output path")
    if not overwrite and destination.exists():
        raise _storage_error("refusing to overwrite an existing scan artifact")

    try:
        serialized = json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise _storage_error(
            "scan artifact is not JSON-compatible", cause=error
        ) from error

    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary_path = Path(temporary_name)
        resolve_within_root(storage_root, temporary_path)
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        descriptor = None
        with stream:
            stream.write(serialized)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if not overwrite and destination.exists():
            raise _storage_error("refusing to overwrite an existing scan artifact")
        os.replace(temporary_path, destination)
        temporary_path = None
    except StorageError:
        raise
    except OSError as error:
        raise _storage_error(
            "unable to atomically write scan artifact", cause=error
        ) from error
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary_path is not None:
            with contextlib.suppress(OSError):
                temporary_path.unlink(missing_ok=True)

    return resolve_within_root(storage_root, destination)


def atomic_write_text(
    path: Path,
    text: str,
    *,
    storage_root: Path,
    overwrite: bool = True,
) -> Path:
    """Atomically write text within storage using a same-directory temporary file."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    destination = resolve_within_root(storage_root, path)
    parent = resolve_within_root(storage_root, destination.parent, allow_root=True)
    if not parent.is_dir():
        raise _storage_error("text output parent directory does not exist")
    if destination.is_symlink():
        raise _storage_error("refusing to replace a symbolic-link output path")
    if not overwrite and destination.exists():
        raise _storage_error("refusing to overwrite an existing scan artifact")

    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary_path = Path(temporary_name)
        resolve_within_root(storage_root, temporary_path)
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        descriptor = None
        with stream:
            stream.write(text)
            if not text.endswith("\n"):
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if not overwrite and destination.exists():
            raise _storage_error("refusing to overwrite an existing scan artifact")
        os.replace(temporary_path, destination)
        temporary_path = None
    except StorageError:
        raise
    except OSError as error:
        raise _storage_error(
            "unable to atomically write scan artifact", cause=error
        ) from error
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary_path is not None:
            with contextlib.suppress(OSError):
                temporary_path.unlink(missing_ok=True)

    return resolve_within_root(storage_root, destination)


def _storage_error(
    message: str,
    *,
    cause: BaseException | None = None,
) -> StorageError:
    return StorageError(
        message,
        component="storage",
        operation="filesystem",
        cause=cause,
    )


__all__ = [
    "atomic_write_json",
    "atomic_write_text",
    "create_directory",
    "resolve_within_root",
]
