"""Unit tests verifying filesystem containment, traversal defense, and atomic write safety."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from webvulnscanner.core.exceptions import StorageError, TargetValidationError
from webvulnscanner.models.target import Target
from webvulnscanner.utils.filesystem import (
    atomic_write_json,
    create_directory,
    resolve_within_root,
)


def test_resolve_within_root_rejects_escaping_paths(tmp_path: Path) -> None:
    """Paths that escape the storage root must raise StorageError."""
    storage_root = tmp_path / "runs"
    storage_root.mkdir()

    escaping_paths = [
        storage_root / ".." / "escaped.json",
        storage_root / ".." / ".." / "etc" / "shadow",
        Path("..") / "outside",
        tmp_path / "sibling_dir" / "file.txt",
    ]

    for candidate in escaping_paths:
        with pytest.raises(StorageError, match=r"escapes the configured storage root"):
            resolve_within_root(storage_root, candidate)


def test_resolve_within_root_boundary_rules(tmp_path: Path) -> None:
    """The root directory itself must be rejected when allow_root=False."""
    storage_root = tmp_path / "runs"
    storage_root.mkdir()

    with pytest.raises(StorageError, match=r"output path must be below the storage root"):
        resolve_within_root(storage_root, storage_root, allow_root=False)

    resolved = resolve_within_root(storage_root, storage_root, allow_root=True)
    assert resolved == storage_root.resolve()


def test_create_directory_containment(tmp_path: Path) -> None:
    """Directory creation outside storage root must be rejected."""
    storage_root = tmp_path / "runs"
    storage_root.mkdir()

    with pytest.raises(StorageError, match=r"escapes the configured storage root"):
        create_directory(storage_root / ".." / "evil_dir", storage_root=storage_root)

    safe_dir = create_directory(
        storage_root / "example.com" / "stage",
        storage_root=storage_root,
        parents=True,
    )
    assert safe_dir.is_dir()
    assert safe_dir.is_relative_to(storage_root.resolve())


def test_atomic_write_json_refuses_symlink_replacement(tmp_path: Path) -> None:
    """atomic_write_json must refuse to replace or follow symbolic links."""
    storage_root = tmp_path / "runs"
    storage_root.mkdir()
    target_file = storage_root / "sensitive.txt"
    target_file.write_text("secret", encoding="utf-8")

    symlink_path = storage_root / "link.json"
    try:
        symlink_path.symlink_to(target_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported or permitted on this environment")

    with pytest.raises(StorageError, match=r"refusing to replace a symbolic-link output path"):
        atomic_write_json(symlink_path, {"test": "data"}, storage_root=storage_root)

    # Ensure target file was not modified
    assert target_file.read_text(encoding="utf-8") == "secret"


def test_atomic_write_json_refuses_overwrite_when_disabled(tmp_path: Path) -> None:
    """atomic_write_json must refuse to overwrite existing scan artifacts when overwrite=False."""
    storage_root = tmp_path / "runs"
    storage_root.mkdir()
    destination = storage_root / "artifact.json"
    destination.write_text('{"initial": true}', encoding="utf-8")

    with pytest.raises(StorageError, match=r"refusing to overwrite an existing scan artifact"):
        atomic_write_json(
            destination,
            {"updated": True},
            storage_root=storage_root,
            overwrite=False,
        )

    # Ensure original content is preserved
    assert '{"initial": true}' in destination.read_text(encoding="utf-8")


def test_target_normalized_domain_filesystem_safety() -> None:
    """Target normalized_domain must be safe for directory and file names."""
    # IPv6 addresses should be normalized without colon characters
    target_v6 = Target("http://[2001:db8::1]:8080")
    assert ":" not in target_v6.normalized_domain
    assert target_v6.normalized_domain.startswith("ipv6__")

    # IPv4 addresses
    target_v4 = Target("http://192.168.1.1:80")
    assert target_v4.normalized_domain == "192.168.1.1"

    # Standard hostname
    target_host = Target("https://sub.example.com")
    assert target_host.normalized_domain == "sub.example.com"


def test_target_rejects_path_traversal_and_slashes_in_host() -> None:
    """Target parsing must strictly reject traversal sequences and invalid characters in host."""
    malicious_targets = [
        "https://example.com/../../etc/passwd",  # path traversal (path is okay, but let's check host validation)
        "https://../evil.com",
        "https://..",
        "https://example.com:65536",
        "https://example.com:0",
        "http://[::1]%eth0",  # scoped IPv6 not allowed
        "http://example.com\\path",  # backslash not allowed
        "http://example\x00evil.com",  # null byte
    ]
    for bad_target in malicious_targets:
        with pytest.raises(TargetValidationError):
            Target(bad_target)
