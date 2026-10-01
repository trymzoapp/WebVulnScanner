"""Tests for safe scan-storage filesystem primitives."""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.core.exceptions import StorageError
from webvulnscanner.utils.filesystem import (
    atomic_write_json,
    create_directory,
    resolve_within_root,
)


def test_resolve_within_root_accepts_descendant(tmp_path: Path) -> None:
    candidate = resolve_within_root(tmp_path, Path("example.com/scan"))

    assert candidate == (tmp_path / "example.com" / "scan").resolve()


@pytest.mark.parametrize(
    "candidate_factory",
    [
        lambda root: root / ".." / "escape",
        lambda root: root.parent / "outside",
        lambda root: Path("..") / "outside",
    ],
)
def test_resolve_within_root_rejects_traversal(
    tmp_path: Path,
    candidate_factory: Any,
) -> None:
    with pytest.raises(StorageError, match="escapes"):
        resolve_within_root(tmp_path, candidate_factory(tmp_path))


def test_storage_root_itself_requires_explicit_permission(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="below"):
        resolve_within_root(tmp_path, tmp_path)

    assert resolve_within_root(tmp_path, tmp_path, allow_root=True) == tmp_path.resolve()


def test_existing_symlink_cannot_redirect_output_outside_root(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "storage"
    outside = tmp_path / "outside"
    storage.mkdir()
    outside.mkdir()
    link = storage / "redirect"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable for this test user")

    with pytest.raises(StorageError, match="escapes"):
        resolve_within_root(storage, link / "artifact.json")


def test_create_directory_validates_containment(tmp_path: Path) -> None:
    created = create_directory(
        tmp_path / "domain" / "date",
        storage_root=tmp_path,
        parents=True,
    )

    assert created.is_dir()
    with pytest.raises(StorageError):
        create_directory(
            tmp_path / ".." / "outside",
            storage_root=tmp_path,
            parents=True,
        )


def test_atomic_json_write_uses_same_directory_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_directory = tmp_path / "scan"
    output_directory.mkdir()
    destination = output_directory / "metadata.json"
    calls: list[tuple[Path, Path]] = []
    real_replace = os.replace

    def recording_replace(source: str | Path, target: str | Path) -> None:
        calls.append((Path(source), Path(target)))
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", recording_replace)

    result = atomic_write_json(
        destination,
        {"status": "running", "scan_id": "scan-12345678"},
        storage_root=tmp_path,
        overwrite=False,
    )

    assert result == destination.resolve()
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "scan_id": "scan-12345678",
        "status": "running",
    }
    assert len(calls) == 1
    assert calls[0][0].parent == destination.parent
    assert calls[0][1] == destination
    assert list(output_directory.glob("*.tmp")) == []


def test_atomic_json_write_refuses_unrequested_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "metadata.json"
    destination.write_text('{"original": true}\n', encoding="utf-8")

    with pytest.raises(StorageError, match="overwrite"):
        atomic_write_json(
            destination,
            {"replacement": True},
            storage_root=tmp_path,
            overwrite=False,
        )

    assert json.loads(destination.read_text(encoding="utf-8")) == {"original": True}


def test_atomic_json_write_can_replace_mutable_metadata(tmp_path: Path) -> None:
    destination = tmp_path / "metadata.json"
    destination.write_text('{"status": "running"}\n', encoding="utf-8")

    atomic_write_json(
        destination,
        {"status": "completed"},
        storage_root=tmp_path,
    )

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "status": "completed"
    }


def test_atomic_json_write_rejects_non_json_values(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="JSON-compatible"):
        atomic_write_json(
            tmp_path / "invalid.json",
            {"value": object()},
            storage_root=tmp_path,
        )

    assert not (tmp_path / "invalid.json").exists()


def test_atomic_json_write_requires_existing_parent(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="parent"):
        atomic_write_json(
            tmp_path / "missing" / "output.json",
            {},
            storage_root=tmp_path,
        )
