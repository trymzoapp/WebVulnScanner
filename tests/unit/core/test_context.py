"""Tests for website-scoped scan context creation."""

import itertools
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.exceptions import StorageError
from webvulnscanner.models.report import ScanMetadata, ScanStatus
from webvulnscanner.models.target import Target

FIXED_LOCAL_TIME = datetime(
    2026,
    9,
    30,
    0,
    30,
    tzinfo=timezone(timedelta(hours=5, minutes=30)),
)
FIXED_UTC_TIME = datetime(2026, 9, 29, 19, 0, tzinfo=UTC)


def scanner_snapshot() -> dict[str, object]:
    return {
        "headers": {
            "enabled": True,
            "timeout": 30,
            "concurrency": 2,
        },
        "nuclei": {
            "enabled": True,
            "timeout": 600,
            "rate_limit_per_second": 5.0,
        },
    }


def test_context_creates_required_website_utc_layout_and_artifacts(
    tmp_path: Path,
) -> None:
    factory = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_LOCAL_TIME,
        id_provider=lambda: "scan-00000001",
    )

    context = factory.create(
        Target("https://Example.COM:8443/path"),
        profile_name="safe",
        scanner_configuration=scanner_snapshot(),
        tool_versions={"nuclei": "3.3.0"},
    )

    expected = (tmp_path / "runs" / "example.com" / "2026-09-29" / "19-00-00").resolve()
    assert context.scan_directory == expected
    assert context.scan_id == "scan-00000001"
    assert context.metadata.started_at == FIXED_UTC_TIME
    assert set(context.stage_directories) == {
        "passive",
        "fingerprint",
        "discovery",
        "vulnerability",
        "reports",
    }
    assert all(path.is_dir() for path in context.stage_directories.values())
    assert context.stage_directory("reports") == expected / "reports"

    metadata = json.loads(context.metadata_path.read_text(encoding="utf-8"))
    assert metadata == {
        "scan_id": "scan-00000001",
        "target_url": "https://example.com:8443/path",
        "normalized_domain": "example.com",
        "started_at": "2026-09-29T19:00:00Z",
        "completed_at": None,
        "profile": "safe",
        "scanner_configuration": scanner_snapshot(),
        "tool_versions": {"nuclei": "3.3.0"},
        "status": "running",
        "errors": [],
    }

    target = json.loads(context.target_path.read_text(encoding="utf-8"))
    assert target["original"] == "https://Example.COM:8443/path"
    assert target["url"] == "https://example.com:8443/path"
    assert target["host"] == "example.com"
    assert target["port"] == 8443
    assert target["kind"] == "hostname"


def test_same_second_contexts_do_not_overwrite_previous_scan(
    tmp_path: Path,
) -> None:
    identifiers = iter(("scan-00000001", "scan-00000002"))
    factory = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_UTC_TIME,
        id_provider=lambda: next(identifiers),
    )
    target = Target("example.com")

    first = factory.create(
        target,
        profile_name="safe",
        scanner_configuration=scanner_snapshot(),
    )
    original_metadata = first.metadata_path.read_bytes()
    second = factory.create(
        target,
        profile_name="safe",
        scanner_configuration=scanner_snapshot(),
    )

    assert first.scan_directory.name == "19-00-00"
    assert second.scan_directory.name == f"19-00-00-{second.scan_id[:12]}"
    assert first.scan_directory != second.scan_directory
    assert first.metadata_path.read_bytes() == original_metadata
    assert json.loads(first.metadata_path.read_text(encoding="utf-8"))["scan_id"] == (
        "scan-00000001"
    )
    assert json.loads(second.metadata_path.read_text(encoding="utf-8"))["scan_id"] == (
        "scan-00000002"
    )


def test_concurrent_context_creation_allocates_unique_directories(
    tmp_path: Path,
) -> None:
    counter = itertools.count(1)
    lock = threading.Lock()

    def next_id() -> str:
        with lock:
            return f"scan-{next(counter):08d}"

    factory = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_UTC_TIME,
        id_provider=next_id,
    )
    target = Target("concurrent.example.com")

    def create_context(_: int) -> tuple[str, Path]:
        context = factory.create(
            target,
            profile_name="safe",
            scanner_configuration=scanner_snapshot(),
        )
        return context.scan_id, context.scan_directory

    with ThreadPoolExecutor(max_workers=8) as executor:
        created = list(executor.map(create_context, range(8)))

    scan_ids = {scan_id for scan_id, _ in created}
    directories = {directory for _, directory in created}
    assert len(scan_ids) == 8
    assert len(directories) == 8
    assert all(directory.is_dir() for directory in directories)
    for scan_id, directory in created:
        metadata = json.loads((directory / "metadata.json").read_text("utf-8"))
        assert metadata["scan_id"] == scan_id


def test_ipv6_context_uses_filesystem_safe_domain_directory(tmp_path: Path) -> None:
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_UTC_TIME,
        id_provider=lambda: "scan-ipv600001",
    ).create(
        Target("2001:db8::1"),
        profile_name="safe",
        scanner_configuration={},
    )

    relative = context.scan_directory.relative_to(context.storage_root)
    assert relative.parts[0] == "ipv6__2001-db8--1"
    assert ":" not in relative.parts[0]


def test_invalid_id_provider_is_rejected(tmp_path: Path) -> None:
    factory = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_UTC_TIME,
        id_provider=lambda: "../escape",
    )

    with pytest.raises(StorageError, match="invalid scan ID"):
        factory.create(
            Target("example.com"),
            profile_name="safe",
            scanner_configuration={},
        )


def test_naive_time_provider_is_rejected(tmp_path: Path) -> None:
    factory = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: datetime(2026, 9, 29, 19, 0),
        id_provider=lambda: "scan-00000001",
    )

    with pytest.raises(StorageError, match="timezone-aware"):
        factory.create(
            Target("example.com"),
            profile_name="safe",
            scanner_configuration={},
        )


def test_context_paths_and_metadata_mappings_are_immutable(tmp_path: Path) -> None:
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_UTC_TIME,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("example.com"),
        profile_name="safe",
        scanner_configuration=scanner_snapshot(),
    )

    with pytest.raises(TypeError):
        context.stage_directories["other"] = tmp_path  # type: ignore[index]
    with pytest.raises(TypeError):
        context.metadata.scanner_configuration["other"] = True  # type: ignore[index]
    with pytest.raises(StorageError, match="unknown"):
        context.stage_directory("other")


def test_metadata_rejects_non_json_configuration_values() -> None:
    with pytest.raises(TypeError, match="non-JSON-compatible"):
        ScanMetadata(
            scan_id="scan-00000001",
            target_url="https://example.com/",
            normalized_domain="example.com",
            started_at=FIXED_UTC_TIME,
            profile="safe",
            scanner_configuration={"unsafe": object()},
        )


def test_metadata_requires_consistent_terminal_timestamp() -> None:
    with pytest.raises(ValueError, match="requires completed_at"):
        ScanMetadata(
            scan_id="scan-00000001",
            target_url="https://example.com/",
            normalized_domain="example.com",
            started_at=FIXED_UTC_TIME,
            profile="safe",
            scanner_configuration={},
            status=ScanStatus.COMPLETED,
        )

    completed = ScanMetadata(
        scan_id="scan-00000001",
        target_url="https://example.com/",
        normalized_domain="example.com",
        started_at=FIXED_UTC_TIME,
        completed_at=FIXED_UTC_TIME + timedelta(seconds=5),
        profile="safe",
        scanner_configuration={},
        status=ScanStatus.COMPLETED,
    )
    assert completed.to_dict()["completed_at"] == "2026-09-29T19:00:05Z"


def test_empty_profile_name_is_rejected_before_context_creation(
    tmp_path: Path,
) -> None:
    factory = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: FIXED_UTC_TIME,
        id_provider=lambda: "scan-00000001",
    )

    with pytest.raises(ValueError, match="profile_name"):
        factory.create(
            Target("example.com"),
            profile_name="",
            scanner_configuration={},
        )
    assert not (tmp_path / "runs").exists()
