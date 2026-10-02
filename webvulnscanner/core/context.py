"""Creation of unique, website-scoped scan contexts."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType

from webvulnscanner.core.exceptions import StorageError
from webvulnscanner.models.report import ScanMetadata
from webvulnscanner.models.scan_result import RoutingDecision
from webvulnscanner.models.target import Target
from webvulnscanner.utils.filesystem import (
    atomic_write_json,
    create_directory,
    resolve_within_root,
)
from webvulnscanner.utils.time import as_utc, utc_now

_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")
_STAGE_DIRECTORIES = (
    "passive",
    "fingerprint",
    "discovery",
    "vulnerability",
    "reports",
)
_MAX_DIRECTORY_ATTEMPTS = 100


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Filesystem paths and initial metadata for one scan execution."""

    target: Target
    metadata: ScanMetadata
    storage_root: Path
    scan_directory: Path
    stage_directories: Mapping[str, Path]
    metadata_path: Path
    target_path: Path

    @property
    def scan_id(self) -> str:
        return self.metadata.scan_id

    def stage_directory(self, stage: str) -> Path:
        """Return a registered stage directory."""
        try:
            return self.stage_directories[stage]
        except KeyError as error:
            raise StorageError(
                f"unknown scan stage directory: {stage}",
                component="context",
                operation="lookup",
                cause=error,
            ) from error


class ScanContextFactory:
    """Create scan contexts with injectable UTC time and unique-ID providers."""

    def __init__(
        self,
        storage_root: Path,
        *,
        time_provider: Callable[[], datetime] = utc_now,
        id_provider: Callable[[], str] | None = None,
    ) -> None:
        self._storage_root = Path(storage_root)
        self._time_provider = time_provider
        self._id_provider = id_provider or (lambda: uuid.uuid4().hex)

    def create(
        self,
        target: Target,
        *,
        profile_name: str,
        scanner_configuration: Mapping[str, object],
        tool_versions: Mapping[str, str] | None = None,
    ) -> ScanContext:
        """Create a unique directory tree and write initial JSON artifacts."""
        if not isinstance(target, Target):
            raise TypeError("target must be a Target")
        if not isinstance(profile_name, str) or not profile_name.strip():
            raise ValueError("profile_name must be a non-empty string")

        started_at = self._get_started_at()
        storage_root = self._prepare_storage_root()
        domain_directory = create_directory(
            storage_root / target.normalized_domain,
            storage_root=storage_root,
            exist_ok=True,
        )
        date_directory = create_directory(
            domain_directory / started_at.strftime("%Y-%m-%d"),
            storage_root=storage_root,
            exist_ok=True,
        )
        scan_id, scan_directory = self._create_unique_scan_directory(
            date_directory,
            started_at,
            storage_root,
        )

        stage_directories = {
            stage: create_directory(
                scan_directory / stage,
                storage_root=storage_root,
            )
            for stage in _STAGE_DIRECTORIES
        }
        metadata = ScanMetadata(
            scan_id=scan_id,
            target_url=target.url,
            normalized_domain=target.normalized_domain,
            started_at=started_at,
            profile=profile_name,
            scanner_configuration=scanner_configuration,
            tool_versions={} if tool_versions is None else tool_versions,
        )

        metadata_path = atomic_write_json(
            scan_directory / "metadata.json",
            metadata.to_dict(),
            storage_root=storage_root,
            overwrite=False,
        )
        target_path = atomic_write_json(
            scan_directory / "target.json",
            _target_data(target),
            storage_root=storage_root,
            overwrite=False,
        )
        return ScanContext(
            target=target,
            metadata=metadata,
            storage_root=storage_root,
            scan_directory=scan_directory,
            stage_directories=MappingProxyType(stage_directories),
            metadata_path=metadata_path,
            target_path=target_path,
        )

    def _get_started_at(self) -> datetime:
        try:
            return as_utc(self._time_provider(), field_name="started_at")
        except (TypeError, ValueError) as error:
            raise StorageError(
                "time provider must return a timezone-aware datetime",
                component="context",
                operation="create",
                cause=error,
            ) from error

    def _prepare_storage_root(self) -> Path:
        try:
            self._storage_root.mkdir(parents=True, exist_ok=True)
            storage_root = self._storage_root.resolve()
        except OSError as error:
            raise StorageError(
                "unable to create the configured storage root",
                component="context",
                operation="create",
                cause=error,
            ) from error
        if not storage_root.is_dir():
            raise StorageError(
                "configured storage root is not a directory",
                component="context",
                operation="create",
            )
        return storage_root

    def _create_unique_scan_directory(
        self,
        date_directory: Path,
        started_at: datetime,
        storage_root: Path,
    ) -> tuple[str, Path]:
        time_name = started_at.strftime("%H-%M-%S")
        scan_id = self._next_scan_id()
        for attempt in range(_MAX_DIRECTORY_ATTEMPTS):
            directory_name = (
                time_name if attempt == 0 else f"{time_name}-{scan_id[:12]}"
            )
            candidate = resolve_within_root(
                storage_root,
                date_directory / directory_name,
            )
            try:
                return scan_id, create_directory(
                    candidate,
                    storage_root=storage_root,
                )
            except StorageError as error:
                if isinstance(error.cause, FileExistsError):
                    if attempt > 0:
                        scan_id = self._next_scan_id()
                    continue
                raise
        raise StorageError(
            "unable to allocate a unique scan result directory",
            component="context",
            operation="create",
        )

    def _next_scan_id(self) -> str:
        scan_id = self._id_provider()
        if not isinstance(scan_id, str) or _SCAN_ID.fullmatch(scan_id) is None:
            raise StorageError(
                "ID provider returned an invalid scan ID",
                component="context",
                operation="create",
            )
        return scan_id


def create_scan_context(
    storage_root: Path,
    target: Target,
    *,
    profile_name: str,
    scanner_configuration: Mapping[str, object],
    tool_versions: Mapping[str, str] | None = None,
    time_provider: Callable[[], datetime] = utc_now,
    id_provider: Callable[[], str] | None = None,
) -> ScanContext:
    """Convenience wrapper for one context creation."""
    return ScanContextFactory(
        storage_root,
        time_provider=time_provider,
        id_provider=id_provider,
    ).create(
        target,
        profile_name=profile_name,
        scanner_configuration=scanner_configuration,
        tool_versions=tool_versions,
    )


def _target_data(target: Target) -> dict[str, object]:
    return {
        "original": target.original,
        "url": target.url,
        "scheme": target.scheme,
        "host": target.host,
        "port": target.port,
        "normalized_domain": target.normalized_domain,
        "kind": target.kind.value,
    }


def write_routing_decisions(
    context: ScanContext,
    decisions: Sequence[RoutingDecision],
) -> Path:
    """Atomically store routing decisions in a structured JSON artifact."""
    payload = [decision.to_dict() for decision in decisions]
    destination = context.scan_directory / "routing.json"
    return atomic_write_json(
        destination,
        payload,
        storage_root=context.storage_root,
        overwrite=True,
    )


def update_latest_pointer(
    context: ScanContext,
    metadata: ScanMetadata,
) -> Path | None:
    """Atomically update runs/<normalized-domain>/latest.json for completed scans."""
    from webvulnscanner.models.report import ScanStatus

    if metadata.status is not ScanStatus.COMPLETED:
        return None

    domain_dir = context.storage_root / context.target.normalized_domain
    latest_path = domain_dir / "latest.json"

    if latest_path.is_file():
        try:
            existing_data = json.loads(latest_path.read_text(encoding="utf-8"))
            existing_time_str = existing_data.get("started_at")
            if isinstance(existing_time_str, str):
                existing_time = datetime.fromisoformat(
                    existing_time_str.replace("Z", "+00:00")
                )
                if metadata.started_at < existing_time:
                    return None
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    payload = metadata.to_dict()
    payload["scan_directory"] = str(context.scan_directory)

    return atomic_write_json(
        latest_path,
        payload,
        storage_root=context.storage_root,
        overwrite=True,
    )


__all__ = [
    "ScanContext",
    "ScanContextFactory",
    "create_scan_context",
    "update_latest_pointer",
    "write_routing_decisions",
]
