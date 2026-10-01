"""Tests for typed Phase 3 service and discovery handoff models."""

import pytest

from webvulnscanner.models.discovery import DiscoveredResource
from webvulnscanner.models.service import WebService


def test_web_service_json_round_trip_and_scope_validation() -> None:
    service = WebService(
        host="Example.COM",
        port=443,
        protocol="tcp",
        service="http",
        product="nginx",
        version="1.24",
        tunnel="ssl",
        web_url="https://example.com/",
    )

    assert WebService.from_dict(service.to_dict()) == service
    assert service.host == "example.com"

    invalid = service.to_dict()
    invalid["web_url"] = "https://outside.example/"
    with pytest.raises(ValueError, match="observed host"):
        WebService.from_dict(invalid)


def test_discovered_resource_json_round_trip_and_validation() -> None:
    resource = DiscoveredResource(
        url="HTTPS://Example.COM/admin",
        status_code=200,
        source="gobuster",
        content_length=42,
    )

    assert DiscoveredResource.from_dict(resource.to_dict()) == resource
    assert resource.url == "https://example.com/admin"

    invalid = resource.to_dict()
    invalid["status_code"] = 999
    with pytest.raises(ValueError, match="between"):
        DiscoveredResource.from_dict(invalid)
