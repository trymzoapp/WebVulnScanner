"""Secure parser for Nmap XML service output."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

from webvulnscanner.models.service import WebService
from webvulnscanner.models.target import Target
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


ServiceObservation = WebService


class NmapParser(BaseParser[WebService]):
    """Parse bounded XML while rejecting DTD/entity declarations."""

    def __init__(self, requested_host: str, allowed_ports: tuple[int, ...]) -> None:
        super().__init__("nmap")
        self.requested_host = Target(requested_host).host
        self.allowed_ports = frozenset(allowed_ports)

    def parse(self, parser_input: ParserInput) -> ParseResult[ServiceObservation]:
        content = parser_input.content
        lowered = content.casefold()
        if "<!doctype" in lowered or "<!entity" in lowered:
            raise self.parsing_error("Nmap XML contains prohibited declarations")
        try:
            root = ET.fromstring(content)
        except ET.ParseError as error:
            raise self.parsing_error("Nmap output is not valid XML", cause=error)
        if root.tag != "nmaprun":
            raise self.parsing_error("Nmap XML has an unexpected root element")

        services: list[WebService] = []
        warnings: list[str] = []
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            ports = host.find("ports")
            if ports is None:
                continue
            for element in ports.findall("port"):
                observation = self._service(element)
                if observation is None:
                    warnings.append("ignored invalid, closed, or unconfigured port")
                    continue
                services.append(observation)
        return ParseResult(
            items=tuple(
                sorted(
                    services,
                    key=lambda item: (item.host, item.protocol, item.port),
                )
            ),
            warnings=tuple(warnings),
        )

    def _service(self, element: ET.Element) -> WebService | None:
        protocol = element.get("protocol")
        raw_port = element.get("portid")
        if protocol not in {"tcp"} or raw_port is None:
            return None
        try:
            port = int(raw_port)
        except ValueError:
            return None
        if port not in self.allowed_ports:
            return None
        state = element.find("state")
        if state is None or state.get("state") != "open":
            return None

        service_element = element.find("service")
        service = (
            None if service_element is None else _optional(service_element.get("name"))
        )
        product = (
            None
            if service_element is None
            else _optional(service_element.get("product"))
        )
        version = (
            None
            if service_element is None
            else _optional(service_element.get("version"))
        )
        tunnel = (
            None
            if service_element is None
            else _optional(service_element.get("tunnel"))
        )
        return WebService(
            host=self.requested_host,
            port=port,
            protocol=protocol,
            service=service,
            product=product,
            version=version,
            tunnel=tunnel,
            web_url=_web_url(self.requested_host, port, service, tunnel),
        )


def _optional(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip()


def _web_url(
    host: str,
    port: int,
    service: str | None,
    tunnel: str | None,
) -> str | None:
    service_name = "" if service is None else service.casefold()
    tunnel_name = "" if tunnel is None else tunnel.casefold()
    if "http" not in service_name and tunnel_name != "ssl":
        return None
    scheme = (
        "https"
        if tunnel_name == "ssl" or service_name in {"https", "https-alt"}
        else "http"
    )
    rendered_host = (
        f"[{host}]" if _is_ipv6(host) else host
    )
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{rendered_host}{suffix}/"


def _is_ipv6(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


__all__ = ["NmapParser", "ServiceObservation"]
