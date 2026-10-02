#!/usr/bin/env python3
"""Deterministic fake external security tools for end-to-end integration tests."""

from __future__ import annotations

import json
import os
import sys
import time


def _fail_if_requested(tool_name: str) -> None:
    fail_tools = os.environ.get("FAKE_TOOLS_FAIL", "").split(",")
    fail_tools = [t.strip().casefold() for t in fail_tools if t.strip()]
    if tool_name.casefold() in fail_tools:
        sys.stderr.write(f"Mock tool failure simulated for {tool_name}\n")
        sys.exit(1)

    timeout_tools = os.environ.get("FAKE_TOOLS_TIMEOUT", "").split(",")
    timeout_tools = [t.strip().casefold() for t in timeout_tools if t.strip()]
    if tool_name.casefold() in timeout_tools:
        # Sleep to trigger caller's timeout
        time.sleep(15.0)


def handle_subfinder(args: list[str]) -> None:
    _fail_if_requested("subfinder")
    if "-version" in args:
        print("subfinder version 2.6.6")
        return

    domain = "example.com"
    if "-d" in args:
        idx = args.index("-d")
        if idx + 1 < len(args):
            domain = args[idx + 1]

    print(
        json.dumps({"host": f"api.{domain}", "source": "fake-recon", "input": domain})
    )
    print(
        json.dumps({"host": f"blog.{domain}", "source": "fake-recon", "input": domain})
    )


def handle_whois(args: list[str]) -> None:
    _fail_if_requested("whois")
    target = args[0] if args else "example.com"
    print(f"""Domain Name: {target.upper()}
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.fakeregistrar.com
Registrar: Fake Registrar LLC
Creation Date: 2021-01-01T00:00:00Z
Updated Date: 2024-01-01T00:00:00Z
Registry Expiry Date: 2028-01-01T00:00:00Z
Domain Status: clientTransferProhibited
Name Server: NS1.{target.upper()}
Name Server: NS2.{target.upper()}
""")


def handle_wappalyzer(args: list[str]) -> None:
    _fail_if_requested("wappalyzer")
    if "--version" in args:
        print("6.10.66")
        return

    url = args[0] if args else "https://example.com/"
    payload = {
        "urls": {url: {"status": 200}},
        "technologies": [
            {
                "slug": "wordpress",
                "name": "WordPress",
                "confidence": 100,
                "version": "6.6",
                "icon": "WordPress.svg",
                "website": "https://wordpress.org",
                "categories": [{"id": 1, "slug": "cms", "name": "CMS"}],
            },
            {
                "slug": "php",
                "name": "PHP",
                "confidence": 90,
                "version": "8.2",
                "categories": [
                    {
                        "id": 2,
                        "slug": "programming-language",
                        "name": "Programming languages",
                    }
                ],
            },
        ],
    }
    print(json.dumps(payload))


def handle_nmap(args: list[str]) -> None:
    _fail_if_requested("nmap")
    if "--version" in args:
        print("Nmap version 7.94 ( https://nmap.org )")
        return

    target = "127.0.0.1"
    for arg in reversed(args):
        if not arg.startswith("-"):
            target = arg
            break

    # Extract port from env or from -p arg
    port = os.environ.get("FAKE_TOOL_PORT")
    if not port and "-p" in args:
        idx = args.index("-p")
        if idx + 1 < len(args):
            p_val = args[idx + 1]
            ports = [p.strip() for p in p_val.split(",") if p.strip()]
            port = ports[0] if ports else "80"
    if not port:
        port = "80"

    xml_output = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="{target}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.52" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    print(xml_output)


def handle_gobuster(args: list[str]) -> None:
    _fail_if_requested("gobuster")
    if "version" in args:
        print("Gobuster v3.6.0")
        return

    print("/admin (Status: 200) [Size: 123]")
    print("/login (Status: 200) [Size: 456]")


def handle_dirsearch(args: list[str]) -> None:
    _fail_if_requested("dirsearch")
    if "--version" in args:
        print("dirsearch v0.4.3")
        return

    base_url = "http://127.0.0.1"
    if "--url" in args:
        idx = args.index("--url")
        if idx + 1 < len(args):
            base_url = args[idx + 1].rstrip("/")

    payload = {
        "results": [
            {"url": f"{base_url}/dashboard", "status": 200, "content_length": 789}
        ]
    }
    print(json.dumps(payload))


def handle_nuclei(args: list[str]) -> None:
    _fail_if_requested("nuclei")
    if "-version" in args:
        print("Nuclei engine v3.2.0")
        return

    target = "http://127.0.0.1"
    if "-u" in args:
        idx = args.index("-u")
        if idx + 1 < len(args):
            target = args[idx + 1]

    finding_line = json.dumps(
        {
            "template-id": "cve-2023-9999",
            "info": {
                "name": "Fake CVE Vulnerability",
                "severity": "high",
                "description": "A severe mock vulnerability",
                "reference": [
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9999"
                ],
            },
            "type": "http",
            "host": target,
            "matched-at": f"{target.rstrip('/')}/admin",
            "extracted-results": ["fake payload match"],
            "timestamp": "2026-10-01T12:00:00Z",
        }
    )

    if "-o" in args:
        idx = args.index("-o")
        if idx + 1 < len(args):
            output_file = args[idx + 1]
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(finding_line + "\n")

    print(finding_line)


def handle_sqlmap(args: list[str]) -> None:
    _fail_if_requested("sqlmap")
    if "--version" in args:
        print("sqlmap/1.8.2#stable")
        return

    print("""---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
---
""")


def handle_wpscan(args: list[str]) -> None:
    _fail_if_requested("wpscan")
    if "--version" in args:
        print("WPScan v3.8.25")
        return

    target = "https://example.com/"
    if "--url" in args:
        idx = args.index("--url")
        if idx + 1 < len(args):
            target = args[idx + 1]

    payload = {
        "target_url": target,
        "version": {
            "number": "6.6",
            "vulnerabilities": [
                {
                    "title": "WordPress <= 6.6 - Authenticated Stored XSS",
                    "fixed_in": "6.6.1",
                    "references": {"cve": ["2024-9999"]},
                }
            ],
        },
    }
    print(json.dumps(payload))


DISPATCHER = {
    "subfinder": handle_subfinder,
    "whois": handle_whois,
    "wappalyzer": handle_wappalyzer,
    "nmap": handle_nmap,
    "gobuster": handle_gobuster,
    "dirsearch": handle_dirsearch,
    "nuclei": handle_nuclei,
    "sqlmap": handle_sqlmap,
    "wpscan": handle_wpscan,
}


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: fake_tool.py <tool_name> [args...]\n")
        sys.exit(1)

    tool_name = sys.argv[1].casefold()
    args = sys.argv[2:]

    handler = DISPATCHER.get(tool_name)
    if not handler:
        sys.stderr.write(f"Unknown fake tool: {tool_name}\n")
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
