# WebVulnScanner

WebVulnScanner is a safe, modular, CLI-based framework for authorized web vulnerability assessments.
It coordinates reconnaissance, service fingerprinting, smart routing, bounded content discovery, and targeted vulnerability scanning into unified, structured reports.

## Authorized use only

> **CRITICAL:** Use this framework exclusively against websites, systems, and assets you own or have explicit, documented authorization to assess.
>
> WebVulnScanner operates strictly under non-destructive, rate-limited, and scope-aware policies.
> It **must not** be used for:
> - Destructive exploitation or denial of service
> - Bypassing authentication, authorization, or WAF controls
> - Credential harvesting or password brute-forcing
> - Privilege escalation or persistent footholds
> - Accessing targets outside the authorized scope

## Architecture and Pipeline

WebVulnScanner organizes assessments into six distinct sequential stages:

1. **Passive Reconnaissance**: Gathers DNS records, Whois metadata, robots.txt, and archived URLs from the Wayback Machine without intrusive interaction.
2. **Fingerprinting**: Identifies running HTTP services and web technologies using constrained Nmap port sweeps and Wappalyzer.
3. **Routing**: Analyzes fingerprint findings to dynamically route targets to appropriate downstream specialized scanners.
4. **Discovery**: Performs bounded content and directory enumeration using Dirsearch and Gobuster.
5. **Vulnerability Assessment**: Runs targeted, non-destructive checks via Nuclei templates, SQLmap parameter testing, and WPScan (if WordPress is detected).
6. **Reporting**: Normalizes and deduplicates findings into machine-readable JSON (`findings.json`), human-readable Markdown (`report.md`), and standalone self-contained HTML (`report.html`).

## Requirements

- Python 3.11 or newer
- Supported operating systems: Linux, macOS, Windows

## Installation

Create and activate a virtual environment, then install the package:

```shell
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## External Tools and Verification

WebVulnScanner coordinates trusted external security tools when available. Before running a scan, verify your environment with the dependency verification script:

```shell
python scripts/verify_tools.py
```

To see JSON-formatted verification results:

```shell
python scripts/verify_tools.py --json
```

For installation commands on Debian, Ubuntu, Arch, or macOS, consult `scripts/install_dependencies.sh`:

```shell
bash scripts/install_dependencies.sh
```

### Supported External Tools

| Tool | Recommended Version | Purpose |
| :--- | :--- | :--- |
| **nmap** | >= 7.80 | Service & TCP port fingerprinting |
| **nuclei** | >= 3.0.0 | Template-based vulnerability assessments |
| **subfinder** | >= 2.5.0 | Passive subdomain discovery |
| **wappalyzer** | >= 6.0 | Web application technology stack detection |
| **dirsearch** | >= 0.4.0 | Web path discovery |
| **gobuster** | >= 3.0.0 | High-speed directory enumeration |
| **sqlmap** | >= 1.5.0 | Safe parameter SQL injection detection |
| **wpscan** | >= 3.8.0 | WordPress core, plugin, and theme checks |
| **whois** | Any modern | Passive domain metadata lookup |

*Note: Real security tools are only required during actual scans; all unit and integration tests execute entirely offline with deterministic mock fixtures.*

## Quick Start

Launch an authorized assessment by supplying the target URL. Affirmative authorization confirmation is required via the `--confirm-authorized` (or `-y`) flag:

```shell
# Run a scan against an authorized target
webvulnscanner scan https://example.com -y

# Select a specific configuration profile
webvulnscanner scan https://example.com -p standard -y

# Scan with custom output directory
webvulnscanner scan https://example.com -o ./custom-runs -y
```

### CLI Exit Codes

- `0` (`EXIT_SUCCESS`): Scan completed successfully with zero vulnerabilities found.
- `1` (`EXIT_FINDINGS_FOUND`): Scan completed and identified at least one vulnerability finding.
- `2` (`EXIT_INVALID_INPUT`): Target URL or command line parameters were invalid.
- `3` (`EXIT_PARTIAL_COMPLETION`): One or more non-critical scanner stages experienced controlled failure.
- `4` (`EXIT_FATAL_FAILURE`): Pipeline aborted due to an unrecoverable error.
- `130` (`EXIT_INTERRUPTED`): Interrupted by operator (`Ctrl+C`).

## Configuration and Profiles

Configuration uses layered precedence: `defaults.yaml` -> `scanners.yaml` -> `<profile>.yaml` -> `user_config.yaml` -> runtime overrides.

Two built-in profiles are provided:
- **`safe`** (default): Low concurrency (max 3 scanners), rate limits (5 req/sec), no recursive discovery, conservative timeouts.
- **`standard`**: Moderate concurrency (max 5 scanners), rate limits (10 req/sec), enables Gobuster.

Output results are saved under domain-partitioned folders:
```
runs/
└── example.com/
    ├── latest.json
    └── 2026-10-01/
        └── 09-00-00/
            ├── metadata.json
            ├── reports/
            │   ├── findings.json
            │   ├── report.md
            │   └── report.html
            └── ...
```

## Development and Testing

Run unit tests:
```shell
python -m pytest -m "not integration"
```

Run isolated integration tests:
```shell
python -m pytest -m integration
```

Check code quality gates:
```shell
python -m ruff format --check .
python -m ruff check .
python -m mypy webvulnscanner scripts
```
