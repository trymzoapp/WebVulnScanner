# WebVulnScanner Overview

## What WebVulnScanner is

WebVulnScanner is a command-line framework for safe, authorized assessment of websites
and web services. It coordinates passive reconnaissance, technology fingerprinting, port
and service identification, and bounded content discovery.

The framework helps an assessor collect evidence that may reveal security weaknesses,
misconfiguration, exposed services, outdated technology, and unexpected web content.
These signals support later vulnerability testing, but they are not by themselves proof
that a vulnerability is exploitable.

Use WebVulnScanner only against websites and assets you own or have explicit permission
to assess. It must not be used to bypass authentication, access controls, WAF controls,
or rate limits.

## Purpose and importance

Modern websites depend on domains, web servers, frameworks, content-management systems,
third-party services, network ports, and historical URLs. Reviewing only the visible
home page can miss important parts of the attack surface.

WebVulnScanner is intended to:

- create a repeatable inventory of an authorized website's exposed web surface;
- identify technologies and services that may require security review;
- collect non-destructive evidence before vulnerability-specific scanners are selected;
- reduce unnecessary scanning by running only configured and eligible tools;
- apply consistent timeout, rate, concurrency, and scope controls;
- preserve structured artifacts for audit and later reporting;
- isolate tool failures so one missing dependency does not crash the complete scan.

The tool does not guarantee that every vulnerability will be found. Results should be
reviewed by a qualified assessor and confirmed using authorized, risk-appropriate
methods.

## Current implemented workflow

The CLI currently executes the completed Phase 2 and Phase 3 stages:

```text
CLI target
  -> configuration loading
  -> target validation and normalization
  -> website/date/time scan directory
  -> passive reconnaissance
  -> technology and service fingerprinting
  -> bounded content discovery
  -> metadata finalization
  -> JSON CLI summary
```

Dynamic routing, vulnerability scanners, finding aggregation, and final vulnerability
reports are planned but are not implemented yet.

## Tool-wise benefits

### HTTP security headers

Purpose:

- collect the HTTP status, redirect chain, selected response headers, and redacted cookie
  metadata;
- highlight missing or weak browser-facing security controls for later review.

Benefits:

- helps assess controls such as Content-Security-Policy and Strict-Transport-Security;
- records server information without sending mutation requests;
- follows only validated redirects and applies configured response-size limits.

Output: `passive/headers.json`

### robots.txt

Purpose:

- retrieve and parse the target origin's `/robots.txt`;
- record user-agent, allow, disallow, and sitemap directives.

Benefits:

- identifies intentionally hidden or crawler-restricted paths that may deserve manual
  review;
- records discovered paths without automatically requesting them;
- treats a missing file as a valid empty result.

Output: `passive/robots.json`

### WHOIS

Purpose:

- collect domain registration dates, registrar, statuses, and nameservers.

Benefits:

- helps identify domain ownership and lifecycle information;
- can expose unexpected registrar or nameserver configuration;
- skips IP targets and isolates lookup failures.

Output: `passive/whois.json`

### Subfinder

Purpose:

- enumerate subdomains from Subfinder's structured JSONL output.

Benefits:

- expands awareness of the authorized domain's public attack surface;
- normalizes and deduplicates hostnames;
- excludes and counts out-of-scope results instead of silently broadening scope.

Output: `passive/subfinder.json`

### Wayback CDX

Purpose:

- collect historical in-scope URLs from the configured Wayback CDX endpoint.

Benefits:

- identifies old paths and query-bearing URLs that may no longer be linked publicly;
- supports future routing decisions for parameter-aware assessment;
- never requests the archived application paths and applies pagination, record, and rate
  limits.

Output: `passive/wayback.json`

### Wappalyzer

Purpose:

- detect web technologies using structured Wappalyzer CLI output.

Benefits:

- identifies frameworks, content-management systems, web servers, and related technology
  categories;
- records version and confidence information where available;
- provides evidence for future technology-aware routing, such as WordPress-specific
  assessment.

Output: `fingerprint/wappalyzer.json`

External requirement: a compatible `wappalyzer` CLI must be installed and available on
`PATH`, or configured using an explicit executable path.

### Nmap

Purpose:

- identify open services on a configured TCP port allowlist;
- perform constrained, light service-version detection.

Benefits:

- confirms which HTTP or HTTPS services are actually exposed;
- provides service, product, version, port, and TLS-tunnel evidence;
- prohibits unbounded port ranges, UDP sweeps, OS exploitation, and NSE exploit scripts
  under the implemented command contract.

Output: `fingerprint/nmap.json`

External requirement: `nmap` must be installed and available on `PATH`, or configured
using an explicit executable path.

### Gobuster

Purpose:

- perform bounded, non-recursive directory discovery against confirmed in-scope web
  services.

Benefits:

- can identify unlinked administrative, legacy, or sensitive-looking paths;
- uses configured wordlists, status policies, request delay, thread limits, and timeout;
- runs only when enabled and supplied with a valid wordlist.

Output: `discovery/gobuster.json`

The safe profile disables Gobuster by default.

### Dirsearch

Purpose:

- provide structured JSON-based content discovery as an alternative to Gobuster.

Benefits:

- supports configured extensions and tightly bounded recursion;
- normalizes results into the same discovered-resource contract used by Gobuster;
- retains scanner provenance for each discovered resource.

Output: `discovery/dirsearch.json`

The safe profile disables Dirsearch by default.

## Framework-level benefits

### Safe target handling

- Accepts explicit HTTP(S), hostname, IPv4, and IPv6 targets.
- Rejects credentials, unsupported schemes, malformed ports, traversal, and ambiguous
  targets.
- Normalizes target-derived directory names and prevents storage-path escape.

### Typed configuration

- Uses layered YAML configuration with deterministic precedence.
- Externalizes executable paths, wordlists, timeouts, rates, concurrency, ports, and
  discovery limits.
- Rejects unknown or unsafe configuration values.

### Failure isolation

- Runs external commands through one bounded asynchronous subprocess implementation.
- Captures bounded stdout, stderr, return code, timeout state, and duration.
- Cleans up timed-out or cancelled child processes.
- Converts individual scanner failures into controlled results while independent
  scanners continue.

### Website-wise evidence storage

Each execution receives a unique scan ID and writes under:

```text
runs/<normalized-domain>/<UTC-date>/<UTC-time>/
```

The current structure includes:

```text
metadata.json
target.json
passive/
fingerprint/
discovery/
vulnerability/
reports/
```

Previous scan directories are not overwritten. The CLI summary reports the scan ID,
scan directory, stage statuses, and controlled errors.

## Running the current tool

```shell
python -m webvulnscanner.cli scan https://example.com
```

Use an alternative storage location:

```shell
python -m webvulnscanner.cli scan https://example.com --storage-root ./local-runs
```

Inspect effective configuration:

```shell
python -m webvulnscanner.cli config --profile safe
```

Missing enabled external tools produce a controlled partial scan. They are not silently
treated as successful. Install the required executable or configure its explicit path
before expecting that scanner's artifact.

## Development progress

### Completed

- Phase 1 — Foundation: Tasks 01–13 completed.
- Phase 2 — Passive Reconnaissance: Tasks 14–19 completed.
- Phase 3 — Fingerprinting and Discovery: Tasks 20–25 completed.
- Task 25A — CLI integration for the completed Phase 2 and Phase 3 pipeline completed.

Completed capabilities include project foundations, typed models and exceptions,
configuration, logging, safe storage, subprocess execution, scanner contracts,
scheduling, orchestration, passive collection, fingerprinting, discovery, and CLI
execution.

Latest verified automated test result:

```text
332 passed, 1 skipped, 0 failed
```

The skipped test is the Windows symbolic-link safety case when local privileges do not
permit symlink creation.

### Pending

- Phase 4 — Dynamic Routing: Tasks 26–28.
- Phase 5 — Vulnerability Scanners: Tasks 29–32.
- Phase 6 — Parsing and Aggregation: Tasks 33–37.
- Phase 7 — Reporting: Tasks 38–42.
- Phase 8 — Testing and Hardening: Tasks 43–50.

Planned vulnerability-specific tools include Nuclei, SQLmap, and WPScan. They are not
currently executed by the CLI. JSON, Markdown, and HTML vulnerability reports, severity
normalization, finding deduplication, and `latest.json` updates are also pending.

`TASKS.md` remains the authoritative implementation checklist and status record.

## Current limitations

- The current release performs reconnaissance, fingerprinting, and optional discovery;
  it does not yet run vulnerability-specific scanners.
- There is no final consolidated vulnerability report yet.
- Missing external executables can cause a stage to complete partially or fail.
- Gobuster and Dirsearch require explicit enablement and configured wordlists.
- Dynamic scanner selection based on technologies, services, and query parameters is
  still pending.
- A successful scan does not prove that a website is vulnerability-free.

## Responsible-use reminder

Authorization is mandatory. Confirm the target, scope, allowed techniques, scan window,
and contact procedures before execution. Use conservative profiles first, review
artifacts carefully, and stop if the assessment affects service availability or exceeds
the agreed scope.
