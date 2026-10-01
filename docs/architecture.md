# WebVulnScanner Architecture

## Purpose and safety boundary

WebVulnScanner is a CLI framework for authorized assessment of explicitly scoped web
assets. Its default profile is non-destructive and bounded by configuration-defined
timeouts, rates, and concurrency. The architecture does not permit authentication
bypass, WAF or access-control bypass, rate-limit bypass, destructive exploitation,
credential attacks, persistence, privilege escalation, or stealth/evasion behavior.

## Planned processing pipeline

The pipeline is intentionally staged:

1. Validate the explicit target and scope.
2. Create a typed scan context and unique website-specific output directory.
3. Run passive reconnaissance.
4. Fingerprint technologies, ports, and web services.
5. Evaluate and log dynamic routing decisions.
6. Run eligible discovery scanners.
7. Run Nuclei against eligible HTTP(S) services.
8. Run SQLmap only for routed in-scope URLs with query parameters.
9. Run WPScan only when sufficient WordPress evidence exists.
10. Parse structured scanner output.
11. Normalize, aggregate, and deduplicate findings.
12. Generate enabled reports.
13. Finalize metadata and atomically update `latest.json`.
14. Return a concise CLI summary.

A stage consumes typed artifacts rather than scraping another stage's logs or report
files. Routing decisions include their evidence, source, and reason.

## Package ownership

### CLI

`webvulnscanner/cli.py` owns argument parsing, authorization confirmation, user-facing
validation errors, final summaries, and process exit codes. It delegates scan execution
to the orchestrator.

### Core

`webvulnscanner/core/` owns orchestration, pipeline stages, scheduling, scan context,
logging, exceptions, and the common asynchronous subprocess runner. The orchestrator
coordinates components but contains no scanner-specific routing or parsing rules.

### Configuration

`webvulnscanner/config/` owns typed configuration loading and validation. Defaults,
profiles, tool paths, wordlists, timeouts, rates, and concurrency limits are externalized
here rather than embedded in scanner classes.

### Models

`webvulnscanner/models/` owns typed, serializable data contracts for targets,
technologies, findings, scanner results, scan metadata, and reports. Models do not
perform network, filesystem, subprocess, routing, or reporting work.

### Scanners

`webvulnscanner/scanners/` owns tool-specific input validation, safe argument
construction, invocation through the shared subprocess runner, and conversion of parser
output into a scanner result. Scanners do not generate final reports, select unrelated
scanners, or modify artifacts owned by another scanner.

### Parsers

`webvulnscanner/parsers/` converts bounded structured output into typed models. Parsers
perform no network or process I/O and report malformed data explicitly.

### Routing

`webvulnscanner/routing/` owns deterministic, explainable rules that decide which
conditional scanners are eligible. A matching rule cannot override a configuration
setting that disables a scanner.

### Aggregation

`webvulnscanner/aggregation/` owns severity normalization, finding deduplication,
provenance-preserving merges, and stable report-ready summaries.

### Reports

`webvulnscanner/reports/` renders aggregate models as JSON, Markdown, and escaped HTML.
Report generators do not launch tools, make network requests, or mutate scanner output.

### Utilities

`webvulnscanner/utils/` contains small reusable helpers for validation, safe filesystem
operations, command handling, and time. Scanner-specific business logic does not belong
in utilities.

## Dependency direction

Typed models are the lowest-level project contracts. Parsers, scanners, routing,
aggregation, reports, and core services may depend on models. Feature modules depend on
narrow core interfaces such as subprocess execution or scan context, not on the concrete
orchestrator.

The orchestrator depends on registered stage interfaces and injected services. It must
not import concrete scanner behavior to make routing decisions. Reports depend on
aggregate models, not scanner implementations. Circular dependencies and global mutable
registries are prohibited.

## Scanner contract

Every scanner implements the same conceptual lifecycle:

1. `validate()` confirms tool availability, target eligibility, configuration, and scope.
2. `build_command()` produces a safe argument sequence without shell interpolation.
3. `run()` invokes the common bounded subprocess abstraction.
4. `parse()` delegates structured output conversion to the appropriate parser.
5. The scanner returns a typed `ScanResult`.

A result represents success, skipped execution, or controlled failure. It includes
timing, scanner status, output references, parse warnings, and bounded diagnostics as
appropriate. Scanner methods receive dependencies explicitly so tests can replace
process, time, filesystem, and parser behavior.

## Failure isolation and resource bounds

External tools run only through the common `asyncio` subprocess runner. The runner
captures stdout, stderr, return code, and duration; applies configured timeouts and
concurrency limits; supports cancellation; and terminates and reaps child processes.
Arguments are passed as sequences without uncontrolled shell execution.

The scheduler converts expected scanner exceptions into failed `ScanResult` values.
Independent scanners continue after a timeout, malformed output, unavailable optional
tool, or nonzero exit. Fatal target-validation or scan-context failures stop before
scanners launch. Errors remain visible in metadata, logs, aggregate results, and reports.

## Result storage

Each execution receives a unique scan ID and writes beneath:

```text
runs/<normalized-domain>/<UTC-date>/<UTC-time>/
```

The directory contains metadata, target data, stage-specific structured output, and
reports. Target-derived names are normalized and verified to remain under the configured
storage root. Writes that establish metadata or pointers are atomic, and previous scan
directories are never overwritten. A domain's `latest.json` is updated only after a
completed scan and cannot be replaced by an older concurrently finishing scan.

## Trust boundaries

Targets, redirects, discovered URLs, DNS data, configuration, environment values,
external-tool output, and report evidence are untrusted. Each boundary validates scope,
size, format, and allowed values. Logs and stored artifacts redact secrets. HTML reports
escape scanner-provided content and use no remote scripts or trackers.
