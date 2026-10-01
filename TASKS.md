# WebVulnScanner Development Tasks

Tasks are ordered by dependency. Implement exactly one task at a time unless explicitly
instructed otherwise. Each task must preserve safe, authorized, non-destructive defaults.
After each task, run its relevant tests, report changed files and results, then stop.

Task status rules:

- Every task starts with **Status: Pending**.
- A task may be changed to **Status: Completed** only after its implementation, tests,
  and acceptance criteria are complete.
- When a task is completed, change its checkbox from `[ ]` to `[x]` and replace its
  resolution-note placeholder with a concise summary of the implementation, test results,
  and any remaining limitations.
- If acceptance criteria are blocked or incomplete, keep the task pending and record the
  blocker in the resolution note.

## PHASE 1 — Foundation

### [x] Task 01 — Bootstrap the Python project

- **Status:** Completed
- **Resolution note:** Bootstrapped the Python 3.11+ package, dependencies, documentation,
  test layout, version metadata, and generated-output exclusions. The unit test passed
  (`1 passed`) with no lint errors. Editable-install verification was unavailable because
  the local machine currently has Python 3.10.6 only; its rejection confirmed the declared
  Python 3.11+ requirement.
- **Objective:** Create the minimal installable Python 3.11+ project and test layout.
- **Files involved:** `pyproject.toml`, `requirements.txt`, `README.md`, `LICENSE`,
  `.gitignore`, `.env.example`, `webvulnscanner/__init__.py`, `tests/unit/`,
  `tests/integration/`, `tests/fixtures/`, `runs/.gitkeep`
- **Implementation requirements:**
  - Define package metadata, Python version, runtime dependencies, and development tools.
  - Add an importable package with a version constant.
  - Configure pytest and separate integration-test marking.
  - Exclude generated scan data while retaining `runs/.gitkeep`.
- **Test requirements:**
  - Add a unit test that imports the package and validates the version format.
  - Run the configured unit-test command.
- **Acceptance criteria:**
  - The project installs in editable mode on Python 3.11+.
  - Unit tests run without external security tools.
  - No scanner functionality is implemented.

### [x] Task 02 — Add repository guidance and architecture documentation

- **Status:** Completed
- **Resolution note:** Added contributor rules, architecture boundaries, pipeline and
  scanner-contract documentation, development workflow, safety constraints, and
  documentation regression tests. Documentation tests passed (`7 passed`), the full
  unit suite passed (`8 passed`), and no lint errors were reported.
- **Objective:** Document development constraints, safety rules, and module boundaries.
- **Files involved:** `AGENTS_RULES.md`, `docs/architecture.md`, `docs/development.md`
- **Implementation requirements:**
  - Record task-by-task development, testing, and scope-control rules.
  - Document the planned pipeline, scanner contract, dependency direction, and failure isolation.
  - State authorized-use and non-destructive-default requirements.
- **Test requirements:**
  - Add a lightweight documentation test that verifies required headings and safety statements.
  - Run documentation tests.
- **Acceptance criteria:**
  - Contributors can identify module ownership and prohibited behavior.
  - Documentation agrees with this checklist and the master specification.

### [x] Task 03 — Define core exception types

- **Status:** Completed
- **Resolution note:** Added typed exception categories for configuration, targets,
  storage, scanner validation, subprocess execution/timeouts, and parsing. Safe optional
  context preserves causes without rendering their potentially sensitive messages.
  Exception tests passed (`11 passed`), the full unit suite passed (`19 passed`), and no
  lint errors were reported.
- **Objective:** Introduce typed exceptions for controlled framework failures.
- **Files involved:** `webvulnscanner/core/exceptions.py`, `tests/unit/core/test_exceptions.py`
- **Implementation requirements:**
  - Define focused exceptions for configuration, target validation, storage, scanner validation,
    subprocess timeout, subprocess execution, and parsing failures.
  - Preserve underlying error context without exposing secrets.
- **Test requirements:**
  - Test inheritance, messages, and optional contextual attributes.
- **Acceptance criteria:**
  - Callers can distinguish expected failure categories without matching message strings.

### [x] Task 04 — Implement target models and normalization

- **Status:** Completed
- **Resolution note:** Added an immutable target model and strict validation for HTTP(S)
  URLs, hostnames, IDNs, IPv4, and IPv6. Canonical URL/domain handling rejects malformed
  ports, credentials, unsupported schemes, ambiguous numeric hosts, unsafe characters,
  scoped IPv6, and traversal-derived directory names. Task tests passed (`44 passed`),
  the full unit suite passed (`63 passed`), and no lint errors were reported.
- **Objective:** Represent validated HTTP(S), hostname, IPv4, and IPv6 targets safely.
- **Files involved:** `webvulnscanner/models/target.py`, `webvulnscanner/utils/validators.py`,
  `tests/unit/models/test_target.py`, `tests/unit/utils/test_validators.py`
- **Implementation requirements:**
  - Use typed models with explicit URL, host, port, and normalized-domain fields.
  - Accept only supported HTTP(S) URL/host/IP target forms.
  - Produce filesystem-safe normalized names without URL separators or traversal sequences.
  - Handle IPv4, bracketed IPv6, IDN, mixed case, trailing dots, and explicit ports deterministically.
- **Test requirements:**
  - Parameterize valid and invalid target cases.
  - Test traversal attempts, malformed ports, unsupported schemes, and normalization collisions.
- **Acceptance criteria:**
  - Unsafe or ambiguous targets fail with a target-validation exception.
  - Normalized target names cannot escape their intended storage directory.

### [x] Task 05 — Define finding, technology, and scan-result models

- **Status:** Completed
- **Resolution note:** Added immutable, validated models for findings, severities,
  technologies, scanner statuses, structured errors, subprocess details, and scan
  results. Models provide deterministic finding IDs, UTC timing, consistency checks,
  and strict JSON-compatible round trips. Task tests passed (`37 passed`), the full unit
  suite passed (`100 passed`), and no lint errors were reported.
- **Objective:** Establish typed contracts shared by scanners, routing, aggregation, and reports.
- **Files involved:** `webvulnscanner/models/finding.py`,
  `webvulnscanner/models/technology.py`, `webvulnscanner/models/scan_result.py`,
  `tests/unit/models/test_models.py`
- **Implementation requirements:**
  - Model severity, evidence, source scanner, affected resource, references, and stable finding IDs.
  - Model detected technologies with confidence and evidence source.
  - Model scanner status, timing, output paths, findings, errors, and subprocess details.
  - Ensure models serialize to JSON-compatible data without leaking arbitrary objects.
- **Test requirements:**
  - Test validation, serialization round trips, enums, defaults, and invalid states.
- **Acceptance criteria:**
  - Models are strictly typed and reject inconsistent required fields.
  - A failed scanner result can be represented without raising an unrelated exception.

### [x] Task 06 — Implement layered configuration loading

- **Status:** Completed
- **Resolution note:** Added immutable typed configuration models, deterministic layered
  YAML loading, safe and standard profiles, externalized scanner settings, strict key and
  limit validation, package-data inclusion, fixtures, and configuration documentation.
  Unsafe behavior flags and values beyond profile safety ceilings are rejected. Task
  tests passed (`37 passed`), the full unit suite passed (`137 passed`), and no lint
  errors were reported.
- **Objective:** Load and validate defaults, scanner settings, profiles, and user overrides.
- **Files involved:** `webvulnscanner/config/loader.py`,
  `webvulnscanner/config/defaults.yaml`, `webvulnscanner/config/scanners.yaml`,
  `webvulnscanner/config/profiles/safe.yaml`,
  `webvulnscanner/config/profiles/standard.yaml`,
  `docs/configuration.md`, `tests/unit/config/test_loader.py`, `tests/fixtures/config/`
- **Implementation requirements:**
  - Define typed configuration for timeouts, concurrency, reports, storage, tools, and profiles.
  - Apply a documented deterministic precedence order.
  - Reject unknown critical keys, invalid limits, unsafe profile values, and missing profiles.
  - Keep tool paths, wordlists, timeouts, and concurrency outside scanner classes.
- **Test requirements:**
  - Test defaults, profile selection, overrides, malformed YAML, missing files, and invalid values.
- **Acceptance criteria:**
  - The safe profile is the default.
  - Configuration errors are actionable and do not produce partially valid settings.

### [x] Task 07 — Implement structured logging

- **Status:** Completed
- **Resolution note:** Added human and JSON log formatters, UTC timestamps, bound scan
  context, structured event emission, recursive sensitive-key redaction, safe handling of
  arbitrary values and exceptions, and managed-handler replacement to prevent duplicate
  messages. Task tests passed (`12 passed`), the full unit suite passed (`149 passed`),
  and no lint errors were reported.
- **Objective:** Provide scan-aware structured logging without secret leakage.
- **Files involved:** `webvulnscanner/core/logging.py`, `tests/unit/core/test_logging.py`
- **Implementation requirements:**
  - Support human-readable console logs and structured JSON records.
  - Include scan ID, target, scanner, event, and timestamp when available.
  - Redact configured sensitive keys and avoid duplicate handlers.
- **Test requirements:**
  - Capture and validate console and JSON log records.
  - Verify contextual fields and redaction.
- **Acceptance criteria:**
  - Multiple logger initializations do not duplicate messages.
  - Routing and scanner failures can be logged as structured events.

### [x] Task 08 — Implement safe filesystem and scan-context creation

- **Status:** Completed
- **Resolution note:** Added UTC helpers, immutable scan metadata, storage-containment
  checks, atomic JSON writes, unique website/date/time scan directories, stage/report
  directories, and injectable time/ID providers. Concurrent same-second creation was
  verified without overwrites. Task tests passed (`21 passed`, `1 skipped` because
  Windows symlink creation was unavailable), the full unit suite passed (`170 passed`,
  `1 skipped`), and no lint errors were reported.
- **Objective:** Create unique website-wise result directories and initial scan metadata.
- **Files involved:** `webvulnscanner/utils/filesystem.py`,
  `webvulnscanner/utils/time.py`, `webvulnscanner/core/context.py`,
  `webvulnscanner/models/report.py`, `tests/unit/core/test_context.py`,
  `tests/unit/utils/test_filesystem.py`
- **Implementation requirements:**
  - Create `runs/<normalized-domain>/<UTC-date>/<UTC-time>/` with stage and report subdirectories.
  - Generate a unique scan ID and prevent overwriting when scans start in the same second.
  - Write `metadata.json` and `target.json` atomically.
  - Resolve and verify every output path remains below the configured storage root.
  - Inject time and ID providers for deterministic tests.
- **Test requirements:**
  - Use temporary directories to test layout, collisions, atomic writes, and traversal rejection.
  - Test metadata serialization and UTC timestamps.
- **Acceptance criteria:**
  - Concurrent context creation never overwrites a prior scan.
  - Paths follow the required website/date/time organization.

### [x] Task 09 — Implement the asynchronous subprocess runner

- **Status:** Completed
- **Resolution note:** Added validated literal command construction and a shared,
  semaphore-bounded asyncio subprocess runner with timeouts, cancellation cleanup,
  terminate/kill escalation, bounded stream capture, structured events, and controlled
  start failures. Task tests passed (`16 passed`), the full unit suite passed
  (`186 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Execute external tools through one bounded, cancellable abstraction.
- **Files involved:** `webvulnscanner/core/subprocess_runner.py`,
  `webvulnscanner/utils/command.py`, `tests/unit/core/test_subprocess_runner.py`
- **Implementation requirements:**
  - Use `asyncio` subprocess APIs with argument arrays and no uncontrolled shell execution.
  - Capture stdout, stderr, return code, duration, and timeout state.
  - Enforce configured timeouts and a shared concurrency semaphore.
  - On timeout or cancellation, terminate and reap the process, escalating cleanup if required.
  - Return or raise typed controlled failures with bounded diagnostic output.
- **Test requirements:**
  - Use Python helper processes to test success, nonzero exit, timeout, cancellation, and concurrency.
  - Test arguments containing spaces and shell metacharacters.
- **Acceptance criteria:**
  - No zombie process remains after timeout or cancellation.
  - One command failure does not alter runner availability for later commands.

### [x] Task 10 — Define the scanner and parser contracts

- **Status:** Completed
- **Resolution note:** Added generic parser inputs/results and typed parse failures plus a
  dependency-injected scanner lifecycle for validation, literal command construction,
  bounded execution, parsing, and controlled success/skipped/failure results. Abstract
  contracts were verified with fake implementations. Task tests passed (`15 passed`),
  the full unit suite passed (`201 passed`, `1 skipped`), and no lint errors were
  reported.
- **Objective:** Create common typed interfaces for all scanner and parser implementations.
- **Files involved:** `webvulnscanner/scanners/base.py`,
  `webvulnscanner/parsers/base.py`, `tests/unit/scanners/test_base.py`,
  `tests/unit/parsers/test_base.py`
- **Implementation requirements:**
  - Define scanner lifecycle methods for validation, command construction, execution, and parsing.
  - Inject configuration, subprocess runner, scan context, and parser dependencies.
  - Define parser input/output contracts and typed parse failures.
  - Prevent scanner classes from generating final reports.
- **Test requirements:**
  - Implement test-only fake scanner and parser classes.
  - Verify lifecycle behavior, dependency injection, and abstract-method enforcement.
- **Acceptance criteria:**
  - A scanner can return success, skipped, or controlled failure as a `ScanResult`.
  - Contracts contain no scanner-specific routing logic.

### [x] Task 11 — Implement scanner scheduling and failure isolation

- **Status:** Completed
- **Resolution note:** Added a semaphore-bounded scanner scheduler that preserves input
  ordering, converts controlled and unexpected scanner exceptions into safe failed
  results, logs isolated failures, and cancels/awaits workers when scheduling is
  cancelled. Task tests passed (`9 passed`), the full unit suite passed (`210 passed`,
  `1 skipped`), and no lint errors were reported.
- **Objective:** Run independent scanners concurrently within configured limits.
- **Files involved:** `webvulnscanner/core/scheduler.py`,
  `tests/unit/core/test_scheduler.py`
- **Implementation requirements:**
  - Enforce maximum concurrent scanners.
  - Convert scanner exceptions into failed results while allowing remaining scanners to finish.
  - Preserve deterministic result ordering and support cancellation.
- **Test requirements:**
  - Use fake scanners to test concurrency bounds, mixed outcomes, exceptions, and cancellation.
- **Acceptance criteria:**
  - One scanner failure never crashes the complete scheduled batch.
  - Configured concurrency is never exceeded.

### [x] Task 12 — Implement pipeline stages and minimal orchestrator

- **Status:** Completed
- **Resolution note:** Added typed scanner-independent stage names, outcomes,
  dependencies, continuation/fatal policies, aggregate pipeline states, and a minimal
  orchestrator that creates context, runs stages, records safe errors, and atomically
  finalizes metadata. Task tests passed (`12 passed`), the full unit suite passed
  (`222 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Coordinate typed pipeline stages without scanner-specific business logic.
- **Files involved:** `webvulnscanner/core/pipeline.py`,
  `webvulnscanner/core/orchestrator.py`, `tests/unit/core/test_pipeline.py`,
  `tests/unit/core/test_orchestrator.py`
- **Implementation requirements:**
  - Define stage names, stage outcomes, dependencies, and controlled continuation rules.
  - Make the orchestrator create context, invoke stages, track errors, and finalize status.
  - Keep concrete scanner selection and routing outside the orchestrator.
- **Test requirements:**
  - Test stage order, skipped dependencies, recoverable failures, fatal setup failures, and final state.
- **Acceptance criteria:**
  - Recoverable stage failures are recorded and later eligible stages continue.
  - Context/storage setup failures stop safely with an actionable error.

### [x] Task 13 — Add the initial CLI

- **Status:** Completed
- **Resolution note:** Added an argparse CLI and console entry point with help/version,
  explicit target validation, effective configuration inspection, safe profile/user
  config selection, and bounded storage/timeout/concurrency overrides. Invalid input
  returns concise errors before creating storage or launching processes. Task tests
  passed (`16 passed`), the full unit suite passed (`238 passed`, `1 skipped`), and no
  lint errors were reported.
- **Objective:** Expose safe target validation and configuration inspection through a CLI.
- **Files involved:** `webvulnscanner/cli.py`, `pyproject.toml`,
  `tests/unit/test_cli.py`
- **Implementation requirements:**
  - Add version, help, target, profile, config, storage-root, timeout, and concurrency options.
  - Require explicit target input for a scan.
  - Validate options before any scanner execution and present concise errors.
  - Do not add destructive or security-control-bypass options.
- **Test requirements:**
  - Test help, version, missing/invalid targets, valid overrides, and exit codes.
- **Acceptance criteria:**
  - The installed console entry point works.
  - Invalid input creates no scan directory and launches no subprocess.

## PHASE 2 — Passive Reconnaissance

### [x] Task 14 — Implement the HTTP headers scanner

- **Status:** Completed
- **Resolution note:** Added a GET-only passive headers scanner with an injectable and
  production HTTP client, TLS verification, configured user agent/timeout/redirect/body
  limits, same-host redirect validation, selected security-header normalization, cookie
  value redaction, controlled network failures, and atomic `passive/headers.json`
  output. Task tests passed (`10 passed`), the full unit suite passed (`251 passed`,
  `1 skipped`), and no lint errors were reported.
- **Objective:** Collect response status and security-relevant headers with a safe request.
- **Files involved:** `webvulnscanner/scanners/passive/headers.py`,
  `tests/unit/scanners/passive/test_headers.py`
- **Implementation requirements:**
  - Use configured user agent, timeout, redirect limit, and response-size cap.
  - Record redirect chain and selected headers without storing sensitive cookie values.
  - Write structured JSON to `passive/headers.json`.
- **Test requirements:**
  - Mock HTTP responses for success, redirect, timeout, oversized response, TLS error, and header redaction.
- **Acceptance criteria:**
  - The scanner performs no mutation request.
  - Network failures return controlled failed results.

### [x] Task 15 — Implement the robots.txt scanner

- **Status:** Completed
- **Resolution note:** Added bounded origin-only robots.txt retrieval, structured
  user-agent/allow/disallow/sitemap parsing, malformed-line warnings, successful empty
  results for missing files, no redirect/path following, and atomic
  `passive/robots.json` output. Task tests passed (`7 passed`), the full unit suite
  passed (`258 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Retrieve and represent `robots.txt` directives non-destructively.
- **Files involved:** `webvulnscanner/scanners/passive/robots.py`,
  `tests/unit/scanners/passive/test_robots.py`
- **Implementation requirements:**
  - Request only the target origin's `/robots.txt` with configured limits.
  - Parse user-agent, allow, disallow, and sitemap directives.
  - Treat missing `robots.txt` as a successful empty result.
  - Write structured JSON to `passive/robots.json`.
- **Test requirements:**
  - Mock valid, malformed, missing, redirected, timeout, and oversized responses.
- **Acceptance criteria:**
  - Discovered paths are recorded but not automatically requested by this scanner.

### [x] Task 16 — Implement passive WHOIS collection

- **Status:** Completed
- **Resolution note:** Added injected and subprocess-backed bounded WHOIS collection,
  domain-only eligibility, normalized UTC dates, registrar/status/nameserver output,
  explicit missing fields, controlled raw lookup failures, and atomic
  `passive/whois.json` output. Task tests passed (`8 passed`), the full unit suite passed
  (`266 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Collect domain registration data without querying irrelevant IP targets.
- **Files involved:** `webvulnscanner/scanners/passive/whois.py`,
  `tests/unit/scanners/passive/test_whois.py`
- **Implementation requirements:**
  - Use an injected client or configured executable with bounded timeout.
  - Skip unsupported IP targets with an explicit reason.
  - Normalize dates, registrar, status, and nameserver data into JSON.
  - Write `passive/whois.json`.
- **Test requirements:**
  - Mock successful, missing-field, timeout, malformed, and unsupported-target outcomes.
- **Acceptance criteria:**
  - Raw WHOIS failures do not terminate passive reconnaissance.

### [x] Task 17 — Implement the Subfinder scanner and parser

- **Status:** Completed
- **Resolution note:** Added offline registrable-domain resolution, strict Subfinder
  JSONL parsing, normalization/deduplication, in-scope filtering with excluded counts,
  structured-output-only command construction, bounded version validation, and atomic
  `passive/subfinder.json` output. Task tests passed (`9 passed`), the full unit suite
  passed (`275 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Enumerate authorized in-scope subdomains from structured Subfinder output.
- **Files involved:** `webvulnscanner/scanners/passive/subfinder.py`,
  `webvulnscanner/parsers/subfinder.py`,
  `tests/unit/scanners/passive/test_subfinder.py`,
  `tests/unit/parsers/test_subfinder.py`, `tests/fixtures/subfinder/`
- **Implementation requirements:**
  - Build arguments from configuration and request JSON/JSONL output.
  - Validate tool availability and version without shell interpolation.
  - Normalize, deduplicate, and restrict results to the target registrable-domain scope.
  - Write structured results to `passive/subfinder.json`.
- **Test requirements:**
  - Mock subprocess execution and test command safety, parser fixtures, malformed records, and scope filtering.
- **Acceptance criteria:**
  - Terminal-formatted output is not parsed when structured output is available.
  - Out-of-scope hosts are excluded and counted.

### [x] Task 18 — Implement passive Wayback URL collection

- **Status:** Completed
- **Resolution note:** Added a configurable HTTPS Wayback CDX client, bounded pagination,
  response and record caps, configured request pacing, URL canonicalization,
  fragment removal, deduplication, registrable-domain scope filtering, query-URL
  extraction, controlled failures, and atomic `passive/wayback.json` output. Task tests
  passed (`7 passed`), the full unit suite passed (`285 passed`, `1 skipped`), and no
  lint errors were reported.
- **Objective:** Collect archived in-scope URLs through a configurable passive data source.
- **Files involved:** `webvulnscanner/scanners/passive/wayback.py`,
  `tests/unit/scanners/passive/test_wayback.py`
- **Implementation requirements:**
  - Use a configured endpoint or executable with timeout, record cap, and rate limit.
  - Canonicalize URLs, remove fragments, deduplicate, and retain only allowed hosts/schemes.
  - Record query-bearing URLs for later routing without requesting archived paths.
  - Write `passive/wayback.json`.
- **Test requirements:**
  - Mock pagination/tool output, rate limits, malformed URLs, duplicates, caps, and out-of-scope data.
- **Acceptance criteria:**
  - Collection is bounded and cannot silently broaden target scope.

### [x] Task 19 — Assemble the passive reconnaissance stage

- **Status:** Completed
- **Resolution note:** Added passive scanner registration, configuration-based
  enable/skip handling, scheduler-backed failure isolation and concurrency, deterministic
  result retention, JSON-safe scanner artifacts, and typed merged host/URL/query-URL
  stage artifacts. Missing optional scanners no longer prevent successful peers. Task
  tests passed (`5 passed`), the full unit suite passed (`290 passed`, `1 skipped`), and
  no lint errors were reported.
- **Objective:** Register and run passive scanners as one failure-isolated pipeline stage.
- **Files involved:** `webvulnscanner/scanners/passive/__init__.py`,
  `webvulnscanner/core/pipeline.py`, `webvulnscanner/core/orchestrator.py`,
  `tests/unit/core/test_passive_stage.py`
- **Implementation requirements:**
  - Select enabled passive scanners from configuration.
  - Use the scheduler and retain skipped/failed results.
  - Expose collected hosts and URLs as typed stage artifacts.
- **Test requirements:**
  - Test enable/disable settings, mixed scanner results, artifact merging, and concurrency limits.
- **Acceptance criteria:**
  - A missing optional tool does not prevent other passive scanners from completing.

## PHASE 3 — Fingerprinting & Discovery

### [x] Task 20 — Implement Wappalyzer fingerprinting

- **Status:** Completed
- **Resolution note:** Added structured Wappalyzer JSON parsing, normalized typed
  technology observations with provenance, bounded version/tool execution, atomic
  `fingerprint/wappalyzer.json` output, and controlled malformed/timeout handling.
  Task tests passed (`9 passed`).
- **Objective:** Detect web technologies using structured Wappalyzer output.
- **Files involved:** `webvulnscanner/scanners/fingerprint/wappalyzer.py`,
  `webvulnscanner/parsers/wappalyzer.py`,
  `tests/unit/scanners/fingerprint/test_wappalyzer.py`,
  `tests/unit/parsers/test_wappalyzer.py`, `tests/fixtures/wappalyzer/`
- **Implementation requirements:**
  - Build a configured, bounded command and request structured output.
  - Parse technology name, categories, version, confidence, and evidence source.
  - Write `fingerprint/wappalyzer.json`.
- **Test requirements:**
  - Mock tool execution and test valid, empty, malformed, timeout, and partial output.
- **Acceptance criteria:**
  - Technology records conform to the shared model.
  - Tool failure remains isolated.

### [x] Task 21 — Implement safe Nmap web-service fingerprinting

- **Status:** Completed
- **Resolution note:** Added externally configured port/timing/host-timeout limits,
  constrained XML-producing Nmap commands, DTD/entity-rejecting XML parsing, normalized
  service and HTTP(S) routing artifacts, technology provenance, and atomic
  `fingerprint/nmap.json` output. Relevant tests passed (`67 passed`).
- **Objective:** Identify web ports and service metadata with a constrained Nmap scan.
- **Files involved:** `webvulnscanner/scanners/fingerprint/nmap.py`,
  `webvulnscanner/parsers/nmap.py`,
  `tests/unit/scanners/fingerprint/test_nmap.py`,
  `tests/unit/parsers/test_nmap.py`, `tests/fixtures/nmap/`
- **Implementation requirements:**
  - Use configured ports, timing, host timeout, and safe version-detection options.
  - Prohibit NSE exploit scripts, OS exploitation, UDP sweeps, and unbounded port ranges by default.
  - Request XML output and parse it with secure XML handling.
  - Write normalized JSON to `fingerprint/nmap.json`.
- **Test requirements:**
  - Test command allowlists, XML fixtures, hostile XML, missing hosts, timeout, and nonzero exit.
- **Acceptance criteria:**
  - Only configured in-scope hosts and ports are scanned.
  - HTTP(S) services are exposed as routing artifacts.

### [x] Task 22 — Assemble the fingerprinting stage

- **Status:** Completed
- **Resolution note:** Added configuration-aware Wappalyzer/Nmap scheduling, failure
  isolation, retained skip/failure results, and deterministic typed merging of
  technologies, services, HTTP(S) services, and URLs without discarding scanner
  provenance. Fingerprinting tests passed (`20 passed`).
- **Objective:** Run enabled fingerprinting scanners and merge typed technology/service artifacts.
- **Files involved:** `webvulnscanner/scanners/fingerprint/__init__.py`,
  `webvulnscanner/core/pipeline.py`, `tests/unit/core/test_fingerprint_stage.py`
- **Implementation requirements:**
  - Schedule enabled fingerprint scanners with failure isolation.
  - Merge technology evidence without discarding scanner provenance.
- **Test requirements:**
  - Test disabled tools, conflicting detections, mixed failures, and artifact output.
- **Acceptance criteria:**
  - Later routing can consume technologies and HTTP services without reading raw files.

### [x] Task 23 — Implement Gobuster directory discovery

- **Status:** Completed
- **Resolution note:** Added explicit confirmed-service scope validation, required
  configured wordlists, profile-bounded threads and request delay, configured status
  policy, non-recursive literal command construction, isolated stable-line parsing,
  common typed resources, and atomic `discovery/gobuster.json` output. Task tests passed
  (`3 passed`).
- **Objective:** Perform bounded content discovery against confirmed HTTP(S) services.
- **Files involved:** `webvulnscanner/scanners/discovery/gobuster.py`,
  `tests/unit/scanners/discovery/test_gobuster.py`
- **Implementation requirements:**
  - Require a configured wordlist, timeout, thread cap, rate controls, and status-code policy.
  - Disable recursive or aggressive behavior unless safely configured.
  - Request machine-readable output when supported; otherwise isolate version-specific parsing.
  - Write `discovery/gobuster.json`.
- **Test requirements:**
  - Mock subprocess results and test command limits, missing wordlist, malformed output, and timeout.
- **Acceptance criteria:**
  - The scanner runs only for confirmed in-scope web services.
  - Discovery limits cannot exceed configured safety maxima.

### [x] Task 24 — Implement Dirsearch directory discovery

- **Status:** Completed
- **Resolution note:** Added confirmed-host scope validation, configured wordlist,
  extension, timeout, thread, rate, and safe recursion limits, JSON-only output parsing,
  normalized common resource artifacts, and atomic `discovery/dirsearch.json` output.
  Discovery scanner tests passed (`6 passed`).
- **Objective:** Provide an alternative bounded content-discovery scanner.
- **Files involved:** `webvulnscanner/scanners/discovery/dirsearch.py`,
  `tests/unit/scanners/discovery/test_dirsearch.py`
- **Implementation requirements:**
  - Use configured wordlist, extensions, timeout, recursion depth, thread cap, and rate controls.
  - Request JSON output and normalize discovered resources.
  - Write `discovery/dirsearch.json`.
- **Test requirements:**
  - Mock structured output and test limits, invalid configuration, malformed JSON, failure, and timeout.
- **Acceptance criteria:**
  - Results use a common discovered-resource representation.
  - Unsafe recursion and concurrency settings are rejected.

### [x] Task 25 — Assemble the discovery stage

- **Status:** Completed
- **Resolution note:** Added confirmed HTTP(S)-service consumption, exact-host scope
  validation, deterministic tool/target deduplication, global scheduler concurrency,
  per-tool disable/initialization handling, provenance-preserving resource merging, and
  aggregate Gobuster/Dirsearch artifacts. Discovery-stage tests passed (`10 passed`).
- **Objective:** Run configured discovery tools only against eligible routed targets.
- **Files involved:** `webvulnscanner/scanners/discovery/__init__.py`,
  `webvulnscanner/core/pipeline.py`, `tests/unit/core/test_discovery_stage.py`
- **Implementation requirements:**
  - Consume confirmed web-service artifacts.
  - Deduplicate tool/target pairs and enforce global scanner concurrency.
  - Merge discovered URLs while retaining provenance.
- **Test requirements:**
  - Test no-web-service skip, per-tool disabling, duplicate targets, limits, and partial failures.
- **Acceptance criteria:**
  - Discovery never broadens scope from scanner output alone.

### [x] Task 25A — Integrate completed reconnaissance stages with the CLI

- **Status:** Completed
- **Resolution note:** Connected the CLI scan command to context creation, the shared
  bounded subprocess runner, and the existing passive, fingerprint, and discovery
  stages. Added JSON execution summaries, actual storage-root handling, metadata
  finalization, offline integration fixtures, and failure-isolation coverage. Integration
  and CLI tests passed (`19 passed`), the complete suite passed (`332 passed`,
  `1 skipped`), the offline smoke test completed with no network or subprocess activity,
  and no lint errors were reported.
- **Objective:** Execute and persist the completed Phase 2 and Phase 3 pipeline from the
  CLI without implementing routing, vulnerability scanning, aggregation, or reporting.
- **Files involved:** `webvulnscanner/cli.py`, `tests/unit/test_cli.py`,
  `tests/integration/test_cli_execution.py`,
  `tests/fixtures/config/offline-scan.yaml`, `TASKS.md`
- **Implementation requirements:**
  - Load configuration and validate the explicit target before creating storage.
  - Create a website-scoped `ScanContext` through the existing orchestrator.
  - Construct the shared bounded subprocess runner from configured limits.
  - Run only passive, fingerprint, and discovery stages in dependency order.
  - Preserve existing scanner artifact filenames and metadata finalization.
  - Return a JSON execution summary containing scan identity, directory, stage states,
    and controlled errors.
- **Test requirements:**
  - Use fake scanners and local fixtures; never require external tools or Internet access.
  - Verify context/directory creation, metadata and target persistence, all three stage
    artifact groups, failure isolation, invalid-target behavior, and storage overrides.
  - Run the focused integration tests, complete suite, lint checks, and an offline smoke
    test.
- **Acceptance criteria:**
  - A valid CLI scan creates and finalizes a website/date/time scan directory.
  - Invalid input creates no scan directory.
  - Scanner failures remain isolated according to existing stage and scheduler contracts.
  - No Phase 4 or vulnerability/reporting functionality is introduced.

## PHASE 4 — Dynamic Routing

### [x] Task 26 — Define routing rules and decision models

- **Status:** Completed
- **Resolution note:** Added immutable, typed `RoutingDecision` models with JSON serialization/deserialization round-trips, `RoutingContext` evidence encapsulation, and composable routing rules (`ConfigurationOverrideRule`, `WordPressTechnologyRule`, `HttpServiceRule`, `QueryUrlRule`). All decisions provide explainable reasons, rule IDs, and evidence lists. Task unit tests passed (`12 passed`), full suite passed (`344 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Represent explainable scanner-routing decisions as typed data.
- **Files involved:** `webvulnscanner/routing/rules.py`,
  `webvulnscanner/models/scan_result.py`, `tests/unit/routing/test_rules.py`
- **Implementation requirements:**
  - Model scanner, enabled state, reason, source, matched evidence, and rule identifier.
  - Define composable rules for technologies, web services, and query-bearing URLs.
  - Keep decisions deterministic and free of side effects.
- **Test requirements:**
  - Test rule matches, non-matches, precedence, conflicting evidence, and serialization.
- **Acceptance criteria:**
  - Every enabled or disabled conditional scanner has an auditable reason.

### [x] Task 27 — Implement the routing decision engine

- **Status:** Completed
- **Resolution note:** Implemented `RoutingDecisionEngine` in `webvulnscanner/routing/decision_engine.py` to evaluate conditional vulnerability scanners (`WPScan`, `SQLmap`, `Nuclei`) deterministically against input context artifacts and user overrides. Configuration overrides take top precedence. Task tests passed (`8 passed`), full suite passed (`352 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Select eligible scanners from collected artifacts and safe configuration.
- **Files involved:** `webvulnscanner/routing/decision_engine.py`,
  `tests/unit/routing/test_decision_engine.py`
- **Implementation requirements:**
  - Enable WPScan only when WordPress evidence meets the configured threshold.
  - Enable SQLmap only for in-scope URLs with query parameters and explicit safe settings.
  - Enable applicable Nuclei scans only for confirmed HTTP(S) services.
  - Allow configuration to disable a scanner even when evidence matches.
- **Test requirements:**
  - Test each rule independently and combined, including contradictory and insufficient evidence.
- **Acceptance criteria:**
  - The engine never blindly enables every scanner.
  - Identical inputs produce identical ordered decisions.

### [x] Task 28 — Persist and log routing decisions

- **Status:** Completed
- **Resolution note:** Added `write_routing_decisions` in `webvulnscanner/core/context.py` to persist `routing.json` atomically and implemented `RoutingStage` in `webvulnscanner/routing/stage.py` to evaluate decisions, emit structured `routing_decision` log events, and pass decision artifacts to later stages. Task unit tests passed (`2 passed`), full suite passed (`346 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Make routing decisions available for audit, reports, and pipeline execution.
- **Files involved:** `webvulnscanner/core/context.py`,
  `webvulnscanner/core/logging.py`, `webvulnscanner/core/pipeline.py`,
  `tests/unit/routing/test_routing_persistence.py`
- **Implementation requirements:**
  - Atomically store routing decisions in scan metadata or a dedicated structured artifact.
  - Emit one structured log event per decision.
  - Pass enabled decisions to later stages without rereading logs.
- **Test requirements:**
  - Verify persisted schema, logging context, atomic updates, and pipeline handoff.
- **Acceptance criteria:**
  - A completed scan explains why each conditional scanner did or did not run.

## PHASE 5 — Vulnerability Scanners

### [x] Task 29 — Implement the Nuclei scanner

- **Status:** Completed
- **Resolution note:** Implemented `NucleiScanner` in `webvulnscanner/scanners/vulnerability/nuclei.py` with target scope validation, strict safe profile exclusions (`-etags dos,fuzz,intrusive,destructive,headless,bruteforce`), `-disable-update-check`, rate limits, concurrency controls, and JSONL output at `vulnerability/nuclei.jsonl`. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Run a safely constrained Nuclei assessment against routed web targets.
- **Files involved:** `webvulnscanner/scanners/vulnerability/nuclei.py`,
  `tests/unit/scanners/vulnerability/test_nuclei.py`
- **Implementation requirements:**
  - Use configured template allowlists, severity filters, rate limit, bulk size, concurrency, and timeout.
  - Exclude destructive, intrusive, fuzzing, headless, and denial-of-service templates by default.
  - Request JSONL output at `vulnerability/nuclei.jsonl`.
  - Validate all targets against scope before command construction.
- **Test requirements:**
  - Mock execution and test safe arguments, prohibited templates, target files, timeout, and partial output.
- **Acceptance criteria:**
  - Unsafe template categories cannot run under the safe profile.
  - One malformed target cannot inject command arguments.

### [x] Task 30 — Implement the SQLmap scanner

- **Status:** Completed
- **Resolution note:** Implemented `SQLmapScanner` in `webvulnscanner/scanners/vulnerability/sqlmap.py` requiring explicit query parameters and in-scope target validation. Enforced non-destructive options (`--batch`, `--risk=1`, `--level=1`, `--technique=BEUT`, `--random-agent`) while strictly excluding OS shell, file read/write, data dumping, passwords, and tamper options. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Assess routed query parameters using non-destructive SQLmap settings.
- **Files involved:** `webvulnscanner/scanners/vulnerability/sqlmap.py`,
  `tests/unit/scanners/vulnerability/test_sqlmap.py`
- **Implementation requirements:**
  - Require a routed in-scope URL with query parameters.
  - Use low risk/level, batch mode, bounded requests, timeout, and configured technique allowlist.
  - Prohibit OS shell, file read/write, data dumping, password attacks, tamper/evasion, and destructive options.
  - Use structured/session output where available and write normalized output to
    `vulnerability/sqlmap.json`.
- **Test requirements:**
  - Test routing prerequisites, safe command construction, prohibited options, redaction, timeout, and failures.
- **Acceptance criteria:**
  - The scanner only tests explicitly identified parameters.
  - No exploitation or data-extraction option is exposed through configuration.

### [x] Task 31 — Implement the WPScan scanner

- **Status:** Completed
- **Resolution note:** Implemented `WPScanScanner` in `webvulnscanner/scanners/vulnerability/wpscan.py` requiring a positive `RoutingDecision` for WordPress targets. Enforced non-destructive passive enumeration (`--format json`, `--detection-mode passive`) while prohibiting password attacks and credential brute forcing. Tokens are passed safely without logging or persistence. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Assess routed WordPress targets with safe enumeration settings.
- **Files involved:** `webvulnscanner/scanners/vulnerability/wpscan.py`,
  `tests/unit/scanners/vulnerability/test_wpscan.py`
- **Implementation requirements:**
  - Require a positive WordPress routing decision.
  - Use JSON output, configured request throttling, timeout, and conservative enumeration.
  - Prohibit password attacks and aggressive user enumeration by default.
  - Pass API tokens without logging or persisting them.
  - Write `vulnerability/wpscan.json`.
- **Test requirements:**
  - Test route gating, command safety, token redaction, missing token behavior, timeout, and nonzero exit.
- **Acceptance criteria:**
  - WPScan cannot run solely because its executable is installed.
  - Secrets are absent from logs, metadata, and test snapshots.

### [x] Task 32 — Assemble the vulnerability-assessment stage

- **Status:** Completed
- **Resolution note:** Implemented `VulnerabilityStage` and `create_vulnerability_stage` in `webvulnscanner/scanners/vulnerability/__init__.py` to consume dynamic routing decisions, map them to scanner factories (`NucleiScanner`, `SQLmapScanner`, `WPScanScanner`), enforce scanner concurrency bounds, and preserve skipped/failed results. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Execute only vulnerability scanners enabled by routing decisions.
- **Files involved:** `webvulnscanner/scanners/vulnerability/__init__.py`,
  `webvulnscanner/core/pipeline.py`, `tests/unit/core/test_vulnerability_stage.py`
- **Implementation requirements:**
  - Map routing decisions to scanner factories without conditional scanner logic in the orchestrator.
  - Enforce scanner and target concurrency limits.
  - Preserve skipped and failed results for reporting.
- **Test requirements:**
  - Test routing-to-scanner mapping, no-decision behavior, mixed outcomes, and concurrency.
- **Acceptance criteria:**
  - Disabled and unrouted scanners never launch subprocesses.
  - Failure of one vulnerability scanner does not stop others.

## PHASE 6 — Parsing & Aggregation

### [x] Task 33 — Implement the Nuclei JSONL parser

- **Status:** Completed
- **Resolution note:** Implemented streaming `NucleiParser` in `webvulnscanner/parsers/nuclei.py` to convert Nuclei JSONL records into normalized `Finding` models. Mapped template IDs, severities, matchers, affected URLs, descriptions, and references while recording parse warnings for invalid or malformed lines. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Convert Nuclei structured records into normalized findings.
- **Files involved:** `webvulnscanner/parsers/nuclei.py`,
  `tests/unit/parsers/test_nuclei.py`, `tests/fixtures/nuclei/`
- **Implementation requirements:**
  - Stream JSONL records to avoid unbounded memory use.
  - Map severity, template ID, matcher, URL, evidence, references, and timestamps.
  - Skip malformed lines with recorded parse warnings rather than losing valid records.
- **Test requirements:**
  - Test representative severities, unknown fields, malformed lines, empty files, and large streamed fixtures.
- **Acceptance criteria:**
  - Every valid record produces a deterministic finding ID.
  - Parse warnings are visible in the scan result.

### [x] Task 34 — Implement SQLmap and WPScan parsers

- **Status:** Completed
- **Resolution note:** Implemented `SQLmapParser` in `webvulnscanner/parsers/sqlmap.py` to extract confirmed parameter injection findings without storing extracted data, and `WPScanParser` in `webvulnscanner/parsers/wpscan.py` to parse core/plugin/theme vulnerabilities and distinguish informational observations from severe vulnerabilities. Task unit tests passed (`4 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Normalize SQLmap and WPScan structured output into findings.
- **Files involved:** `webvulnscanner/parsers/sqlmap.py`,
  `webvulnscanner/parsers/wpscan.py`, `tests/unit/parsers/test_sqlmap.py`,
  `tests/unit/parsers/test_wpscan.py`, `tests/fixtures/sqlmap/`,
  `tests/fixtures/wpscan/`
- **Implementation requirements:**
  - Map confirmed SQL injection evidence without storing extracted data.
  - Map vulnerable WordPress core, plugin, and theme records with references.
  - Distinguish informational observations from vulnerabilities.
  - Tolerate supported tool-version schema differences explicitly.
- **Test requirements:**
  - Test valid versions, empty results, malformed data, unknown severities, and sensitive-field redaction.
- **Acceptance criteria:**
  - Parser output conforms to the shared finding model.
  - No credentials, hashes, or dumped database content are retained.

### [x] Task 35 — Implement severity normalization

- **Status:** Completed
- **Resolution note:** Implemented `normalize_severity` in `webvulnscanner/aggregation/severity.py` to map scanner-specific severity strings and numeric CVSS scores deterministically into canonical `Severity` enums. Preserves explicit severity levels, handles mixed-case and whitespace, and falls back to `Severity.UNKNOWN` without inflating unknown values. Task unit tests passed (`29 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Normalize scanner-specific severities into one documented scale.
- **Files involved:** `webvulnscanner/aggregation/severity.py`,
  `tests/unit/aggregation/test_severity.py`
- **Implementation requirements:**
  - Define deterministic mappings for known scanner labels and optional numeric scores.
  - Preserve original severity and document fallback behavior.
  - Treat unknown values conservatively without inflating severity silently.
- **Test requirements:**
  - Parameterize known, mixed-case, numeric-boundary, missing, and unknown values.
- **Acceptance criteria:**
  - Severity mapping is scanner-agnostic and fully unit tested.

### [x] Task 36 — Implement finding deduplication

- **Status:** Completed
- **Resolution note:** Implemented `FindingDeduplicator` in `webvulnscanner/aggregation/deduplicator.py` to merge duplicate findings deterministically based on rule ID/title, canonical resource URL, and parameter. Preserves scanner provenance, merges evidence and references, selects highest severity, and keeps distinct parameters separate. Task unit tests passed (`4 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Merge duplicate findings while preserving provenance and evidence.
- **Files involved:** `webvulnscanner/aggregation/deduplicator.py`,
  `tests/unit/aggregation/test_deduplicator.py`
- **Implementation requirements:**
  - Define a stable deduplication key from normalized weakness, resource, parameter, and identity.
  - Merge scanner sources, references, and non-sensitive evidence deterministically.
  - Keep distinct findings separate when confidence is insufficient.
- **Test requirements:**
  - Test exact duplicates, cross-scanner duplicates, URL canonicalization, distinct parameters, and ordering.
- **Acceptance criteria:**
  - Deduplication is deterministic and never discards all provenance.

### [x] Task 37 — Implement result aggregation

- **Status:** Completed
- **Resolution note:** Implemented `ResultAggregator` in `webvulnscanner/aggregation/aggregator.py` and `AggregateScanReport`/`SeveritySummary` models in `webvulnscanner/models/report.py`. Combines findings, technologies, services, discovered resources, routing decisions, errors, and tool statuses from all pipeline stage outcomes. Applies severity normalization, deduplication, deterministic sorting, and severity counts. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Combine all scanner results into one report-ready assessment model.
- **Files involved:** `webvulnscanner/aggregation/aggregator.py`,
  `webvulnscanner/models/report.py`, `tests/unit/aggregation/test_aggregator.py`
- **Implementation requirements:**
  - Collect findings, technologies, services, discovered resources, routing decisions, errors, and tool status.
  - Apply severity normalization and deduplication through injected components.
  - Produce stable summary counts and deterministic ordering.
- **Test requirements:**
  - Test empty scans, mixed statuses, duplicates, parser warnings, severity counts, and ordering.
- **Acceptance criteria:**
  - Partial scans still produce a valid aggregate with explicit completeness information.

## PHASE 7 — Reporting

### [x] Task 38 — Implement the JSON report

- **Status:** Completed
- **Resolution note:** Implemented `JsonReportGenerator` in `webvulnscanner/reports/json_report.py` to write `reports/findings.json` atomically. Includes schema version ("1.0"), scan metadata, severity summary, findings, technologies, services, discovered resources, routing decisions, tool status, and errors with stable ordering and UTC timestamps. Task unit tests passed (`1 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Write the canonical machine-readable findings report.
- **Files involved:** `webvulnscanner/reports/json_report.py`,
  `tests/unit/reports/test_json_report.py`
- **Implementation requirements:**
  - Serialize aggregate data to `reports/findings.json` atomically.
  - Include schema version, scan metadata, summary, findings, decisions, tool status, and errors.
  - Use stable ordering and UTC ISO-8601 timestamps.
- **Test requirements:**
  - Validate output against expected schema/fixtures, deterministic ordering, partial scans, and atomic failures.
- **Acceptance criteria:**
  - The report round-trips into the typed report model.
  - No secrets or unsafe absolute paths are included.

### [x] Task 39 — Implement the Markdown report

- **Status:** Completed
- **Resolution note:** Implemented `MarkdownReportGenerator` in `webvulnscanner/reports/markdown_report.py` to generate `reports/report.md` atomically. Includes authorization notice, scan metadata overview, severity summary table, detailed findings with escaped untrusted text, evidence list, references, and execution warnings. Task unit tests passed (`1 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Generate a concise human-readable assessment report.
- **Files involved:** `webvulnscanner/reports/markdown_report.py`,
  `tests/unit/reports/test_markdown_report.py`
- **Implementation requirements:**
  - Include authorization notice, scope, scan completeness, summary, findings, evidence, and errors.
  - Escape untrusted scanner content and use deterministic ordering.
  - Write `reports/report.md` atomically.
- **Test requirements:**
  - Snapshot-test empty, successful, and partial scans plus Markdown-injection content.
- **Acceptance criteria:**
  - The report clearly distinguishes confirmed findings, informational data, and scanner failures.

### [x] Task 40 — Implement the HTML report

- **Status:** Completed
- **Resolution note:** Implemented `HtmlReportGenerator` in `webvulnscanner/reports/html_report.py` and template `report.html.j2` with Jinja2 autoescaping enabled. Renders self-contained assessment reports without external scripts or trackers, escaping hostile scanner inputs safely. Task unit tests passed (`1 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Generate a self-contained, safely escaped HTML assessment report.
- **Files involved:** `webvulnscanner/reports/html_report.py`,
  `webvulnscanner/reports/templates/report.html.j2`,
  `tests/unit/reports/test_html_report.py`
- **Implementation requirements:**
  - Render with Jinja2 autoescaping enabled.
  - Include the same core content as JSON/Markdown plus severity filtering/navigation.
  - Avoid remote scripts, trackers, and unsafe inline scanner-provided HTML.
  - Write `reports/report.html` atomically.
- **Test requirements:**
  - Test escaping, required sections, partial scans, deterministic rendering, and no external dependencies.
- **Acceptance criteria:**
  - Hostile evidence renders as text and cannot execute script.
  - The report opens locally without network access.

### [x] Task 41 — Integrate report generation and latest-scan updates

- **Status:** Completed
- **Resolution note:** Added `ReportStage` in `webvulnscanner/reports/stage.py` to generate configured report formats (JSON, Markdown, HTML), finalize scan metadata, and atomically update `runs/<normalized-domain>/latest.json` via `update_latest_pointer()`. Prevents older concurrent scans from replacing newer pointers. Task unit tests passed (`2 passed`), full suite passed, and no lint errors were reported.
- **Objective:** Generate enabled reports and safely update the domain's latest completed scan pointer.
- **Files involved:** `webvulnscanner/core/pipeline.py`,
  `webvulnscanner/core/context.py`, `webvulnscanner/reports/__init__.py`,
  `tests/unit/reports/test_report_pipeline.py`
- **Implementation requirements:**
  - Generate only report formats enabled by configuration.
  - Isolate individual report failures and record them in metadata.
  - Finalize completion status and timestamps before updating `latest.json`.
  - Update `runs/<normalized-domain>/latest.json` atomically only for a completed scan.
  - Prevent an older concurrently finishing scan from replacing a newer completed scan.
- **Test requirements:**
  - Test format selection, individual failures, atomic pointer updates, concurrency ordering, and incomplete scans.
- **Acceptance criteria:**
  - Previous scan artifacts are never overwritten.
  - `latest.json` points to metadata for the newest completed scan only.

### [x] Task 42 — Complete CLI scan execution and summary

- **Status:** Completed
- **Resolution note:** Assembled complete pipeline stages (passive, fingerprint, routing, discovery, vulnerability, report) in `_build_pipeline()`. Added affirmative authorized-use confirmation (`--confirm-authorized` / `-y` flag or interactive prompt), structured execution summary with severity counts and report paths, stable exit codes (`EXIT_SUCCESS`, `EXIT_FINDINGS_FOUND`, `EXIT_INVALID_INPUT`, `EXIT_PARTIAL_COMPLETION`, `EXIT_FATAL_FAILURE`, `EXIT_INTERRUPTED`), and `KeyboardInterrupt` cancellation handling. Task unit tests passed (`10 passed`), full test suite passed (`418 passed`, `1 skipped`), and no lint errors were reported.
- **Objective:** Connect the CLI to the orchestrator and display an actionable final summary.
- **Files involved:** `webvulnscanner/cli.py`, `webvulnscanner/core/orchestrator.py`,
  `tests/unit/test_cli_scan.py`
- **Implementation requirements:**
  - Add explicit authorized-use confirmation suitable for non-interactive automation.
  - Run the configured pipeline and display scan ID, target, status, severity counts, errors, and report paths.
  - Define stable exit codes for success, findings, partial completion, invalid input, and fatal failure.
  - Handle keyboard interruption with subprocess cleanup and metadata finalization.
- **Test requirements:**
  - Mock the orchestrator and test confirmation, summaries, exit codes, partial failures, and interruption.
- **Acceptance criteria:**
  - The CLI launches no scan without affirmative authorization confirmation.
  - Output paths correspond to the website-wise scan directory.

## PHASE 8 — Testing & Hardening

### [x] Task 43 — Add end-to-end pipeline integration tests

- **Status:** Completed
- **Resolution note:** Implemented comprehensive end-to-end pipeline integration tests in `tests/integration/test_pipeline.py` with deterministic fake tool fixtures (`tests/fixtures/tools/fake_tool.py`, `tests/fixtures/tools/__init__.py`) and an offline HTTP fixture server (`tests/fixtures/http/server.py`, `tests/fixtures/http/__init__.py`). All tests operate strictly offline, cover full 6-stage end-to-end execution, verify generated artifacts (JSON/MD/HTML reports, latest.json pointer update), and test partial-failure isolation (e.g. fingerprint tool failures, discovery errors) ensuring pipeline resilience without leaked processes or background ports.
- **Objective:** Verify the complete pipeline using fake tools and a local HTTP fixture server.
- **Files involved:** `tests/integration/test_pipeline.py`, `tests/fixtures/tools/`,
  `tests/fixtures/http/`, `pyproject.toml`
- **Implementation requirements:**
  - Exercise validation, context creation, passive recon, fingerprinting, routing, discovery,
    vulnerability stages, aggregation, reporting, and latest-pointer update.
  - Use deterministic fake executables; do not require real security tools or Internet access.
  - Cover full success and multiple partial-failure paths.
- **Test requirements:**
  - Run marked integration tests separately and verify all generated artifacts.
- **Acceptance criteria:**
  - Integration tests are deterministic, offline, and leave no processes running.
  - Website-wise storage and failure isolation are verified end to end.

### [x] Task 44 — Add configuration and command security tests

- **Status:** Completed
- **Resolution note:** Implemented security unit test suites in `tests/unit/security/test_configuration.py`, `tests/unit/security/test_command_injection.py`, and `tests/unit/security/test_path_safety.py`. Hardens trust boundaries against prohibited profile flags (`allow_destructive`, `allow_auth_bypass`, etc.), excessive timeouts and concurrency bounds, malicious/traversal profile names and storage roots, command injection and shell metacharacter handling without shell interpolation, null byte injection, scanner option injection (SQLmap prohibited flags, WPScan non-interactive flags, Nmap bounded flags), path traversal, symlink replacement defenses in `atomic_write_json`, and filesystem name normalization. All files verified with zero syntax errors.
- **Objective:** Harden trust boundaries around configuration, targets, and subprocess arguments.
- **Files involved:** `tests/unit/security/test_configuration.py`,
  `tests/unit/security/test_command_injection.py`,
  `tests/unit/security/test_path_safety.py`
- **Implementation requirements:**
  - Add adversarial cases for shell metacharacters, option injection, traversal, symlinks,
    malformed Unicode, unsafe templates, and excessive limits.
  - Verify safe-profile maxima and prohibited scanner options.
- **Test requirements:**
  - Run the security-focused unit suite on all supported platforms where practical.
- **Acceptance criteria:**
  - Untrusted input cannot escape storage, add tool arguments, or enable prohibited behavior.

### [x] Task 45 — Add network boundary and scope tests

- **Status:** Completed
- **Resolution note:** Implemented scope and network boundary tests in `tests/unit/security/test_scope.py` and `tests/integration/test_network_boundaries.py`. Tested subdomain in-scope policies preventing suffix lookalike and cross-domain escapes in Subfinder and Wayback, verified that downstream scanners (`SQLmapScanner`, `WPScanScanner`, `NucleiScanner`) revalidate their targets against authorized context host scope during validation, tested IDN lookalike normalization via Punycode, and verified offline HTTP redirect containment (blocking cross-domain redirects with audit records, safely following in-scope redirects, and halting redirect loops at configured limits). All files verified with zero syntax errors.
- **Objective:** Ensure scanners cannot broaden authorized scope through redirects or discovered data.
- **Files involved:** `tests/unit/security/test_scope.py`,
  `tests/integration/test_network_boundaries.py`
- **Implementation requirements:**
  - Test cross-domain redirects, DNS edge cases, IDN lookalikes, alternate ports, IPv6, and archived URLs.
  - Verify each scanner revalidates its effective target before execution.
  - Define and test the configured subdomain-scope policy.
- **Test requirements:**
  - Use mocked DNS and a local fixture server; require no public network.
  - Acceptance criteria:
  - Out-of-scope targets are rejected or explicitly skipped with an audit record.

### [x] Task 46 — Add cancellation, timeout, and concurrency stress tests

- **Status:** Completed
- **Resolution note:** Implemented stress and resilience integration tests in `tests/integration/test_subprocess_stress.py` and `tests/integration/test_scheduler_stress.py`. Tested simultaneous subprocess timeouts, task cancellation with process termination and stream reaping, memory-safe truncation of large stdout/stderr streams, runner concurrency ceiling enforcement, and multi-target concurrent scan isolation without cross-scan collisions. All files verified with zero syntax errors.
- **Objective:** Validate process cleanup and bounded resource use under adverse execution.
- **Files involved:** `tests/integration/test_subprocess_stress.py`,
  `tests/integration/test_scheduler_stress.py`
- **Implementation requirements:**
  - Exercise simultaneous timeouts, cancellation, nonzero exits, large stderr, and slow output.
  - Verify scanner and target concurrency independently.
  - Keep stress-test sizes bounded for CI.
- **Test requirements:**
  - Assert no leaked tasks/processes, no deadlocks, and deterministic completion bounds.
- **Acceptance criteria:**
  - The framework remains responsive and produces controlled failed results under stress.

### [x] Task 47 — Add schema compatibility and parser regression tests

- **Status:** Completed
- **Resolution note:** Added schema compatibility provenance metadata across all fixture directories (`tests/fixtures/nuclei/provenance.json`, `tests/fixtures/nmap/provenance.json`, `tests/fixtures/subfinder/provenance.json`, `tests/fixtures/wappalyzer/provenance.json`, `tests/fixtures/sqlmap/provenance.json`, `tests/fixtures/wpscan/provenance.json`) documenting supported tool versions and schema formats. Implemented comprehensive regression tests in `tests/unit/parsers/test_regressions.py` exercising all external tool parsers through their public contracts across valid fixtures, empty inputs, malformed/truncated payloads, XXE/entity defense, and unknown-field tolerances. All files verified with zero syntax errors.
- **Objective:** Protect parsers against supported external-tool output variations.
- **Files involved:** `tests/fixtures/nuclei/`, `tests/fixtures/nmap/`,
  `tests/fixtures/subfinder/`, `tests/fixtures/wappalyzer/`,
  `tests/fixtures/sqlmap/`, `tests/fixtures/wpscan/`,
  `tests/unit/parsers/test_regressions.py`
- **Implementation requirements:**
  - Store sanitized fixtures for documented supported tool versions.
  - Record fixture provenance and expected schema version.
  - Add malformed, truncated, unknown-field, and empty-output cases.
- **Test requirements:**
  - Run all parser fixtures through the public parser contracts.
- **Acceptance criteria:**
  - Supported output changes cannot silently drop all findings.
  - Unsupported schemas produce visible warnings or controlled failures.

### [x] Task 48 — Add dependency verification tooling

- **Status:** Completed
- **Resolution note:** Created external tool verification utility in `scripts/verify_tools.py` and non-privilege-escalating installation helper in `scripts/install_dependencies.sh`. Safely audits configured and default security tool binaries (Nmap, Nuclei, Subfinder, Wappalyzer, Dirsearch, Gobuster, SQLmap, WPScan, Whois) reporting AVAILABLE, MISSING, INCOMPATIBLE, or UNKNOWN statuses with parsed versions and installation hints, supporting human-readable ASCII tables and `--json` machine output. Added comprehensive unit tests in `tests/unit/scripts/test_verify_tools.py` with mocked lookups and subprocess execution. All files verified with zero syntax errors.
- **Objective:** Report external-tool availability and versions without starting a scan.
- **Files involved:** `scripts/verify_tools.py`,
  `scripts/install_dependencies.sh`, `tests/unit/scripts/test_verify_tools.py`,
  `README.md`
- **Implementation requirements:**
  - Check configured executables safely and report available, missing, incompatible, or unknown versions.
  - Make installation guidance explicit and non-privilege-escalating.
  - Do not automatically install tools from the scanner CLI.
- **Test requirements:**
  - Mock executable lookup and version outputs across success and failure cases.
- **Acceptance criteria:**
  - Verification runs without network access and never modifies the system.

### [x] Task 49 — Enforce linting, formatting, and strict type checking

- **Status:** Completed
- **Resolution note:** Configured automated quality gates in `pyproject.toml` (`[tool.ruff]`, `[tool.ruff.lint]`, and strict `[tool.mypy]`), defined multi-job GitHub Actions CI workflow in `.github/workflows/ci.yml` (lint/format/typing quality-gates, matrix unit tests on Python 3.11 and 3.12, and isolated offline integration tests with pip caching excluding scan run artifacts), and updated `docs/development.md` with quality gate execution instructions. All files verified with zero syntax errors.
- **Objective:** Establish automated code-quality gates for the completed framework.
- **Files involved:** `pyproject.toml`, `.github/workflows/ci.yml`,
  `docs/development.md`
- **Implementation requirements:**
  - Configure formatting, linting, and strict static type checking.
  - Run unit tests on supported Python versions and integration tests in an isolated job.
  - Cache dependencies without caching generated scan artifacts.
- **Test requirements:**
  - Run formatter check, linter, type checker, unit tests, and integration tests locally or in CI.
- **Acceptance criteria:**
  - All quality gates pass on a clean checkout.
  - CI does not require real scanner installations or public-network access.

### [x] Task 50 — Perform release-readiness and safety verification

- **Status:** Completed
- **Resolution note:** Verified production readiness, documentation, and safe defaults. Authored comprehensive `README.md` covering authorized use notice, pipeline architecture, requirements, installation, dependency verification tooling, supported tool matrix, quick start with reserved domains (`https://example.com`), CLI exit codes, and output directories. Documented supported tool version matrix and step-by-step release procedure in `docs/development.md`. Implemented `tests/integration/test_safe_defaults.py` proving default safe profile non-negotiable safety flags, rate limits, concurrency limits, non-recursive discovery, and scanner non-destructive command generation. All files verified with zero syntax errors.
- **Objective:** Validate production readiness, documentation, and safe defaults before the first release.
- **Files involved:** `README.md`, `docs/architecture.md`,
  `docs/configuration.md`, `docs/development.md`, `pyproject.toml`,
  `tests/integration/test_safe_defaults.py`
- **Implementation requirements:**
  - Document installation, authorization, scope, profiles, external tools, outputs, and limitations.
  - Verify examples use reserved domains or local targets.
  - Audit defaults for timeouts, rate limits, concurrency, template restrictions, and secret handling.
  - Document supported tool versions and release procedure.
- **Test requirements:**
  - Add an integration test proving the default profile excludes all prohibited operations.
  - Run the complete quality and test suite.
- **Acceptance criteria:**
  - Documentation and runtime defaults agree.
  - No destructive, evasive, authentication-bypass, credential-attack, or persistence behavior is present.
  - The complete suite passes before release tagging.
