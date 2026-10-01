# WebVulnScanner Agent Rules

These rules apply to every contributor and automated coding agent working in this
repository.

## Authorized and safe use

- WebVulnScanner is only for assets the operator owns or is explicitly authorized to
  assess.
- Default behavior must be non-destructive, bounded, rate-limited, and scope-aware.
- Never add destructive exploitation, credential harvesting, persistence, privilege
  escalation, denial-of-service behavior, or stealth/evasion mechanisms.
- Never bypass authentication, authorization, WAF controls, access controls, or rate
  limits.
- Do not add an unsafe option merely because it is disabled by default.
- Treat targets, scanner output, configuration, and external-tool output as untrusted
  input.

## Task-by-task development

1. Read `AGENTS_RULES.md` and the requested entry in `TASKS.md`.
2. Inspect existing interfaces and related tests before editing.
3. Implement only the requested task. Do not begin a later task automatically.
4. Do not modify unrelated files or recreate functionality that already exists.
5. Add or update tests required by the task.
6. Run the relevant tests, then configured lint and type checks when available.
7. Report changed files, test results, and unresolved issues.
8. When all acceptance criteria are met, change the task checkbox to `[x]`, set its
   status to `Completed`, and replace the resolution-note placeholder.
9. Stop and wait for the next task.

If a required acceptance criterion is blocked, keep the task status `Pending` and record
the blocker in its resolution note.

## Scope control

- Accept only explicit targets and enforce an auditable target scope.
- Revalidate targets before network access and before launching an external tool.
- Do not broaden scope based solely on redirects, discovered URLs, DNS responses, or
  third-party data.
- Normalize target-derived path components and reject path traversal.
- Keep generated output under the configured website-specific scan directory.
- Do not hardcode credentials, secrets, absolute paths, tool locations, wordlists,
  timeouts, or concurrency limits.

## Architecture boundaries

- `core/` coordinates execution and contains shared infrastructure. It must not contain
  scanner-specific detection rules.
- `config/` owns configuration loading, validation, defaults, and profiles.
- `models/` owns typed data contracts and must not perform I/O.
- `scanners/` owns tool-specific validation, command construction, execution, and
  scanner-level parsing coordination.
- `parsers/` converts structured tool output into typed models and performs no network or
  process I/O.
- `routing/` owns explainable scanner-selection rules and decisions.
- `aggregation/` normalizes, deduplicates, and combines scanner results.
- `reports/` renders aggregate data and does not execute scanners.
- `utils/` contains small reusable helpers with no scanner business logic.

Dependencies should point toward shared contracts: feature modules may depend on
`models/` and narrow `core/` interfaces, while models remain independent of scanners,
routing, aggregation, and reports. Avoid circular imports and global mutable state.

## Scanner and subprocess rules

- Every scanner follows the shared lifecycle: `validate()`, `build_command()`, `run()`,
  `parse()`, and return a typed `ScanResult`.
- Scanner-specific behavior remains inside that scanner's module.
- Scanners must not generate final reports or invoke other scanners directly.
- Execute external tools only through the common asynchronous subprocess abstraction.
- Construct argument arrays without uncontrolled shell execution.
- Every scanner has configured timeout, rate, and concurrency limits.
- Prefer JSON, NDJSON, or XML output. Do not parse terminal text when structured output
  is available.
- Timeouts, cancellation, malformed output, and nonzero exits must become controlled
  scanner failures.
- One scanner failure must never crash the complete scan.

## Testing rules

- Unit tests must not require external security tools, Internet access, or privileged
  access.
- Mock subprocesses, HTTP clients, clocks, IDs, and tool output as appropriate.
- Put deterministic tool samples under `tests/fixtures/`.
- Mark integration tests with `@pytest.mark.integration`.
- Test success, skipped, malformed-input, timeout, cancellation, and controlled-failure
  paths where relevant.
- Do not silently weaken a test to make it pass.

## Data and logging rules

- Use UTC timestamps for persisted metadata.
- Preserve previous scans; never overwrite their artifacts.
- Store results under `runs/<normalized-domain>/<date>/<time>/`.
- Update `latest.json` atomically only after a completed scan.
- Use structured logging with scan and scanner context.
- Redact secrets and sensitive values from commands, logs, errors, metadata, fixtures,
  and reports.
- Do not silently swallow exceptions; retain actionable, bounded error information.

## Code quality

- Target Python 3.11 or newer and use strict typing.
- Prefer small functions, explicit interfaces, dependency injection, and `pathlib`.
- Avoid giant orchestrator functions, duplicated subprocess logic, raw path
  concatenation, and hidden side effects.
- Preserve existing architecture unless the requested task requires a documented change.
