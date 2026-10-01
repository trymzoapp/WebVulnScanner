# WebVulnScanner Development Guide

## Prerequisites

- Python 3.11 or newer
- A virtual environment
- No external scanner is required for unit tests

Install the package and development dependencies:

```shell
python -m pip install -e ".[dev]"
```

## Required task workflow

Development proceeds one task at a time:

1. Read `AGENTS_RULES.md`.
2. Read the requested task and its dependencies in `TASKS.md`.
3. Inspect existing interfaces, configuration, fixtures, and tests.
4. Confirm the change is limited to the requested objective.
5. Implement the smallest complete change that meets the task requirements.
6. Add deterministic tests without requiring installed security tools.
7. Run the relevant tests and configured quality checks.
8. Fix regressions introduced by the task.
9. Report changed files, checks, results, and remaining issues.
10. If all acceptance criteria pass, mark the task and status completed and add its
    resolution note.
11. Stop and wait for the next requested task.

Do not bundle later tasks, opportunistic refactors, or unrelated formatting changes into
the current task. Architecture changes must be necessary for the task and documented.

## Task status and resolution notes

Every task begins as `Pending`. A task becomes `Completed` only when its implementation,
test requirements, and acceptance criteria are satisfied. At completion:

- Change `[ ]` to `[x]`.
- Change `Status: Pending` to `Status: Completed`.
- Replace the resolution placeholder with a concise implementation summary.
- Include the relevant test result and any known limitation.

If environment, access, or another dependency blocks acceptance, keep the task pending
and describe the blocker without starting another task.

## Testing

Run unit tests without integration tests:

```shell
python -m pytest -m "not integration"
```

Run documentation tests directly when changing project guidance:

```shell
python -m pytest tests/unit/test_documentation.py
```

Run integration tests separately:

```shell
python -m pytest -m integration
```

Unit tests must be deterministic and offline. Mock external tools, network clients,
clocks, and identifiers. Mark integration tests with `@pytest.mark.integration`; they
must remain bounded and must not target public systems. Never require Nmap, Nuclei,
SQLmap, WPScan, or another scanner merely to run the unit suite.

## Test design expectations

- Cover success and controlled-failure behavior.
- Add timeout and cancellation coverage for asynchronous/process boundaries.
- Validate malformed and hostile input at trust boundaries.
- Use sanitized structured fixtures under `tests/fixtures/`.
- Assert concurrency and rate limits where applicable.
- Verify sensitive values are absent from logs, metadata, snapshots, and reports.
- Do not depend on wall-clock timing when an injected clock can make a test deterministic.

## Safety requirements

All development assumes authorized use against an explicit scope. Safe defaults are
non-destructive and bounded. Contributions must not:

- bypass authentication, authorization, WAF controls, access controls, or rate limits;
- add destructive payloads, denial-of-service behavior, credential harvesting, password
  attacks, persistence, privilege escalation, or stealth/evasion;
- silently follow redirects or discovered data outside authorized scope;
- expose secrets through command lines, logs, fixtures, metadata, or reports; or
- launch an external tool without configured timeout and concurrency limits.

Prefer structured output such as JSON, NDJSON, or XML. Do not parse decorated terminal
output when a tool provides a structured format.

## Module-boundary checklist

Before submitting a task, confirm:

- Models remain typed and independent from I/O.
- Scanners contain only their own tool-specific behavior.
- Parsers perform no network or process I/O.
- The orchestrator contains no scanner-specific business logic.
- Routing decisions are deterministic and explainable.
- Reports consume aggregate data and never execute scanners.
- External processes use the common asynchronous subprocess abstraction.
- Scanner failures become controlled results and do not crash the complete scan.
- Paths use `pathlib`, remain under the configured root, and cannot traverse directories.
- Configuration owns tool paths, wordlists, timeouts, rates, and concurrency limits.

## Change reporting

At the end of each task, report:

- the task outcome;
- files created or modified;
- tests and quality checks run, including pass/fail counts;
- any unverified acceptance criterion or remaining issue; and
- confirmation that no later task was implemented.

Do not hide failures or claim a check passed when it was not run.
