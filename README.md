# WebVulnScanner

WebVulnScanner is a CLI-based framework for authorized web vulnerability assessments.
The project is under incremental development and does not yet contain scanner
implementations.

## Authorized use only

Use this project only against websites and assets you own or have explicit permission
to assess. Its intended defaults are non-destructive, rate-limited, and scope-aware.
It must not be used to bypass authentication, access controls, web application
firewalls, or rate limits.

## Requirements

- Python 3.11 or newer

## Development setup

Create and activate a virtual environment, then install the project and development
dependencies:

```shell
python -m pip install -e ".[dev]"
```

Run unit tests without integration tests:

```shell
python -m pytest -m "not integration"
```

Run integration tests separately:

```shell
python -m pytest -m integration
```

Development is performed one task at a time according to `TASKS.md`.
