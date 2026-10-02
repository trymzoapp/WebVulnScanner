"""Regression tests for required project guidance."""

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("relative_path", "required_headings"),
    [
        (
            "AGENTS_RULES.md",
            {
                "## Authorized and safe use",
                "## Task-by-task development",
                "## Scope control",
                "## Architecture boundaries",
                "## Scanner and subprocess rules",
                "## Testing rules",
            },
        ),
        (
            "docs/architecture.md",
            {
                "## Purpose and safety boundary",
                "## Planned processing pipeline",
                "## Package ownership",
                "## Dependency direction",
                "## Scanner contract",
                "## Failure isolation and resource bounds",
                "## Result storage",
            },
        ),
        (
            "docs/development.md",
            {
                "## Required task workflow",
                "## Task status and resolution notes",
                "## Testing",
                "## Safety requirements",
                "## Module-boundary checklist",
                "## Change reporting",
            },
        ),
    ],
)
def test_guidance_contains_required_headings(
    relative_path: str,
    required_headings: set[str],
) -> None:
    """Each guidance document retains its required contributor-facing sections."""
    content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")

    assert required_headings.issubset(set(content.splitlines()))


@pytest.mark.parametrize(
    "relative_path",
    [
        "AGENTS_RULES.md",
        "docs/architecture.md",
        "docs/development.md",
    ],
)
def test_guidance_states_core_safety_requirements(relative_path: str) -> None:
    """Every guidance document states the project's central safety constraints."""
    content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8").casefold()

    assert "authorized" in content
    assert "non-destructive" in content
    assert "authentication" in content
    assert re.search(r"rate[- ]limit", content)


def test_architecture_documents_failure_isolation_and_scanner_contract() -> None:
    """The architecture keeps scanner behavior bounded and failure-isolated."""
    content = (PROJECT_ROOT / "docs/architecture.md").read_text(encoding="utf-8")

    for method in ("validate()", "build_command()", "run()", "parse()", "ScanResult"):
        assert method in content
    assert "One scanner failure must never crash the complete scan." in (
        PROJECT_ROOT / "AGENTS_RULES.md"
    ).read_text(encoding="utf-8")
