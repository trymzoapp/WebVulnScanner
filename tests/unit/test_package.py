"""Tests for package metadata."""

import re

import webvulnscanner


def test_package_exposes_semantic_version() -> None:
    """The public package version follows a three-part semantic version."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", webvulnscanner.__version__)
