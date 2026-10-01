"""Aggregation package for severity normalization, deduplication, and scan summaries."""

from webvulnscanner.aggregation.aggregator import ResultAggregator
from webvulnscanner.aggregation.deduplicator import (
    FindingDeduplicator,
    canonicalize_resource,
)
from webvulnscanner.aggregation.severity import normalize_severity

__all__ = [
    "FindingDeduplicator",
    "ResultAggregator",
    "canonicalize_resource",
    "normalize_severity",
]
