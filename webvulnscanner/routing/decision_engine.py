"""Routing decision engine for evaluating scanner eligibility."""

from __future__ import annotations

from typing import Sequence

from webvulnscanner.models.scan_result import RoutingDecision
from webvulnscanner.routing.rules import (
    ConfigurationOverrideRule,
    HttpServiceRule,
    QueryUrlRule,
    RoutingContext,
    RoutingRule,
    WordPressTechnologyRule,
)


class RoutingDecisionEngine:
    """Engine that evaluates dynamic routing rules deterministically."""

    DEFAULT_CONDITIONAL_SCANNERS: tuple[str, ...] = ("nuclei", "sqlmap", "wpscan")

    def __init__(
        self,
        rules: Sequence[RoutingRule] | None = None,
        target_scanners: Sequence[str] | None = None,
    ) -> None:
        if target_scanners is None:
            self._target_scanners = self.DEFAULT_CONDITIONAL_SCANNERS
        else:
            if any(not isinstance(s, str) or not s.strip() for s in target_scanners):
                raise ValueError("target_scanners must contain only non-empty strings")
            self._target_scanners = tuple(sorted(set(target_scanners)))

        if rules is None:
            self._rules: tuple[RoutingRule, ...] = (
                ConfigurationOverrideRule("nuclei"),
                HttpServiceRule("nuclei"),
                ConfigurationOverrideRule("sqlmap"),
                QueryUrlRule("sqlmap"),
                ConfigurationOverrideRule("wpscan"),
                WordPressTechnologyRule(),
            )
        else:
            if any(not isinstance(r, RoutingRule) for r in rules):
                raise TypeError("rules must contain only RoutingRule instances")
            self._rules = tuple(rules)

    def evaluate(self, context: RoutingContext) -> tuple[RoutingDecision, ...]:
        """Evaluate context against registered rules deterministically."""
        if not isinstance(context, RoutingContext):
            raise TypeError("context must be a RoutingContext instance")

        decisions: list[RoutingDecision] = []

        for scanner in self._target_scanners:
            scanner_decision: RoutingDecision | None = None

            # Check configuration override first
            override_rule = ConfigurationOverrideRule(scanner)
            scanner_decision = override_rule.evaluate(context)

            if scanner_decision is None:
                # Find evidence rule matching scanner
                for rule in self._rules:
                    if isinstance(rule, ConfigurationOverrideRule):
                        continue
                    decision = rule.evaluate(context)
                    if decision is not None and decision.scanner == scanner:
                        scanner_decision = decision
                        break

            if scanner_decision is None:
                scanner_decision = RoutingDecision(
                    scanner=scanner,
                    enabled=False,
                    reason=f"No matching routing rule evaluated for scanner '{scanner}'",
                    source="default",
                    rule_id=f"rule_default_{scanner}",
                    matched_evidence=(),
                )

            decisions.append(scanner_decision)

        return tuple(sorted(decisions, key=lambda d: d.scanner))

    @staticmethod
    def get_enabled_scanners(
        decisions: Sequence[RoutingDecision],
    ) -> tuple[str, ...]:
        """Return sorted list of enabled scanner names from routing decisions."""
        return tuple(
            sorted(
                decision.scanner for decision in decisions if decision.enabled
            )
        )
