"""Pipeline stage for dynamic routing evaluation, persistence, and logging."""

from __future__ import annotations

import logging
from collections.abc import Mapping

from webvulnscanner.core.context import ScanContext, write_routing_decisions
from webvulnscanner.core.logging import bind_logger, log_event
from webvulnscanner.core.pipeline import (
    FailurePolicy,
    PipelineStage,
    StageName,
    StageOutcome,
    StageStatus,
)
from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology
from webvulnscanner.routing.decision_engine import RoutingDecisionEngine
from webvulnscanner.routing.rules import RoutingContext
from webvulnscanner.utils.time import utc_now


class RoutingStage(PipelineStage):
    """Stage that runs dynamic routing, logs decisions, and persists routing.json."""

    name = StageName.ROUTING
    dependencies: tuple[StageName, ...] = (StageName.PASSIVE, StageName.FINGERPRINT)
    failure_policy = FailurePolicy.CONTINUE

    def __init__(
        self,
        engine: RoutingDecisionEngine | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._engine = engine or RoutingDecisionEngine()
        self._logger = logger

    async def run(
        self,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        started_at = utc_now()
        logger = bind_logger(
            self._logger,
            scan_id=context.scan_id,
            target=context.target.url,
        )

        technologies = self._extract_technologies(previous)
        services = self._extract_services(previous)
        urls = self._extract_urls(previous)
        scanner_configs = context.metadata.scanner_configuration.get("scanners", {})
        if not isinstance(scanner_configs, Mapping):
            scanner_configs = {}

        routing_context = RoutingContext(
            target_url=context.target.url,
            technologies=technologies,
            services=services,
            urls=urls,
            scanner_configs=scanner_configs,
        )

        decisions = self._engine.evaluate(routing_context)

        for decision in decisions:
            log_level = logging.INFO if decision.enabled else logging.DEBUG
            log_event(
                logger,
                log_level,
                event="routing_decision",
                message=f"Routing decision for scanner '{decision.scanner}': enabled={decision.enabled} ({decision.reason})",
                scanner=decision.scanner,
                enabled=decision.enabled,
                reason=decision.reason,
                source=decision.source,
                rule_id=decision.rule_id,
                matched_evidence=list(decision.matched_evidence),
            )

        routing_path = write_routing_decisions(context, decisions)
        enabled_scanners = self._engine.get_enabled_scanners(decisions)

        return StageOutcome(
            name=self.name,
            status=StageStatus.SUCCESS,
            started_at=started_at,
            completed_at=utc_now(),
            artifacts={
                "decisions": [d.to_dict() for d in decisions],
                "enabled_scanners": list(enabled_scanners),
                "routing_file": str(routing_path),
            },
        )

    def _extract_technologies(
        self,
        previous: Mapping[StageName, StageOutcome],
    ) -> tuple[Technology, ...]:
        techs: list[Technology] = []
        fp_outcome = previous.get(StageName.FINGERPRINT)
        if fp_outcome and fp_outcome.artifacts:
            fp_art = fp_outcome.artifacts.get("fingerprint")
            if hasattr(fp_art, "technologies") and isinstance(
                fp_art.technologies, tuple
            ):
                techs.extend(fp_art.technologies)
            raw_techs = fp_outcome.artifacts.get("technologies", [])
            if isinstance(raw_techs, (list, tuple)):
                for item in raw_techs:
                    if isinstance(item, Technology):
                        techs.append(item)
                    elif isinstance(item, Mapping):
                        techs.append(Technology.from_dict(item))
        return tuple(techs)

    def _extract_services(
        self,
        previous: Mapping[StageName, StageOutcome],
    ) -> tuple[WebService, ...]:
        services: list[WebService] = []
        fp_outcome = previous.get(StageName.FINGERPRINT)
        if fp_outcome and fp_outcome.artifacts:
            fp_art = fp_outcome.artifacts.get("fingerprint")
            if hasattr(fp_art, "web_services") and isinstance(
                fp_art.web_services, tuple
            ):
                services.extend(fp_art.web_services)
            elif hasattr(fp_art, "services") and isinstance(fp_art.services, tuple):
                services.extend(fp_art.services)
            raw_services = fp_outcome.artifacts.get("services", [])
            if isinstance(raw_services, (list, tuple)):
                for item in raw_services:
                    if isinstance(item, WebService):
                        services.append(item)
                    elif isinstance(item, Mapping):
                        services.append(WebService.from_dict(item))
        return tuple(services)

    def _extract_urls(
        self,
        previous: Mapping[StageName, StageOutcome],
    ) -> tuple[str, ...]:
        urls: list[str] = []
        for stage_name in (StageName.PASSIVE, StageName.FINGERPRINT):
            outcome = previous.get(stage_name)
            if outcome and outcome.artifacts:
                art = outcome.artifacts.get(stage_name.value)
                if hasattr(art, "query_urls") and isinstance(art.query_urls, tuple):
                    urls.extend(art.query_urls)
                if hasattr(art, "urls") and isinstance(art.urls, tuple):
                    urls.extend(art.urls)
                raw_urls = outcome.artifacts.get("urls", [])
                if isinstance(raw_urls, (list, tuple)):
                    for u in raw_urls:
                        if isinstance(u, str) and u.strip():
                            urls.append(u.strip())
        return tuple(sorted(set(urls)))
