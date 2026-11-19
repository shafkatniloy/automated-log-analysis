from collections import defaultdict
from datetime import timedelta
import re
from typing import Dict, List, Optional

from log_analyzer.config import DetectionRule, RulesConfig
from log_analyzer.incidents import Incident
from log_analyzer.models import LogEvent


class DetectionEngine:
    def __init__(self, config: RulesConfig) -> None:
        self.config = config
        self._compiled_patterns: Dict[str, Optional[re.Pattern]] = {
            rule.id: re.compile(rule.pattern, re.IGNORECASE) if rule.pattern else None
            for rule in self.config.rules
        }

    def event_matches_rule(self, event: LogEvent, rule: DetectionRule) -> bool:
        if (
            rule.event_type
            and rule.event_type != "generic"
            and event.event_type.lower() == rule.event_type.lower()
        ):
            return True

        pattern = self._compiled_patterns.get(rule.id)
        if pattern and pattern.search(event.message):
            return True

        return False

    def detect_incidents(self, events: List[LogEvent]) -> List[Incident]:
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        incidents: List[Incident] = []

        for rule in self.config.rules:
            grouped: Dict[str, List[LogEvent]] = defaultdict(list)
            for event in sorted_events:
                if self.event_matches_rule(event, rule):
                    grouped[event.service].append(event)

            window_delta = timedelta(minutes=rule.window_minutes)

            for service, group_events in grouped.items():
                if len(group_events) < rule.threshold:
                    continue

                window_start_idx = 0
                threshold_breached = False
                triggering_events: List[LogEvent] = []

                for i in range(len(group_events)):
                    current_event = group_events[i]
                    while (
                        current_event.timestamp - group_events[window_start_idx].timestamp
                        > window_delta
                    ):
                        window_start_idx += 1

                    count_in_window = i - window_start_idx + 1
                    if count_in_window >= rule.threshold:
                        threshold_breached = True
                        triggering_events = group_events[window_start_idx : i + 1]

                if threshold_breached and triggering_events:
                    evidence = [
                        f"[{e.timestamp.strftime('%H:%M:%S')}] {e.message}"
                        for e in group_events[:5]
                    ]
                    summary = (
                        f"{rule.title}: Detected {len(group_events)} matching events "
                        f"(threshold: {rule.threshold} in {rule.window_minutes}m) "
                        f"in service '{service}'."
                    )
                    incident_sig = f"{rule.id}::{service}"

                    incident = Incident(
                        rule_id=rule.id,
                        title=rule.title,
                        service=service,
                        severity=rule.severity,
                        signature=incident_sig,
                        first_seen=group_events[0].timestamp,
                        last_seen=group_events[-1].timestamp,
                        event_count=len(group_events),
                        summary=summary,
                        recommended_action=rule.recommended_action,
                        evidence=evidence,
                    )
                    incidents.append(incident)

        return incidents
