from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

from log_analyzer.incidents import Incident

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


class AlertNotifier:
    def __init__(self, webhook_url: Optional[str] = None, log_file: Optional[str] = None) -> None:
        self.webhook_url = webhook_url
        self.log_file = log_file

    def format_incident_payload(self, incident: Incident) -> Dict[str, Any]:
        return {
            "source": "LogAnalyzer",
            "alert_time": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident.incident_id,
            "rule_id": incident.rule_id,
            "title": incident.title,
            "service": incident.service,
            "severity": incident.severity,
            "event_count": incident.event_count,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
            "summary": incident.summary,
            "recommended_action": incident.recommended_action,
            "evidence": incident.evidence[:3],
        }

    def send_webhook(self, incident: Incident) -> bool:
        if not self.webhook_url:
            return False

        payload = self.format_incident_payload(incident)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "LogAnalyzer-AlertBot/1.0"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 201, 202, 204)
        except Exception as exc:
            logger.error("Failed to send webhook alert for %s: %s", incident.incident_id, exc)
            return False

    def log_alert_to_file(self, incident: Incident) -> bool:
        if not self.log_file:
            return False

        payload = self.format_incident_payload(incident)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
            return True
        except Exception as exc:
            logger.error("Failed writing alert to file %s: %s", self.log_file, exc)
            return False

    def notify_critical_incidents(
        self, incidents: List[Incident], min_severity: str = "CRITICAL"
    ) -> List[str]:
        min_rank = SEVERITY_LEVELS.get(min_severity.upper(), 3)
        notified_ids: List[str] = []

        for inc in incidents:
            if SEVERITY_LEVELS.get(inc.severity.upper(), 0) >= min_rank:
                if self.webhook_url:
                    self.send_webhook(inc)
                if self.log_file:
                    self.log_alert_to_file(inc)
                notified_ids.append(inc.incident_id)

        return notified_ids
