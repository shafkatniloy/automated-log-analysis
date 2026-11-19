from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List
import uuid


@dataclass
class Incident:
    rule_id: str
    title: str
    service: str
    severity: str
    signature: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    summary: str
    recommended_action: str
    incident_id: str = field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}"
    )
    status: str = "OPEN"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "service": self.service,
            "severity": self.severity,
            "status": self.status,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "signature": self.signature,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "evidence": "; ".join(self.evidence[:5]),
        }
