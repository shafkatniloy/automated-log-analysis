from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class LogEvent:
    timestamp: datetime
    service: str
    level: str
    message: str
    source_file: str
    line_number: int
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "generic"
    signature: str = ""
    request_id: Optional[str] = None
    host: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "service": self.service,
            "level": self.level,
            "event_type": self.event_type,
            "message": self.message,
            "signature": self.signature,
            "request_id": self.request_id or "",
            "host": self.host or "",
            "source_file": self.source_file,
            "line_number": self.line_number,
            "metadata": self.metadata,
        }


@dataclass
class MalformedRecord:
    source_file: str
    line_number: int
    raw_content: str
    error_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "line_number": self.line_number,
            "raw_content": self.raw_content,
            "error_reason": self.error_reason,
        }


@dataclass
class ParsingResult:
    events: List[LogEvent] = field(default_factory=list)
    malformed_records: List[MalformedRecord] = field(default_factory=list)
    total_lines_read: int = 0

    @property
    def successfully_parsed(self) -> int:
        return len(self.events)

    @property
    def malformed_count(self) -> int:
        return len(self.malformed_records)

    def merge(self, other: "ParsingResult") -> None:
        self.events.extend(other.events)
        self.malformed_records.extend(other.malformed_records)
        self.total_lines_read += other.total_lines_read
