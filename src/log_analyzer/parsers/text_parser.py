from pathlib import Path
import re
from typing import List, Pattern, TextIO, Tuple, Union

from log_analyzer.models import LogEvent, MalformedRecord, ParsingResult
from log_analyzer.normalization import (
    generate_signature,
    infer_event_type,
    normalize_level,
    parse_timestamp,
)
from log_analyzer.redaction import redact_secrets, sanitize_snippet

PATTERN_APP_STANDARD: Pattern = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<level>[A-Z]+)\s+"
    r"\[(?P<service>[^\]]+)\]\s+"
    r"(?P<message>.*)$"
)

PATTERN_SYSLOG_ISO: Pattern = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

PATTERN_SYSLOG_BSD: Pattern = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


class TextLogParser:
    def __init__(self) -> None:
        self.patterns: List[Tuple[str, Pattern]] = [
            ("app_standard", PATTERN_APP_STANDARD),
            ("syslog_iso", PATTERN_SYSLOG_ISO),
            ("syslog_bsd", PATTERN_SYSLOG_BSD),
        ]

    def _infer_level(self, message: str) -> str:
        msg_lower = message.lower()
        if any(w in msg_lower for w in ["critical", "fatal", "emergency", "panic"]):
            return "CRITICAL"
        if any(w in msg_lower for w in ["error", "failed", "failure", "timeout", "refused"]):
            return "ERROR"
        if any(w in msg_lower for w in ["warn", "warning"]):
            return "WARNING"
        if any(w in msg_lower for w in ["debug"]):
            return "DEBUG"
        return "INFO"

    def parse_stream(self, stream: TextIO, source_name: str = "stream") -> ParsingResult:
        result = ParsingResult()

        for line_num, line in enumerate(stream, start=1):
            result.total_lines_read += 1
            raw_line = line.strip()

            if not raw_line:
                continue

            matched = False
            for format_name, pattern in self.patterns:
                match = pattern.match(raw_line)
                if match:
                    matched = True
                    groups = match.groupdict()

                    try:
                        raw_ts = groups.get("timestamp")
                        if not raw_ts:
                            raise ValueError("Timestamp not matched")

                        parsed_ts = parse_timestamp(raw_ts)
                        service = (groups.get("service") or "system").strip()
                        host = groups.get("host")

                        if "level" in groups and groups["level"]:
                            level = normalize_level(groups["level"])
                        else:
                            level = self._infer_level(groups["message"])

                        message = redact_secrets(groups["message"].strip())
                        event_type = infer_event_type(message)
                        sig = generate_signature(service, event_type, message)

                        metadata = {}
                        if "pid" in groups and groups["pid"]:
                            metadata["pid"] = groups["pid"]
                        metadata["format"] = format_name

                        event = LogEvent(
                            timestamp=parsed_ts,
                            service=service,
                            level=level,
                            message=message,
                            source_file=source_name,
                            line_number=line_num,
                            event_type=event_type,
                            signature=sig,
                            host=host,
                            metadata=metadata,
                        )
                        result.events.append(event)
                    except Exception as exc:
                        result.malformed_records.append(
                            MalformedRecord(
                                source_file=source_name,
                                line_number=line_num,
                                raw_content=sanitize_snippet(raw_line),
                                error_reason=f"Field processing error: {str(exc)}",
                            )
                        )
                    break

            if not matched:
                result.malformed_records.append(
                    MalformedRecord(
                        source_file=source_name,
                        line_number=line_num,
                        raw_content=sanitize_snippet(raw_line),
                        error_reason="Unrecognized log line format",
                    )
                )

        return result

    def parse_file(self, file_path: Union[str, Path]) -> ParsingResult:
        path = Path(file_path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return self.parse_stream(f, source_name=str(path))
