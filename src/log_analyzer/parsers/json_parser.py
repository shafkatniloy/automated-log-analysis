import json
from pathlib import Path
from typing import TextIO, Union

from log_analyzer.models import LogEvent, MalformedRecord, ParsingResult
from log_analyzer.normalization import (
    generate_signature,
    infer_event_type,
    normalize_level,
    parse_timestamp,
)
from log_analyzer.redaction import redact_secrets, sanitize_snippet

CORE_FIELDS = {
    "timestamp",
    "time",
    "@timestamp",
    "datetime",
    "level",
    "severity",
    "log_level",
    "service",
    "app",
    "application",
    "message",
    "msg",
    "event",
    "event_type",
    "request_id",
    "req_id",
    "trace_id",
    "host",
    "hostname",
}


class JSONLogParser:
    def parse_stream(self, stream: TextIO, source_name: str = "stream") -> ParsingResult:
        result = ParsingResult()

        for line_num, line in enumerate(stream, start=1):
            result.total_lines_read += 1
            raw_line = line.strip()

            if not raw_line:
                continue

            try:
                data = json.loads(raw_line)
                if not isinstance(data, dict):
                    raise ValueError(f"Expected dict, got {type(data).__name__}")

                raw_ts = (
                    data.get("timestamp")
                    or data.get("time")
                    or data.get("@timestamp")
                    or data.get("datetime")
                )
                if not raw_ts:
                    raise ValueError("Missing timestamp field")

                parsed_ts = parse_timestamp(str(raw_ts))
                raw_level = data.get("level") or data.get("severity") or data.get("log_level")
                level = normalize_level(str(raw_level) if raw_level else None)
                service = str(
                    data.get("service")
                    or data.get("app")
                    or data.get("application")
                    or "application"
                ).strip()

                raw_msg = str(
                    data.get("message")
                    or data.get("msg")
                    or data.get("event")
                    or ""
                ).strip()
                if not raw_msg:
                    raw_msg = json.dumps(data)

                message = redact_secrets(raw_msg)
                explicit_type = data.get("event") or data.get("event_type")
                event_type = infer_event_type(
                    message, str(explicit_type) if explicit_type else None
                )
                sig = generate_signature(service, event_type, message)

                request_id = data.get("request_id") or data.get("req_id") or data.get("trace_id")
                host = data.get("host") or data.get("hostname")
                metadata = {k: v for k, v in data.items() if k not in CORE_FIELDS}

                event = LogEvent(
                    timestamp=parsed_ts,
                    service=service,
                    level=level,
                    message=message,
                    source_file=source_name,
                    line_number=line_num,
                    event_type=event_type,
                    signature=sig,
                    request_id=str(request_id) if request_id else None,
                    host=str(host) if host else None,
                    metadata=metadata,
                )
                result.events.append(event)

            except Exception as exc:
                result.malformed_records.append(
                    MalformedRecord(
                        source_file=source_name,
                        line_number=line_num,
                        raw_content=sanitize_snippet(raw_line),
                        error_reason=f"JSON parse error: {str(exc)}",
                    )
                )

        return result

    def parse_file(self, file_path: Union[str, Path]) -> ParsingResult:
        path = Path(file_path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return self.parse_stream(f, source_name=str(path))
