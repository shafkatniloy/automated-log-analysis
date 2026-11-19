from datetime import datetime, timezone
import hashlib
import re
from typing import Optional
from dateutil import parser as dt_parser

from log_analyzer.redaction import redact_secrets

LEVEL_MAP = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
}

RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
RE_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
RE_NUMBERS = re.compile(r"\d+(?:ms|s|m|h|kb|mb|gb|b)?", re.IGNORECASE)
RE_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{16,}\b")
RE_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)


def parse_timestamp(raw_timestamp: str) -> datetime:
    cleaned = raw_timestamp.strip()
    if not cleaned:
        raise ValueError("Timestamp string is empty")

    if "T" in cleaned:
        iso_str = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    dt = dt_parser.parse(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def normalize_level(raw_level: Optional[str]) -> str:
    if not raw_level:
        return "INFO"
    return LEVEL_MAP.get(raw_level.strip().upper(), "INFO")


def infer_event_type(message: str, current_type: Optional[str] = None) -> str:
    if current_type and current_type.strip() and current_type.strip() != "generic":
        return current_type.strip().lower()

    msg_lower = message.lower()
    if any(
        kw in msg_lower
        for kw in [
            "database connection",
            "could not connect to database",
            "db-replica",
            "connection pool exhausted",
        ]
    ):
        return "database_connection_failed"
    if any(
        kw in msg_lower
        for kw in [
            "failed password",
            "login failed",
            "authentication attempt failed",
            "invalid credentials",
        ]
    ):
        return "login_failed"
    if any(
        kw in msg_lower
        for kw in ["unhandled exception", "traceback", "panic:", "exception occurred"]
    ):
        return "unhandled_exception"
    if any(
        kw in msg_lower
        for kw in [
            "500 internal server error",
            "502 bad gateway",
            "503 service unavailable",
            "504 gateway timeout",
            "status_code: 50",
            'status_code":50',
        ]
    ):
        return "http_5xx"
    if any(
        kw in msg_lower
        for kw in ["response time above threshold", "latency warning", "slow query"]
    ):
        return "latency_warning"
    if any(
        kw in msg_lower
        for kw in ["disk space warning", "disk usage above", "no space left on device"]
    ):
        return "disk_warning"
    if any(
        kw in msg_lower
        for kw in [
            "service stopped",
            "health check failed",
            "failed with result 'exit-code'",
            "exited, status=1",
            "circuit breaker tripped",
        ]
    ):
        return "service_failure"

    return "generic"


def generate_signature(service: str, event_type: str, message: str) -> str:
    normalized_msg = message.strip()
    normalized_msg = RE_TIMESTAMP.sub("<TIMESTAMP>", normalized_msg)
    normalized_msg = RE_UUID.sub("<UUID>", normalized_msg)
    normalized_msg = RE_IPV4.sub("<IP>", normalized_msg)
    normalized_msg = RE_HEX.sub("<HEX>", normalized_msg)
    normalized_msg = RE_NUMBERS.sub("<NUM>", normalized_msg)
    normalized_msg = re.sub(r"\s+", " ", normalized_msg).strip().lower()

    key = f"{service.lower()}|{event_type.lower()}|{normalized_msg}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
