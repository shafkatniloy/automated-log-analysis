"""Unit tests for normalization and redaction modules."""

from datetime import datetime, timezone
import pytest

from log_analyzer.normalization import (
    generate_signature,
    infer_event_type,
    normalize_level,
    parse_timestamp,
)
from log_analyzer.redaction import redact_secrets, sanitize_snippet


def test_parse_timestamp_iso_utc():
    ts = parse_timestamp("2026-11-01T09:00:00Z")
    assert ts == datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)


def test_parse_timestamp_iso_offset():
    ts = parse_timestamp("2026-11-01T11:00:00+02:00")
    # 11:00 at UTC+2 is 09:00 UTC
    assert ts == datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)


def test_parse_timestamp_standard_text():
    ts = parse_timestamp("2026-11-01 09:05:00")
    assert ts == datetime(2026, 11, 1, 9, 5, 0, tzinfo=timezone.utc)


def test_parse_timestamp_invalid():
    with pytest.raises(ValueError):
        parse_timestamp("invalid-date-string-xyz")


def test_normalize_level():
    assert normalize_level("info") == "INFO"
    assert normalize_level("WARN") == "WARNING"
    assert normalize_level("warning") == "WARNING"
    assert normalize_level("err") == "ERROR"
    assert normalize_level("CRITICAL") == "CRITICAL"
    assert normalize_level("fatal") == "CRITICAL"
    assert normalize_level(None) == "INFO"
    assert normalize_level("unknown_level") == "INFO"


def test_infer_event_type():
    assert (
        infer_event_type("Could not connect to database host")
        == "database_connection_failed"
    )
    assert infer_event_type("Failed password for user admin") == "login_failed"
    assert (
        infer_event_type("Unhandled exception in route /checkout")
        == "unhandled_exception"
    )
    assert (
        infer_event_type("POST /checkout 503 Service Unavailable")
        == "http_5xx"
    )
    assert (
        infer_event_type("disk space warning: /var usage above 95%")
        == "disk_warning"
    )
    assert (
        infer_event_type("payment-api.service: Failed with result 'exit-code'")
        == "service_failure"
    )
    assert infer_event_type("Normal application operation") == "generic"


def test_generate_signature_strips_dynamic_values():
    sig1 = generate_signature(
        "payment-api",
        "database_connection_failed",
        "Could not connect to database at 192.168.1.10:5432 after 5000ms (req req-001)",
    )
    sig2 = generate_signature(
        "payment-api",
        "database_connection_failed",
        "Could not connect to database at 10.0.0.5:5432 after 3200ms (req req-999)",
    )
    # Both messages describe the same error pattern differing only by IP and duration
    assert sig1 == sig2


def test_redact_secrets():
    raw = 'user logged in with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz and password="superSecretPassword123"'
    redacted = redact_secrets(raw)
    assert "superSecretPassword123" not in redacted
    assert "Bearer [REDACTED]" in redacted
    assert 'password="[REDACTED]"' in redacted


def test_sanitize_snippet():
    long_line = "A" * 200
    snippet = sanitize_snippet(long_line, max_length=50)
    assert len(snippet) <= 50
    assert snippet.endswith("...")
