"""Unit tests for JSON and Text log parsers."""

import io
from log_analyzer.parsers.json_parser import JSONLogParser
from log_analyzer.parsers.text_parser import TextLogParser


def test_json_parser_valid_and_malformed():
    raw_content = (
        '{"timestamp":"2026-11-01T09:00:00Z","level":"INFO","service":"payment-api","message":"Order paid","request_id":"req-1"}\n'
        '{"timestamp":"2026-11-01T09:01:00Z","level":"ERROR","service":"payment-api","event":"database_connection_failed","message":"DB error"}\n'
        'MALFORMED JSON LINE HERE\n'
        '{"timestamp":"2026-11-01T09:02:00Z","level":"WARN","service":"auth-service","message":"Auth warning"}\n'
    )
    parser = JSONLogParser()
    result = parser.parse_stream(io.StringIO(raw_content), source_name="test.jsonl")

    assert result.total_lines_read == 4
    assert result.successfully_parsed == 3
    assert result.malformed_count == 1

    ev1, ev2, ev3 = result.events
    assert ev1.service == "payment-api"
    assert ev1.level == "INFO"
    assert ev1.request_id == "req-1"

    assert ev2.event_type == "database_connection_failed"
    assert ev2.level == "ERROR"

    assert ev3.level == "WARNING"

    mal = result.malformed_records[0]
    assert mal.line_number == 3
    assert "MALFORMED JSON LINE" in mal.raw_content


def test_text_parser_valid_and_malformed():
    raw_content = (
        "2026-11-01 09:05:00 INFO  [inventory-api] Service started on port 8080\n"
        "2026-11-01 09:06:10 WARN  [inventory-api] Response time above threshold: 1800ms\n"
        "CORRUPT LINE WITHOUT TIMESTAMP\n"
        "2026-11-01 09:07:20 ERROR [inventory-api] Database connection timeout: host db unreachable\n"
    )
    parser = TextLogParser()
    result = parser.parse_stream(io.StringIO(raw_content), source_name="test.log")

    assert result.total_lines_read == 4
    assert result.successfully_parsed == 3
    assert result.malformed_count == 1

    ev1 = result.events[0]
    assert ev1.service == "inventory-api"
    assert ev1.level == "INFO"
    assert "Service started" in ev1.message

    mal = result.malformed_records[0]
    assert mal.line_number == 3
    assert "CORRUPT LINE" in mal.raw_content


def test_syslog_iso_parser():
    raw_content = (
        "2026-11-01T08:50:10.123456+00:00 srv-app-01 systemd[1]: Started Daily log rotation.\n"
        "2026-11-01T08:53:22.112233+00:00 srv-app-01 systemd[1]: payment-api.service: Failed with result 'exit-code'.\n"
    )
    parser = TextLogParser()
    result = parser.parse_stream(io.StringIO(raw_content), source_name="syslog.log")

    assert result.successfully_parsed == 2
    assert result.malformed_count == 0

    assert result.events[0].host == "srv-app-01"
    assert result.events[0].service == "systemd"
    assert result.events[0].level == "INFO"

    assert result.events[1].level == "ERROR"
    assert result.events[1].event_type == "service_failure"
