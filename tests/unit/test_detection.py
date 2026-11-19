"""Unit tests for the detection engine and sliding time-window logic."""

from datetime import datetime, timezone, timedelta
from log_analyzer.config import DetectionRule, RulesConfig
from log_analyzer.detection import DetectionEngine
from log_analyzer.models import LogEvent


def make_event(
    timestamp: datetime,
    service: str = "payment-api",
    event_type: str = "generic",
    message: str = "Test error message",
    signature: str = "sig-001",
    level: str = "ERROR",
) -> LogEvent:
    return LogEvent(
        timestamp=timestamp,
        service=service,
        level=level,
        message=message,
        source_file="test.log",
        line_number=1,
        event_type=event_type,
        signature=signature,
    )


def test_threshold_detection():
    rule = DetectionRule(
        id="DB-001",
        title="DB Failure",
        event_type="database_connection_failed",
        threshold=3,
        window_minutes=5,
        severity="CRITICAL",
    )
    config = RulesConfig(rules=[rule])
    engine = DetectionEngine(config)

    base_time = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 2 events (below threshold of 3)
    events_2 = [
        make_event(base_time, event_type="database_connection_failed"),
        make_event(
            base_time + timedelta(seconds=30),
            event_type="database_connection_failed",
        ),
    ]
    assert len(engine.detect_incidents(events_2)) == 0

    # 3 events (reaches threshold)
    events_3 = events_2 + [
        make_event(
            base_time + timedelta(seconds=60),
            event_type="database_connection_failed",
        )
    ]
    incidents = engine.detect_incidents(events_3)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.rule_id == "DB-001"
    assert inc.severity == "CRITICAL"
    assert inc.event_count == 3
    assert inc.first_seen == base_time
    assert inc.last_seen == base_time + timedelta(seconds=60)


def test_window_expiry():
    rule = DetectionRule(
        id="AUTH-001",
        title="Failed Logins",
        event_type="login_failed",
        threshold=3,
        window_minutes=5,
        severity="MEDIUM",
    )
    config = RulesConfig(rules=[rule])
    engine = DetectionEngine(config)

    base_time = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 3 events spaced across 20 minutes (never more than 1 in any 5m window)
    events = [
        make_event(base_time, event_type="login_failed"),
        make_event(base_time + timedelta(minutes=7), event_type="login_failed"),
        make_event(base_time + timedelta(minutes=15), event_type="login_failed"),
    ]
    assert len(engine.detect_incidents(events)) == 0


def test_regex_pattern_match():
    rule = DetectionRule(
        id="DISK-001",
        title="Disk Warning",
        event_type="generic",
        pattern=r"(?i)disk usage above",
        threshold=1,
        window_minutes=5,
        severity="HIGH",
    )
    config = RulesConfig(rules=[rule])
    engine = DetectionEngine(config)

    event = make_event(
        datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
        message="Warning: partition /var disk usage above 92%",
    )
    incidents = engine.detect_incidents([event])
    assert len(incidents) == 1
    assert incidents[0].rule_id == "DISK-001"
