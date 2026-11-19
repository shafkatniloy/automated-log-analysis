"""Unit tests for the AlertNotifier module."""

from datetime import datetime, timezone
import json
from pathlib import Path
from log_analyzer.alerts import AlertNotifier
from log_analyzer.incidents import Incident
from log_analyzer.cli import main


def make_incident(severity: str = "CRITICAL", rule_id: str = "DB-001") -> Incident:
    return Incident(
        rule_id=rule_id,
        title="Database Failure",
        service="payment-api",
        severity=severity,
        signature="sig-db-fail",
        first_seen=datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 11, 1, 10, 2, 0, tzinfo=timezone.utc),
        event_count=4,
        summary="Database Connection Failure Spike: 4 events",
        recommended_action="Restart DB service if safe",
        evidence=["Could not connect to DB at 10:00:00"],
    )


def test_format_incident_payload():
    inc = make_incident("CRITICAL")
    notifier = AlertNotifier()
    payload = notifier.format_incident_payload(inc)

    assert payload["source"] == "LogAnalyzer"
    assert payload["incident_id"] == inc.incident_id
    assert payload["severity"] == "CRITICAL"
    assert payload["rule_id"] == "DB-001"
    assert payload["event_count"] == 4


def test_log_alert_to_file(tmp_path):
    alert_file = tmp_path / "alerts.log"
    notifier = AlertNotifier(log_file=str(alert_file))

    inc_crit = make_incident("CRITICAL")
    inc_med = make_incident("MEDIUM", rule_id="AUTH-001")

    notified = notifier.notify_critical_incidents(
        [inc_crit, inc_med], min_severity="HIGH"
    )

    # Only CRITICAL is >= HIGH
    assert len(notified) == 1
    assert notified[0] == inc_crit.incident_id

    assert alert_file.exists()
    lines = alert_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["incident_id"] == inc_crit.incident_id
    assert data["severity"] == "CRITICAL"


def test_cli_alert_file_generation(tmp_path):
    alert_file = tmp_path / "cli_alerts.log"
    exit_code = main([
        "--input",
        "sample-logs/scenarios/database_failure.jsonl",
        "--output",
        str(tmp_path / "reports"),
        "--alert-file",
        str(alert_file),
        "--alert-min-severity",
        "CRITICAL",
        "--quiet",
    ])
    assert exit_code == 0
    assert alert_file.exists()
    lines = alert_file.read_text().strip().splitlines()
    assert len(lines) > 0
