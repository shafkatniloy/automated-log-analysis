"""Integration tests for the complete log analysis and reporting pipeline."""

from pathlib import Path
import openpyxl
import pandas as pd
import pytest

from log_analyzer.cli import main


def test_database_failure_scenario(tmp_path):
    report_dir = tmp_path / "reports_db"
    exit_code = main([
        "--input",
        "sample-logs/scenarios/database_failure.jsonl",
        "--output",
        str(report_dir),
        "--rules",
        "config/rules.yaml",
        "--format",
        "all",
        "--quiet",
    ])
    assert exit_code == 0

    # Verify CSV files
    events_csv = report_dir / "events.csv"
    incidents_csv = report_dir / "incidents.csv"
    assert events_csv.exists()
    assert incidents_csv.exists()

    df_inc = pd.read_csv(incidents_csv)
    assert len(df_inc) > 0
    rule_ids = df_inc["rule_id"].tolist()
    assert "DB-001" in rule_ids

    # Verify Excel workbook and sheets
    xlsx_path = report_dir / "log_analysis_report.xlsx"
    assert xlsx_path.exists()
    wb = openpyxl.load_workbook(xlsx_path)
    sheet_names = wb.sheetnames
    assert "Overview" in sheet_names
    assert "Incidents" in sheet_names
    assert "Events" in sheet_names
    assert "Severity Summary" in sheet_names
    assert "Service Summary" in sheet_names


def test_repeated_login_scenario(tmp_path):
    report_dir = tmp_path / "reports_auth"
    exit_code = main([
        "--input",
        "sample-logs/scenarios/repeated_login_failures.jsonl",
        "--output",
        str(report_dir),
        "--rules",
        "config/rules.yaml",
        "--format",
        "csv",
        "--quiet",
    ])
    assert exit_code == 0

    df_inc = pd.read_csv(report_dir / "incidents.csv")
    assert "AUTH-001" in df_inc["rule_id"].values


def test_application_outage_scenario(tmp_path):
    report_dir = tmp_path / "reports_outage"
    exit_code = main([
        "--input",
        "sample-logs/scenarios/application_outage.jsonl",
        "--output",
        str(report_dir),
        "--rules",
        "config/rules.yaml",
        "--format",
        "csv",
        "--quiet",
    ])
    assert exit_code == 0

    df_inc = pd.read_csv(report_dir / "incidents.csv")
    rule_ids = set(df_inc["rule_id"].values)
    assert "HTTP-001" in rule_ids or "SERVICE-001" in rule_ids


def test_cli_exit_codes(tmp_path):
    # Non-existent input file returns 1
    code_missing = main(["--input", "does_not_exist_file.log", "--quiet"])
    assert code_missing == 1

    # Database failure triggers CRITICAL, --fail-on-critical should return 2
    code_critical = main([
        "--input",
        "sample-logs/scenarios/database_failure.jsonl",
        "--output",
        str(tmp_path / "reports_crit"),
        "--fail-on-critical",
        "--quiet",
    ])
    assert code_critical == 2
