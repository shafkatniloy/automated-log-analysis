# Log Analyzer

A Python CLI tool for parsing, normalizing, and detecting operational incidents from application and system logs.

## Features

- Multi-format ingestion: JSON Lines (`.jsonl`), plain text, and syslog formats.
- Timestamp normalization to UTC and log level normalization.
- Sensitive data masking for credentials, tokens, and keys.
- Rule-based detection using sliding time windows and configurable count thresholds.
- Grouping of repeated events into incident records with evidence samples.
- Export to console summary, CSV, and formatted Excel sheets.
- Optional webhook notifications and local alert logging.
- Background execution support via systemd timer or cron.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

Analyze a log file or directory:

```bash
python3 -m log_analyzer -i ./sample-logs
```

Export reports to CSV and Excel:

```bash
python3 -m log_analyzer -i ./sample-logs -o ./reports -f summary,csv,xlsx
```

Filter by minimum severity:

```bash
python3 -m log_analyzer -i ./sample-logs --min-severity ERROR
```

Trigger alerts on critical incidents:

```bash
python3 -m log_analyzer -i ./sample-logs --alert-file ./reports/alerts.log --alert-min-severity CRITICAL
```

Using the helper script:

```bash
./scripts/run_analysis.sh all
./scripts/run_analysis.sh db-fail
./scripts/run_analysis.sh auth-spike
./scripts/run_analysis.sh outage
```

## Configuration

Rules are configured in `config/rules.yaml`:

```yaml
rules:
  - id: DB-001
    title: Database Connection Failure Spike
    event_type: database_connection_failed
    threshold: 3
    window_minutes: 5
    severity: CRITICAL
    recommended_action: Verify database connectivity and connection pool status.
```

## Running Tests

```bash
pytest -v
```
