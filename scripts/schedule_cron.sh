#!/usr/bin/env bash
# Helper script to display or configure cron execution
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VENV_PYTHON="${ROOT_DIR}/.venv/bin/python3"
CRON_JOB="*/5 * * * * cd '${ROOT_DIR}' && PYTHONPATH=src '${VENV_PYTHON}' -m log_analyzer -i ./sample-logs -o ./reports --alert-file ./reports/alerts.log --quiet >> ./reports/cron.log 2>&1"

echo "=================================================="
echo "    Log Analyzer Cron Scheduling Helper"
echo "=================================================="
echo ""
echo "Recommended Crontab entry (runs every 5 minutes):"
echo ""
echo "${CRON_JOB}"
echo ""
echo "To install this into your current user's crontab:"
echo "  (crontab -l 2>/dev/null; echo \"${CRON_JOB}\") | crontab -"
echo ""
echo "To view current crontab:"
echo "  crontab -l"
echo ""
echo "=================================================="
