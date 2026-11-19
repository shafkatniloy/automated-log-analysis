#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if [[ -f ".venv/bin/activate" ]]; then
    source ".venv/bin/activate"
fi

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

show_help() {
    cat << EOF
Usage: ./scripts/run_analysis.sh [COMMAND] [OPTIONS]

Commands:
  all             Analyze all sample logs
  app             Analyze application logs
  db-fail         Run Scenario: Database Failure
  auth-spike      Run Scenario: Auth Failure Spike
  outage          Run Scenario: Service Outage
  generate-logs   Generate demo logs
  test            Run pytest
  help            Show this help message
EOF
}

CMD="${1:-all}"
shift || true

case "${CMD}" in
    all)
        python3 -m log_analyzer -i ./sample-logs "$@"
        ;;
    app)
        python3 -m log_analyzer -i ./sample-logs/application "$@"
        ;;
    db-fail)
        python3 -m log_analyzer -i ./sample-logs/scenarios/database_failure.jsonl "$@"
        ;;
    auth-spike)
        python3 -m log_analyzer -i ./sample-logs/scenarios/repeated_login_failures.jsonl "$@"
        ;;
    outage)
        python3 -m log_analyzer -i ./sample-logs/scenarios/application_outage.jsonl "$@"
        ;;
    generate-logs)
        python3 scripts/generate_demo_logs.py "$@"
        ;;
    test)
        pytest -v "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: ${CMD}"
        show_help
        exit 1
        ;;
esac
