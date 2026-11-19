import argparse
from pathlib import Path
import sys
from typing import List, Optional

from log_analyzer.alerts import AlertNotifier
from log_analyzer.config import RulesConfig
from log_analyzer.detection import DetectionEngine
from log_analyzer.ingestion import IngestionEngine
from log_analyzer.reporting import Reporter

SEVERITY_ORDER = {
    "DEBUG": 0,
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Log Analysis and Incident Detection CLI.",
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        type=str,
        help="Path to log file or directory.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="./reports",
        help="Directory to save exported reports. Default: ./reports",
    )
    parser.add_argument(
        "-r",
        "--rules",
        type=str,
        default="./config/rules.yaml",
        help="Path to rules YAML. Default: ./config/rules.yaml",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="summary,csv,xlsx",
        help="Report formats: summary, csv, xlsx, or all. Default: summary,csv,xlsx",
    )
    parser.add_argument(
        "--min-severity",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Filter events and incidents to minimum severity.",
    )
    parser.add_argument(
        "--service",
        type=str,
        default=None,
        help="Filter by service name.",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with return code 2 if any CRITICAL incident is detected.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress console output.",
    )
    parser.add_argument(
        "--alert-webhook",
        type=str,
        default=None,
        help="Webhook URL for incident notifications.",
    )
    parser.add_argument(
        "--alert-file",
        type=str,
        default=None,
        help="Log file to append incident alerts.",
    )
    parser.add_argument(
        "--alert-min-severity",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="CRITICAL",
        help="Minimum severity that triggers alerts.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input path '{input_path}' does not exist.", file=sys.stderr)
        return 1

    rules_path = Path(args.rules)
    if not rules_path.exists():
        alt_rules = Path(__file__).resolve().parent.parent.parent / "config" / "rules.yaml"
        if alt_rules.exists():
            rules_path = alt_rules
        else:
            print(f"Warning: Rules config '{rules_path}' not found.", file=sys.stderr)

    rules_config = RulesConfig.load_from_yaml(rules_path)

    ingestion = IngestionEngine()
    parsing_result = ingestion.ingest_path(input_path)

    events = parsing_result.events
    if args.service:
        events = [e for e in events if e.service.lower() == args.service.lower()]
    if args.min_severity:
        min_level_val = SEVERITY_ORDER.get(args.min_severity, 0)
        events = [
            e for e in events if SEVERITY_ORDER.get(e.level, 0) >= min_level_val
        ]
    parsing_result.events = events

    detection = DetectionEngine(rules_config)
    incidents = detection.detect_incidents(events)

    if args.min_severity:
        inc_min_level_val = SEVERITY_ORDER.get(args.min_severity, 0)
        incidents = [
            inc
            for inc in incidents
            if SEVERITY_ORDER.get(inc.severity, 0) >= inc_min_level_val
        ]

    reporter = Reporter(output_dir=Path(args.output))
    formats = [f.strip().lower() for f in args.format.split(",")]
    if "all" in formats:
        formats = ["summary", "csv", "xlsx"]

    if "summary" in formats and not args.quiet:
        print(reporter.generate_console_summary(parsing_result, incidents))

    if "csv" in formats:
        csv_events = reporter.export_events_csv(parsing_result.events)
        csv_inc = reporter.export_incidents_csv(incidents)
        if not args.quiet:
            print(f"Exported events CSV:    {csv_events}")
            print(f"Exported incidents CSV: {csv_inc}")

    if "xlsx" in formats:
        xlsx_file = reporter.export_excel_report(parsing_result, incidents)
        if not args.quiet:
            print(f"Exported Excel report:  {xlsx_file}")

    if (args.alert_webhook or args.alert_file) and incidents:
        notifier = AlertNotifier(
            webhook_url=args.alert_webhook, log_file=args.alert_file
        )
        notified = notifier.notify_critical_incidents(
            incidents, min_severity=args.alert_min_severity
        )
        if notified and not args.quiet:
            print(f"Dispatched alerts for {len(notified)} incident(s).")

    if args.fail_on_critical:
        has_critical = any(inc.severity == "CRITICAL" for inc in incidents)
        if has_critical:
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
