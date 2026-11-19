from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import openpyxl
from openpyxl.styles import Border, Font, PatternFill, Side
import pandas as pd

from log_analyzer.incidents import Incident
from log_analyzer.models import LogEvent, ParsingResult

ORDER_LEVELS = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
ORDER_INC_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class Reporter:
    def __init__(self, output_dir: Path = Path("./reports")) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_console_summary(
        self,
        parsing_result: ParsingResult,
        incidents: List[Incident],
        source_paths: Optional[List[str]] = None,
    ) -> str:
        events = parsing_result.events
        total_lines = parsing_result.total_lines_read
        parsed_count = parsing_result.successfully_parsed
        malformed_count = parsing_result.malformed_count

        if events:
            first_ts = min(e.timestamp for e in events).strftime("%Y-%m-%d %H:%M:%S UTC")
            last_ts = max(e.timestamp for e in events).strftime("%Y-%m-%d %H:%M:%S UTC")
            period_str = f"{first_ts} to {last_ts}"
        else:
            period_str = "N/A (No events parsed)"

        severity_counts = Counter(e.level for e in events)
        incident_counts = Counter(inc.severity for inc in incidents)

        lines = [
            "=" * 60,
            "               LOG ANALYSIS & INCIDENT REPORT               ",
            "=" * 60,
            f"Analysis Period:     {period_str}",
            f"Total Lines Read:    {total_lines}",
            f"Successfully Parsed: {parsed_count}",
            f"Malformed Lines:     {malformed_count}",
            "-" * 60,
            "EVENTS BY SEVERITY:",
        ]
        for lvl in ORDER_LEVELS:
            cnt = severity_counts.get(lvl, 0)
            lines.append(f"  {lvl:<10} : {cnt:>6}")

        lines.extend([
            "-" * 60,
            f"INCIDENTS DETECTED ({len(incidents)} total):",
        ])
        for lvl in ORDER_INC_LEVELS:
            cnt = incident_counts.get(lvl, 0)
            lines.append(f"  {lvl:<10} : {cnt:>6}")

        if incidents:
            lines.extend([
                "-" * 60,
                "ACTIVE INCIDENT DETAILS:",
            ])
            for idx, inc in enumerate(incidents, start=1):
                lines.append(
                    f"[{idx}] {inc.incident_id} | {inc.severity} | {inc.service} | {inc.title}"
                )
                lines.append(f"    First Seen:  {inc.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"    Last Seen:   {inc.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"    Event Count: {inc.event_count}")
                lines.append(f"    Summary:     {inc.summary}")
                lines.append(f"    Action:      {inc.recommended_action}")
                if inc.evidence:
                    lines.append(f"    Sample:      {inc.evidence[0]}")
                lines.append("")

        if malformed_count > 0:
            lines.extend([
                "-" * 60,
                f"MALFORMED SAMPLES ({min(malformed_count, 3)} of {malformed_count}):",
            ])
            for rec in parsing_result.malformed_records[:3]:
                lines.append(
                    f"  File: {rec.source_file}:{rec.line_number} -> {rec.error_reason}"
                )
                lines.append(f"  Content: {rec.raw_content}")

        lines.append("=" * 60)
        return "\n".join(lines)

    def export_events_csv(
        self, events: List[LogEvent], filename: str = "events.csv"
    ) -> Path:
        out_path = self.output_dir / filename
        columns = [
            "event_id",
            "timestamp",
            "service",
            "level",
            "event_type",
            "signature",
            "source_file",
            "message",
        ]
        if events:
            data = [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat(),
                    "service": e.service,
                    "level": e.level,
                    "event_type": e.event_type,
                    "signature": e.signature,
                    "source_file": e.source_file,
                    "message": e.message,
                }
                for e in events
            ]
            df = pd.DataFrame(data)
        else:
            df = pd.DataFrame(columns=columns)
        df.to_csv(out_path, index=False)
        return out_path

    def export_incidents_csv(
        self, incidents: List[Incident], filename: str = "incidents.csv"
    ) -> Path:
        out_path = self.output_dir / filename
        columns = [
            "incident_id",
            "rule_id",
            "title",
            "service",
            "severity",
            "status",
            "first_seen",
            "last_seen",
            "event_count",
            "signature",
            "summary",
            "recommended_action",
            "evidence",
        ]
        if incidents:
            data = [inc.to_dict() for inc in incidents]
            df = pd.DataFrame(data)
        else:
            df = pd.DataFrame(columns=columns)
        df.to_csv(out_path, index=False)
        return out_path

    def export_excel_report(
        self,
        parsing_result: ParsingResult,
        incidents: List[Incident],
        filename: str = "log_analysis_report.xlsx",
    ) -> Path:
        out_path = self.output_dir / filename
        wb = openpyxl.Workbook()

        header_fill = PatternFill(
            start_color="1F497D", end_color="1F497D", fill_type="solid"
        )
        header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        crit_fill = PatternFill(
            start_color="FCE4D6", end_color="FCE4D6", fill_type="solid"
        )
        high_fill = PatternFill(
            start_color="FFF2CC", end_color="FFF2CC", fill_type="solid"
        )
        border_thin = Border(
            left=Side(style="thin", color="D9D9D9"),
            right=Side(style="thin", color="D9D9D9"),
            top=Side(style="thin", color="D9D9D9"),
            bottom=Side(style="thin", color="D9D9D9"),
        )

        # Overview
        ws_overview = wb.active
        ws_overview.title = "Overview"
        ws_overview.append(["Log Analysis & Incident Detection Report"])
        ws_overview.append([])
        ws_overview.append(["Metric", "Value"])

        events = parsing_result.events
        first_ts = (
            min(e.timestamp for e in events).isoformat() if events else "N/A"
        )
        last_ts = (
            max(e.timestamp for e in events).isoformat() if events else "N/A"
        )

        overview_metrics = [
            ("Analysis Start", first_ts),
            ("Analysis End", last_ts),
            ("Total Lines Read", parsing_result.total_lines_read),
            ("Successfully Parsed", parsing_result.successfully_parsed),
            ("Malformed Records", parsing_result.malformed_count),
            ("Total Incidents Detected", len(incidents)),
        ]
        for m, v in overview_metrics:
            ws_overview.append([m, v])

        ws_overview["A1"].font = Font(size=14, bold=True, color="1F497D")
        for cell in ws_overview[3]:
            cell.fill = header_fill
            cell.font = header_font

        # Incidents
        ws_incidents = wb.create_sheet(title="Incidents")
        inc_headers = [
            "Incident ID",
            "Rule ID",
            "Title",
            "Service",
            "Severity",
            "Status",
            "First Seen",
            "Last Seen",
            "Event Count",
            "Summary",
            "Recommended Action",
            "Evidence Sample",
        ]
        ws_incidents.append(inc_headers)
        for inc in incidents:
            ws_incidents.append([
                inc.incident_id,
                inc.rule_id,
                inc.title,
                inc.service,
                inc.severity,
                inc.status,
                inc.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                inc.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                inc.event_count,
                inc.summary,
                inc.recommended_action,
                inc.evidence[0] if inc.evidence else "",
            ])

        for cell in ws_incidents[1]:
            cell.fill = header_fill
            cell.font = header_font

        for row in ws_incidents.iter_rows(min_row=2, max_row=ws_incidents.max_row):
            sev = row[4].value
            for cell in row:
                cell.border = border_thin
                if sev == "CRITICAL":
                    cell.fill = crit_fill
                elif sev == "HIGH":
                    cell.fill = high_fill

        # Events
        ws_events = wb.create_sheet(title="Events")
        event_headers = [
            "Event ID",
            "Timestamp (UTC)",
            "Service",
            "Level",
            "Event Type",
            "Signature",
            "Source File",
            "Line Number",
            "Message",
        ]
        ws_events.append(event_headers)
        for e in events:
            ws_events.append([
                e.event_id,
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                e.service,
                e.level,
                e.event_type,
                e.signature,
                e.source_file,
                e.line_number,
                e.message,
            ])

        for cell in ws_events[1]:
            cell.fill = header_fill
            cell.font = header_font

        for row in ws_events.iter_rows(min_row=2, max_row=ws_events.max_row):
            for cell in row:
                cell.border = border_thin

        # Summaries
        ws_sev = wb.create_sheet(title="Severity Summary")
        ws_sev.append(["Severity Level", "Event Count"])
        for cell in ws_sev[1]:
            cell.fill = header_fill
            cell.font = header_font
        for lvl, cnt in Counter(e.level for e in events).most_common():
            ws_sev.append([lvl, cnt])

        ws_svc = wb.create_sheet(title="Service Summary")
        ws_svc.append(["Service", "Event Count"])
        for cell in ws_svc[1]:
            cell.fill = header_fill
            cell.font = header_font
        for svc, cnt in Counter(e.service for e in events).most_common():
            ws_svc.append([svc, cnt])

        for ws in wb.worksheets:
            ws.freeze_panes = "A2"
            for col in ws.columns:
                max_len = max(len(str(cell.value or "")) for cell in col)
                col_letter = col[0].column_letter
                ws.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 60)

        wb.save(out_path)
        return out_path
