import json
from pathlib import Path
from typing import List, Union

from log_analyzer.models import MalformedRecord, ParsingResult
from log_analyzer.parsers.json_parser import JSONLogParser
from log_analyzer.parsers.text_parser import TextLogParser

SUPPORTED_EXTENSIONS = {".jsonl", ".log", ".txt", ".json"}


class IngestionEngine:
    def __init__(self) -> None:
        self.json_parser = JSONLogParser()
        self.text_parser = TextLogParser()

    def detect_format(self, file_path: Path) -> str:
        suffix = file_path.suffix.lower()
        if suffix in {".jsonl", ".json"}:
            return "json"
        if suffix in {".log", ".txt"}:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped:
                            if stripped.startswith("{") and stripped.endswith("}"):
                                try:
                                    json.loads(stripped)
                                    return "json"
                                except ValueError:
                                    pass
                            break
            except Exception:
                pass
            return "text"

        return "text"

    def ingest_file(self, file_path: Union[str, Path]) -> ParsingResult:
        path = Path(file_path)
        if not path.exists():
            res = ParsingResult()
            res.malformed_records.append(
                MalformedRecord(
                    source_file=str(path),
                    line_number=0,
                    raw_content="",
                    error_reason="File not found",
                )
            )
            return res

        fmt = self.detect_format(path)
        if fmt == "json":
            return self.json_parser.parse_file(path)
        return self.text_parser.parse_file(path)

    def ingest_path(self, target_path: Union[str, Path]) -> ParsingResult:
        path = Path(target_path)
        combined_result = ParsingResult()

        if not path.exists():
            combined_result.malformed_records.append(
                MalformedRecord(
                    source_file=str(path),
                    line_number=0,
                    raw_content="",
                    error_reason="Path does not exist",
                )
            )
            return combined_result

        files_to_process: List[Path] = []
        if path.is_file():
            files_to_process.append(path)
        elif path.is_dir():
            for item in sorted(path.rglob("*")):
                if item.is_file() and item.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_to_process.append(item)

        for log_file in files_to_process:
            file_res = self.ingest_file(log_file)
            combined_result.merge(file_res)

        combined_result.events.sort(key=lambda event: event.timestamp)
        return combined_result
