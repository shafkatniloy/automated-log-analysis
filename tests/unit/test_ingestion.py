"""Unit tests for the ingestion engine."""

from pathlib import Path
from log_analyzer.ingestion import IngestionEngine


def test_ingest_sample_jsonl():
    engine = IngestionEngine()
    sample_file = Path("sample-logs/application/app_sample.jsonl")
    assert sample_file.exists()

    result = engine.ingest_file(sample_file)
    assert result.total_lines_read > 0
    assert result.successfully_parsed > 0
    # Our sample log contains 1 intentional malformed line for resilience testing
    assert result.malformed_count == 1


def test_ingest_sample_text():
    engine = IngestionEngine()
    sample_file = Path("sample-logs/application/app_text_sample.log")
    assert sample_file.exists()

    result = engine.ingest_file(sample_file)
    assert result.total_lines_read > 0
    assert result.successfully_parsed > 0
    assert result.malformed_count == 1


def test_ingest_directory_scans_and_sorts():
    engine = IngestionEngine()
    result = engine.ingest_path("sample-logs/application")

    assert result.successfully_parsed > 0
    # Verify that the parsed events are sorted chronologically
    timestamps = [e.timestamp for e in result.events]
    assert timestamps == sorted(timestamps)


def test_ingest_nonexistent_path():
    engine = IngestionEngine()
    result = engine.ingest_path("non_existent_directory_or_file.log")
    assert result.successfully_parsed == 0
    assert result.malformed_count == 1
    assert "not exist" in result.malformed_records[0].error_reason.lower()
