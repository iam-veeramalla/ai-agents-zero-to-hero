"""Unit tests for LogParser."""

import pytest
from app.k8s_forensics.parser import LogParser
from app.k8s_forensics.models import LogLevel


def test_parse_cri_format():
    parser = LogParser()
    raw = "2026-09-22T12:00:00.123456789Z stdout F [INFO] Server started successfully on port 8080"
    entries = parser.parse(raw)
    assert len(entries) == 1
    assert entries[0].line_number == 1
    assert entries[0].timestamp == "2026-09-22T12:00:00.123456789Z"
    assert entries[0].stream == "stdout"
    assert entries[0].level == LogLevel.INFO
    assert "Server started successfully" in entries[0].message


def test_parse_json_format():
    parser = LogParser()
    raw = '{"time":"2026-09-22T10:00:00Z","level":"error","msg":"connection refused to db","service":"cart"}'
    entries = parser.parse(raw)
    assert len(entries) == 1
    assert entries[0].level == LogLevel.ERROR
    assert "connection refused" in entries[0].message
    assert entries[0].component == "cart"


def test_parse_multiline_stack_trace():
    parser = LogParser()
    raw = """2026-09-22T10:00:00Z [ERROR] Failed to process request
Traceback (most recent call last):
  File "app.py", line 42, in handle
    raise ValueError("Invalid payload")
ValueError: Invalid payload
2026-09-22T10:00:01Z [INFO] Resuming loop"""
    entries = parser.parse(raw)
    # The traceback is stitched directly to the preceding ERROR entry
    assert len(entries) == 2
    assert entries[0].level == LogLevel.ERROR
    assert entries[0].is_stack_trace is True
    assert entries[0].stack_trace is not None
    assert "Traceback" in entries[0].stack_trace
    assert "ValueError: Invalid payload" in entries[0].stack_trace
    assert entries[1].level == LogLevel.INFO
