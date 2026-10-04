"""Multi-format log parser with multi-line stack trace stitching."""

import json
import re
from typing import List, Optional, Tuple
from .models import LogEntry, LogLevel


class LogParser:
    """Parses various Kubernetes container log formats into structured LogEntry objects."""

    # CRI format regex: "2026-09-22T12:00:00.123456789Z stdout F ..."
    CRI_REGEX = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
        r"(?P<stream>stdout|stderr)\s+"
        r"(?P<tag>[FP])\s+"
        r"(?P<message>.*)$"
    )

    # ISO8601 or common timestamp at start of line
    TIMESTAMP_REGEX = re.compile(
        r"^(?:\[)?(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?:\])?\s*"
    )

    # Standard log levels
    LEVEL_REGEX = re.compile(
        r"\b(?P<level>FATAL|CRITICAL|ERROR|SEVERE|WARN|WARNING|INFO|DEBUG|TRACE)\b",
        re.IGNORECASE,
    )

    # Stack trace indicators
    STACKTRACE_START = (
        "Traceback (most recent call last):",
        "panic: ",
        "goroutine ",
        "Exception in thread ",
        "Caused by: ",
    )

    STACKTRACE_CONTINUATION = (
        "    at ",
        "\tat ",
        "  File \"",
        "    ",
        "\t",
    )

    def parse(self, raw_logs: str) -> List[LogEntry]:
        """Parses a multi-line string of logs into a list of LogEntry objects."""
        lines = raw_logs.splitlines()
        entries: List[LogEntry] = []
        current_trace_lines: List[str] = []
        target_entry: Optional[LogEntry] = None

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            in_trace = bool(current_trace_lines)

            # Check if this line continues an active stack trace
            if in_trace and self._is_stack_continuation(line, stripped, in_trace=True):
                current_trace_lines.append(line)
                continue

            # If we were in a trace and reached the end of it, finalize target_entry
            if current_trace_lines and target_entry:
                target_entry.stack_trace = "\n".join(current_trace_lines)
                current_trace_lines = []
                target_entry = None

            # Check if this line is the beginning of a stack trace
            if self._is_stack_start(stripped):
                # If preceding entry was an ERROR/FATAL, attach trace to it
                if entries and entries[-1].level in (LogLevel.ERROR, LogLevel.FATAL, LogLevel.CRITICAL) and not entries[-1].stack_trace:
                    target_entry = entries[-1]
                    target_entry.is_stack_trace = True
                    current_trace_lines = [line]
                    continue
                else:
                    entry = self._parse_single_line(idx, line)
                    entry.is_stack_trace = True
                    entries.append(entry)
                    target_entry = entry
                    current_trace_lines = [line]
                    continue

            # Parse a standard single log line
            entry = self._parse_single_line(idx, line)
            entries.append(entry)

        # Attach any trailing stack trace
        if current_trace_lines and target_entry:
            target_entry.stack_trace = "\n".join(current_trace_lines)

        return entries

    def _is_stack_start(self, stripped: str) -> bool:
        """Determines if a line starts an unhandled exception or stack trace."""
        for pattern in self.STACKTRACE_START:
            if stripped.startswith(pattern):
                return True
        if stripped.startswith("Exception:") or stripped.startswith("Error:"):
            return True
        return False

    def _is_stack_continuation(self, raw_line: str, stripped: str, in_trace: bool = False) -> bool:
        """Determines if a line continues a previous stack trace."""
        for pattern in self.STACKTRACE_CONTINUATION:
            if raw_line.startswith(pattern):
                return True
        if stripped.startswith("at ") or stripped.startswith("Caused by: ") or stripped.startswith("..."):
            return True
        # If inside a trace, unindented lines without timestamps or CRI headers that specify the exception type
        if in_trace:
            if self.TIMESTAMP_REGEX.match(raw_line) or self.CRI_REGEX.match(raw_line):
                return False
            # Check for standard exception names like ValueError:, KeyError:, RuntimeException:
            if re.match(r"^[a-zA-Z0-9_\.]+(?:Error|Exception|Panic|Fault):\s*", stripped):
                return True
        return False

    def _parse_single_line(self, line_number: int, raw_text: str) -> LogEntry:
        """Attempts to parse a line using JSON, CRI, or plain text heuristics."""
        stripped = raw_text.strip()

        # 1. Try Container / App JSON Log
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    return self._from_json(line_number, raw_text, data)
            except Exception:
                pass

        # 2. Try Kubernetes CRI Format
        cri_match = self.CRI_REGEX.match(raw_text)
        if cri_match:
            timestamp = cri_match.group("timestamp")
            stream = cri_match.group("stream")
            msg = cri_match.group("message")
            level = self._extract_level(msg)
            return LogEntry(
                line_number=line_number,
                raw_text=raw_text,
                message=msg,
                timestamp=timestamp,
                level=level,
                stream=stream,
            )

        # 3. Logfmt or Standard Text Log
        timestamp, remaining = self._extract_timestamp(raw_text)
        level = self._extract_level(remaining or raw_text)

        return LogEntry(
            line_number=line_number,
            raw_text=raw_text,
            message=remaining if remaining else raw_text,
            timestamp=timestamp,
            level=level,
            stream=None,
        )

    def _from_json(self, line_number: int, raw_text: str, data: dict) -> LogEntry:
        """Extracts fields from parsed JSON dictionary."""
        # Docker/CRI format: {"log": "...", "stream": "stderr", "time": "..."}
        if "log" in data:
            raw_msg = data.get("log", "")
            timestamp = data.get("time")
            stream = data.get("stream")
            level = self._extract_level(raw_msg)
            return LogEntry(
                line_number=line_number,
                raw_text=raw_text,
                message=raw_msg.rstrip("\n"),
                timestamp=timestamp,
                level=level,
                stream=stream,
            )

        # App JSON format: {"msg": "...", "level": "error", "timestamp": "..."}
        msg = data.get("message") or data.get("msg") or data.get("error") or str(data)
        timestamp = data.get("timestamp") or data.get("time") or data.get("ts")
        if isinstance(timestamp, (int, float)):
            timestamp = str(timestamp)

        raw_level = data.get("level") or data.get("severity") or data.get("lvl")
        level = self._map_level(str(raw_level)) if raw_level else self._extract_level(str(msg))

        component = data.get("service") or data.get("component") or data.get("caller")

        stack_trace = None
        if "stack" in data:
            stack_trace = str(data["stack"])
        elif "stack_trace" in data:
            stack_trace = str(data["stack_trace"])

        return LogEntry(
            line_number=line_number,
            raw_text=raw_text,
            message=str(msg),
            timestamp=str(timestamp) if timestamp else None,
            level=level,
            stream=data.get("stream"),
            component=str(component) if component else None,
            is_stack_trace=bool(stack_trace),
            stack_trace=stack_trace,
        )

    def _extract_timestamp(self, text: str) -> Tuple[Optional[str], str]:
        """Extracts timestamp from beginning of line if present."""
        match = self.TIMESTAMP_REGEX.match(text)
        if match:
            ts = match.group("timestamp")
            remaining = text[match.end():]
            return ts, remaining
        return None, text

    def _extract_level(self, text: str) -> LogLevel:
        """Finds log level keywords within text."""
        match = self.LEVEL_REGEX.search(text)
        if match:
            return self._map_level(match.group("level"))
        return LogLevel.UNKNOWN

    def _map_level(self, val: str) -> LogLevel:
        v = val.upper()
        if "FATAL" in v:
            return LogLevel.FATAL
        if "CRIT" in v:
            return LogLevel.CRITICAL
        if "ERR" in v or "SEVERE" in v:
            return LogLevel.ERROR
        if "WARN" in v:
            return LogLevel.WARN
        if "INFO" in v:
            return LogLevel.INFO
        if "DEBUG" in v:
            return LogLevel.DEBUG
        if "TRACE" in v:
            return LogLevel.TRACE
        return LogLevel.UNKNOWN
