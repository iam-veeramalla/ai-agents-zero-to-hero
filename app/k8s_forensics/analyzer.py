"""Forensic analysis engine for Kubernetes container logs."""

from typing import List, Optional
from .models import (
    EvidenceItem,
    InvestigationReport,
    IssueCategory,
    LogEntry,
    LogLevel,
    RemediationStep,
    RootCause,
    SeverityLevel,
    TimelineEvent,
)
from .parser import LogParser
from .rules import RULES, DiagnosticRule


class LogAnalyzer:
    """Analyzes Kubernetes logs, extracts supporting evidence, and generates an investigation report."""

    def __init__(self, parser: Optional[LogParser] = None):
        self.parser = parser or LogParser()

    def analyze(self, raw_logs: str, max_evidence_items: int = 15) -> InvestigationReport:
        """Runs end-to-end investigation on raw log text."""
        entries = self.parser.parse(raw_logs)
        raw_lines = raw_logs.splitlines()

        if not entries:
            return InvestigationReport(
                title="Empty or Unparseable Log Input",
                severity=SeverityLevel.INFO,
                status="NO_LOGS_PROVIDED",
                summary="No log entries could be extracted from the input provided.",
                detected_issues=[],
                root_causes=[],
                evidence=[],
                timeline=[],
                impact_assessment="No logs available to assess impact.",
                remediation_steps=[],
                metadata={"total_lines": 0},
            )

        # 1. Match entries against diagnostic rules and extract evidence
        evidence_items: List[EvidenceItem] = []
        matched_rules: List[DiagnosticRule] = []
        ev_counter = 1

        for entry in entries:
            text_to_scan = f"{entry.message} {entry.stack_trace or ''}"

            for rule in RULES:
                if rule.pattern.search(text_to_scan):
                    # Extract surrounding lines for full forensic context
                    start_idx = max(0, entry.line_number - 3)
                    end_idx = min(len(raw_lines), entry.line_number + 2)
                    context = [
                        f"L{i+1}: {raw_lines[i]}"
                        for i in range(start_idx, end_idx)
                    ]

                    # Pick the best excerpt (stack trace if present, else message)
                    excerpt = (
                        entry.stack_trace[:300] + "..."
                        if (entry.stack_trace and len(entry.stack_trace) > 300)
                        else (entry.stack_trace or entry.message)
                    )

                    ev = EvidenceItem(
                        id=f"EV-{ev_counter:03d}",
                        line_number=entry.line_number,
                        timestamp=entry.timestamp,
                        log_excerpt=excerpt,
                        context_lines=context,
                        category=rule.category,
                        signal_name=rule.title,
                        explanation=rule.explanation,
                        confidence=rule.confidence,
                    )
                    evidence_items.append(ev)
                    ev_counter += 1

                    if rule not in matched_rules:
                        matched_rules.append(rule)

                    if len(evidence_items) >= max_evidence_items:
                        break

            if len(evidence_items) >= max_evidence_items:
                break

        # 2. Compute log metadata and error statistics
        error_count = sum(1 for e in entries if e.level in (LogLevel.ERROR, LogLevel.FATAL, LogLevel.CRITICAL))
        warn_count = sum(1 for e in entries if e.level in (LogLevel.WARN, LogLevel.WARNING))
        timestamps = [e.timestamp for e in entries if e.timestamp]
        time_range = {
            "start": timestamps[0] if timestamps else None,
            "end": timestamps[-1] if timestamps else None,
        }

        # 3. Construct chronological timeline
        timeline = self._build_timeline(entries)

        # 4. Synthesize Root Causes and Action Plan
        root_causes, severity, remediation_steps = self._synthesize_causes(matched_rules, entries, error_count)

        detected_issues = [r.title for r in root_causes]
        if not detected_issues and error_count > 0:
            detected_issues = ["Unclassified Application Errors Detected"]

        # 5. Formulate Executive Summary & Impact Assessment
        status, summary, impact = self._generate_narrative(
            root_causes=root_causes,
            error_count=error_count,
            warn_count=warn_count,
            total_entries=len(entries),
            evidence_count=len(evidence_items),
        )

        return InvestigationReport(
            title=f"Kubernetes Incident Investigation: {root_causes[0].title if root_causes else 'Log Health Check'}",
            severity=severity,
            status=status,
            summary=summary,
            detected_issues=detected_issues,
            root_causes=root_causes,
            evidence=evidence_items,
            timeline=timeline,
            impact_assessment=impact,
            remediation_steps=remediation_steps,
            metadata={
                "total_lines": len(raw_lines),
                "parsed_entries": len(entries),
                "error_count": error_count,
                "warning_count": warn_count,
                "time_range": time_range,
                "evidence_count": len(evidence_items),
            },
        )

    def _build_timeline(self, entries: List[LogEntry]) -> List[TimelineEvent]:
        """Builds a condensed milestone timeline of the incident."""
        timeline: List[TimelineEvent] = []
        has_normal = False
        has_warn = False
        has_error = False

        for entry in entries:
            # Capture normal baseline
            if not has_normal and entry.level == LogLevel.INFO:
                timeline.append(
                    TimelineEvent(
                        timestamp=entry.timestamp,
                        line_number=entry.line_number,
                        phase="Baseline Operation",
                        description="Application running normally and logging information messages.",
                        log_excerpt=entry.message[:120],
                    )
                )
                has_normal = True

            # Capture initial warning
            elif not has_warn and entry.level in (LogLevel.WARN, LogLevel.WARNING):
                timeline.append(
                    TimelineEvent(
                        timestamp=entry.timestamp,
                        line_number=entry.line_number,
                        phase="Initial Warning",
                        description="Warning indicator detected in log stream.",
                        log_excerpt=entry.message[:120],
                    )
                )
                has_warn = True

            # Capture onset of failure
            elif not has_error and entry.level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL):
                timeline.append(
                    TimelineEvent(
                        timestamp=entry.timestamp,
                        line_number=entry.line_number,
                        phase="Incident Onset",
                        description="First error or fatal condition logged.",
                        log_excerpt=entry.message[:120],
                    )
                )
                has_error = True

            # Capture explicit crash or termination
            if "exit code" in entry.message.lower() or "oomkilled" in entry.message.lower() or "crashloop" in entry.message.lower():
                timeline.append(
                    TimelineEvent(
                        timestamp=entry.timestamp,
                        line_number=entry.line_number,
                        phase="Termination / Crash",
                        description="Pod/container termination or restart back-off triggered.",
                        log_excerpt=entry.message[:120],
                    )
                )

        return timeline[:8]  # Keep milestone timeline concise

    def _synthesize_causes(
        self, matched_rules: List[DiagnosticRule], entries: List[LogEntry], error_count: int
    ) -> tuple[List[RootCause], SeverityLevel, List[RemediationStep]]:
        """Synthesizes root causes from matched rules and error severity."""
        if not matched_rules:
            if error_count > 0:
                generic_cause = RootCause(
                    category=IssueCategory.APP_EXCEPTION,
                    title="Generic Application Runtime Errors",
                    confidence=0.75,
                    summary=f"Found {error_count} error log entries without matching a specific Kubernetes infrastructure failure signature.",
                    technical_details="Review application stack traces and unhandled exceptions in the supporting evidence.",
                    contributing_factors=["Application-level exception", "Missing handler"],
                )
                return [generic_cause], SeverityLevel.MEDIUM, [
                    RemediationStep(
                        order=1,
                        action="Inspect application error logs and stack traces",
                        type="investigative",
                        command_or_yaml="kubectl logs <pod-name> -n <namespace> | grep -i error",
                        rationale="Locates application-level bug or uncaught exception.",
                    )
                ]
            else:
                return [], SeverityLevel.INFO, []

        # Prioritize root cause categories over symptoms:
        # e.g., OOM, Network, DB, Config, RBAC, ImagePull are primary causes; CrashLoop / Probe are symptoms.
        PRIMARY_PRIORITY = {
            IssueCategory.NODE_NOT_READY: 1,
            IssueCategory.NODE_MEMORY_PRESSURE: 2,
            IssueCategory.RESOURCE_LIMITS: 3,
            IssueCategory.OOM_KILLED: 4,
            IssueCategory.CPU_THROTTLING: 5,
            IssueCategory.SERVICE_NO_ENDPOINTS: 6,
            IssueCategory.SERVICE_ROUTING: 7,
            IssueCategory.CONFIG_SECRET: 8,
            IssueCategory.RBAC_PERMISSION: 9,
            IssueCategory.IMAGE_PULL: 10,
            IssueCategory.STORAGE_VOLUME: 11,
            IssueCategory.DATABASE_BACKEND: 12,
            IssueCategory.NETWORK_DNS: 13,
            IssueCategory.APP_EXCEPTION: 14,
            IssueCategory.PROBE_FAILURE: 15,
            IssueCategory.CRASH_LOOP: 16,
        }

        sorted_rules = sorted(
            matched_rules,
            key=lambda r: (PRIMARY_PRIORITY.get(r.category, 50), -r.confidence),
        )

        root_causes: List[RootCause] = []
        remediation_steps: List[RemediationStep] = []
        highest_severity = SeverityLevel.LOW

        for rule in sorted_rules:
            # Update severity
            if rule.severity == SeverityLevel.CRITICAL:
                highest_severity = SeverityLevel.CRITICAL
            elif rule.severity == SeverityLevel.HIGH and highest_severity != SeverityLevel.CRITICAL:
                highest_severity = SeverityLevel.HIGH
            elif rule.severity == SeverityLevel.MEDIUM and highest_severity not in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                highest_severity = SeverityLevel.MEDIUM

            root_causes.append(
                RootCause(
                    category=rule.category,
                    title=rule.title,
                    confidence=rule.confidence,
                    summary=rule.explanation,
                    technical_details=f"Matched diagnostic signature {rule.rule_id}.",
                    contributing_factors=[rule.title],
                )
            )

            for step in rule.remediations:
                if step.action not in [s.action for s in remediation_steps]:
                    step_copy = step.model_copy()
                    step_copy.order = len(remediation_steps) + 1
                    remediation_steps.append(step_copy)

        return root_causes, highest_severity, remediation_steps

    def _generate_narrative(
        self,
        root_causes: List[RootCause],
        error_count: int,
        warn_count: int,
        total_entries: int,
        evidence_count: int,
    ) -> tuple[str, str, str]:
        """Creates the executive summary and impact assessment."""
        if not root_causes:
            if error_count == 0:
                return (
                    "HEALTHY",
                    f"Analyzed {total_entries} log entries. No critical Kubernetes anomalies or errors detected.",
                    "No negative impact detected on service availability.",
                )
            return (
                "DEGRADED",
                f"Analyzed {total_entries} log entries. Detected {error_count} errors and {warn_count} warnings, but no specific Kubernetes infrastructure failures.",
                "Service may be experiencing intermittent request degradation or unhandled errors.",
            )

        primary = root_causes[0]
        status = f"INCIDENT_{primary.category.value}"
        summary = (
            f"Forensic investigation identified a **{primary.title}** condition with {int(primary.confidence * 100)}% confidence. "
            f"The log stream contained {error_count} error events and {warn_count} warning events across {total_entries} parsed entries. "
            f"Extracted {evidence_count} key supporting evidence items demonstrating the root cause."
        )

        impact = (
            f"High impact on workload reliability. The detected {primary.category.value} condition directly affects pod availability, "
            f"causing service restarts, request drops, or traffic routing disruptions."
        )

        return status, summary, impact
