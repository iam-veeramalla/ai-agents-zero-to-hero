"""Unit tests for LogAnalyzer."""

import pytest
from app.k8s_forensics.analyzer import LogAnalyzer
from app.k8s_forensics.models import IssueCategory, SeverityLevel


def test_analyze_empty_logs():
    analyzer = LogAnalyzer()
    report = analyzer.analyze("")
    assert report.status == "NO_LOGS_PROVIDED"
    assert report.severity == SeverityLevel.INFO
    assert len(report.evidence) == 0


def test_analyze_oom_killed():
    logs = """2026-09-22T10:14:02.102Z stdout F [INFO] Starting PaymentService
2026-09-22T10:14:45.301Z stdout F [WARN] High heap memory utilization detected: 92% of 512MB used
2026-09-22T10:15:22.502Z stderr F java.lang.OutOfMemoryError: Java heap space
2026-09-22T10:15:24.019Z stderr F [FATAL] cgroup out of memory: Killed process 42 (java) total-vm:845320kB, anon-rss:524288kB
2026-09-22T10:15:24.120Z stderr F Container payment-processor terminated with exit code 137 (OOMKilled)"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.CRITICAL
    assert report.status == "INCIDENT_OOM_KILLED"
    assert len(report.evidence) >= 2
    assert any(ev.category == IssueCategory.OOM_KILLED for ev in report.evidence)
    assert len(report.timeline) > 0
    assert len(report.remediation_steps) > 0


def test_analyze_dns_failure():
    logs = """{"time":"2026-09-22T04:12:00.100Z","level":"INFO","msg":"Starting inventory sync service"}
{"time":"2026-09-22T04:12:06.310Z","level":"ERROR","caller":"client.go:88","msg":"Get \\"http://catalog-service.production.svc.cluster.local:8080/v1/items\\": dial tcp: lookup catalog-service.production.svc.cluster.local: no such host"}
{"time":"2026-09-22T04:12:12.600Z","level":"ERROR","caller":"envoy.proxy:112","msg":"upstream connect error: 503 Service Unavailable"}"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.HIGH
    assert report.status == "INCIDENT_NETWORK_DNS"
    assert any(ev.category == IssueCategory.NETWORK_DNS for ev in report.evidence)
    assert any("DNS Resolution Failure" in rc.title for rc in report.root_causes)


def test_analyze_rbac_failure():
    logs = """2026-09-22T11:20:00.100Z [INFO] vault-agent - Initializing secrets sync sidecar
2026-09-22T11:20:03.951Z [ERROR] vault-agent - User "system:serviceaccount:default:vault-collector" cannot get resource "secrets" in API group "" in the namespace "default": 403 Forbidden
2026-09-22T11:20:04.100Z [FATAL] vault-agent - Authorization failure is fatal. Exiting with status 1."""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.HIGH
    assert report.status == "INCIDENT_RBAC_PERMISSION"
    assert any(ev.category == IssueCategory.RBAC_PERMISSION for ev in report.evidence)
