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


def test_analyze_cpu_throttling():
    logs = """2026-09-22T12:00:00.000Z [INFO] worker - Processing video transcode job #4018
2026-09-22T12:00:15.120Z [WARN] cgroup.cpu - CPU quota exceeded: throttled periods: 842 / 1000 (84.2%)
2026-09-22T12:00:18.450Z [ERROR] worker - High CPU throttling detected on container video-processor (throttled_time: 14200ms)"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.HIGH
    assert report.status == "INCIDENT_CPU_THROTTLING"
    assert any(ev.category == IssueCategory.CPU_THROTTLING for ev in report.evidence)
    assert any("CPU Throttling" in rc.title for rc in report.root_causes)


def test_analyze_node_memory_pressure():
    logs = """2026-09-22T14:10:00.000Z [INFO] kubelet - Node condition MemoryPressure is True
2026-09-22T14:10:02.140Z [WARN] kubelet - The node was low on resource: memory. Threshold: 100Mi, Available: 48Mi
2026-09-22T14:10:05.900Z [ERROR] kubelet - eviction manager: evicting pod analytics-batch-8k92b due to node memory pressure"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.CRITICAL
    assert report.status == "INCIDENT_NODE_MEMORY_PRESSURE"
    assert any(ev.category == IssueCategory.NODE_MEMORY_PRESSURE for ev in report.evidence)


def test_analyze_node_not_ready():
    logs = """2026-09-22T15:00:00.000Z [WARN] kubelet - PLEG is not healthy: pleg was last seen active 3m20s ago
2026-09-22T15:01:10.000Z [ERROR] node-controller - Kubelet stopped posting node status
2026-09-22T15:01:15.000Z [ERROR] node-controller - Node gke-pool-1-worker-9a8c is NotReady"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.CRITICAL
    assert report.status == "INCIDENT_NODE_NOT_READY"
    assert any(ev.category == IssueCategory.NODE_NOT_READY for ev in report.evidence)


def test_analyze_resource_limits():
    logs = """2026-09-22T16:00:00.000Z [WARN] default-scheduler - 0/6 nodes are available: 6 Insufficient cpu, 6 Insufficient memory
2026-09-22T16:00:05.100Z [ERROR] admission-webhook - failed quota: compute-resources: exceeded quota: requests.cpu, requested: 8, used: 28, limited: 32"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.HIGH
    assert report.status == "INCIDENT_RESOURCE_LIMITS"
    assert any(ev.category == IssueCategory.RESOURCE_LIMITS for ev in report.evidence)


def test_analyze_service_no_endpoints():
    logs = """2026-09-22T17:00:00.000Z [WARN] ingress-nginx - Service has no endpoints: default/checkout-service
2026-09-22T17:00:05.100Z [ERROR] kube-proxy - Endpoints: <none> for service checkout-service in namespace default"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.HIGH
    assert report.status == "INCIDENT_SERVICE_NO_ENDPOINTS"
    assert any(ev.category == IssueCategory.SERVICE_NO_ENDPOINTS for ev in report.evidence)


def test_analyze_service_routing():
    logs = """2026-09-22T18:00:00.000Z [WARN] envoy - Service selector mismatch: selector matched unexpected pods
2026-09-22T18:00:05.100Z [ERROR] envoy - upstream connect error: 502 Bad Gateway, traffic routed to wrong pod with targetPort mismatch"""

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs)

    assert report.severity == SeverityLevel.HIGH
    assert report.status == "INCIDENT_SERVICE_ROUTING"
    assert any(ev.category == IssueCategory.SERVICE_ROUTING for ev in report.evidence)

