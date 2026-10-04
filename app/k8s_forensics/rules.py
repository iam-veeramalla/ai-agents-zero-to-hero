"""Diagnostic rules and pattern signatures for Kubernetes and container failures."""

import re
from typing import Dict, List, NamedTuple, Optional
from .models import IssueCategory, RemediationStep, SeverityLevel


class DiagnosticRule(NamedTuple):
    rule_id: str
    category: IssueCategory
    title: str
    severity: SeverityLevel
    pattern: re.Pattern
    explanation: str
    confidence: float
    remediations: List[RemediationStep]


# Comprehensive signature catalog for Kubernetes failures
RULES: List[DiagnosticRule] = [
    # 1. OOMKILLED / MEMORY LIMIT
    DiagnosticRule(
        rule_id="K8S_OOM_001",
        category=IssueCategory.OOM_KILLED,
        title="Container Terminated Due to OOMKilled (Exit Code 137)",
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(OOMKilled|exit code 137|cgroup out of memory|Killed process \d+ .*total-vm:|Memory cgroup out of memory|fatal error: runtime: out of memory)",
            re.IGNORECASE,
        ),
        explanation="The container exceeded its configured cgroup memory limit or node memory was exhausted, causing the Linux kernel OOM Killer to terminate the process.",
        confidence=0.98,
        remediations=[
            RemediationStep(
                order=1,
                action="Increase Pod memory limits in deployment manifest",
                type="immediate",
                command_or_yaml="resources:\n  limits:\n    memory: \"1Gi\"\n  requests:\n    memory: \"512Mi\"",
                rationale="Prevents the kernel OOM killer from terminating the container during memory consumption spikes.",
            ),
            RemediationStep(
                order=2,
                action="Inspect recent pod termination status with kubectl",
                type="investigative",
                command_or_yaml="kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.containerStatuses[*].lastState.terminated}'",
                rationale="Confirms exit code 137 and OOMKilled reason from the kubelet status.",
            ),
            RemediationStep(
                order=3,
                action="Profile application memory usage for leaks",
                type="permanent_fix",
                command_or_yaml="kubectl exec -it <pod-name> -n <namespace> -- <memory-profiler-command>",
                rationale="Identifies unbounded memory growth, unclosed connections, or oversized caching layers.",
            ),
        ],
    ),
    DiagnosticRule(
        rule_id="JAVA_OOM_002",
        category=IssueCategory.OOM_KILLED,
        title="Java Virtual Machine OutOfMemoryError",
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(java\.lang\.OutOfMemoryError:\s*(?:Java heap space|Metaspace|GC overhead limit exceeded))",
            re.IGNORECASE,
        ),
        explanation="The JVM exhausted its allocated heap or metaspace before the container-level memory limit was hit.",
        confidence=0.99,
        remediations=[
            RemediationStep(
                order=1,
                action="Tune JVM heap parameters to match container memory limits",
                type="immediate",
                command_or_yaml="env:\n  - name: JAVA_TOOL_OPTIONS\n    value: \"-XX:MaxRAMPercentage=75.0 -XX:+UseContainerSupport\"",
                rationale="Ensures the JVM respects Kubernetes cgroup memory limits rather than node physical RAM.",
            ),
        ],
    ),

    # 2. CRASHLOOP & PANIC
    DiagnosticRule(
        rule_id="K8S_CRASHLOOP_001",
        category=IssueCategory.CRASH_LOOP,
        title="Pod in CrashLoopBackOff",
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(CrashLoopBackOff|Back-off restarting failed container|restarting container.*due to exit code)",
            re.IGNORECASE,
        ),
        explanation="The application crashed shortly after startup and Kubernetes is applying an exponential backoff delay before restarting it.",
        confidence=0.95,
        remediations=[
            RemediationStep(
                order=1,
                action="Retrieve previous container crash logs",
                type="investigative",
                command_or_yaml="kubectl logs <pod-name> -n <namespace> --previous --tail=200",
                rationale="Captures the fatal exception or exit stack trace from the crashed instance before it restarted.",
            ),
            RemediationStep(
                order=2,
                action="Describe pod to check restart count and termination reasons",
                type="investigative",
                command_or_yaml="kubectl describe pod <pod-name> -n <namespace>",
                rationale="Reveals exit codes, restart count, and events.",
            ),
        ],
    ),
    DiagnosticRule(
        rule_id="APP_PANIC_002",
        category=IssueCategory.APP_EXCEPTION,
        title="Fatal Application Runtime Panic / SIGSEGV",
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(panic:\s*runtime error:|SIGSEGV|Segmentation fault|fatal error:\s*concurrent map|Unhandled Exception:|terminate called after throwing)",
            re.IGNORECASE,
        ),
        explanation="The application encountered an unhandled fatal condition, nil-pointer dereference, or memory fault causing sudden process termination.",
        confidence=0.96,
        remediations=[
            RemediationStep(
                order=1,
                action="Inspect stack trace and pinpoint offending code path",
                type="immediate",
                command_or_yaml=None,
                rationale="Review the stack trace frames captured in the supporting evidence.",
            ),
        ],
    ),

    # 3. IMAGE PULL
    DiagnosticRule(
        rule_id="K8S_IMAGE_PULL_001",
        category=IssueCategory.IMAGE_PULL,
        title="Container Image Pull Failure (ImagePullBackOff / ErrImagePull)",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(ImagePullBackOff|ErrImagePull|Failed to pull image|manifest unknown|unauthorized: authentication required|rpc error: code = NotFound desc = failed to pull)",
            re.IGNORECASE,
        ),
        explanation="Kubernetes kubelet cannot download the container image from the container registry due to invalid image tag, non-existent repository, or missing authentication credentials.",
        confidence=0.98,
        remediations=[
            RemediationStep(
                order=1,
                action="Verify image name and tag existence in registry",
                type="investigative",
                command_or_yaml="kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[*].image}'",
                rationale="Checks whether the container image reference has typos or deprecated tags.",
            ),
            RemediationStep(
                order=2,
                action="Attach imagePullSecrets if accessing a private registry",
                type="immediate",
                command_or_yaml="imagePullSecrets:\n  - name: regcred",
                rationale="Provides docker-registry credentials required to pull private images.",
            ),
        ],
    ),

    # 4. NETWORK & DNS
    DiagnosticRule(
        rule_id="K8S_DNS_001",
        category=IssueCategory.NETWORK_DNS,
        title="DNS Resolution Failure (Lookup / CoreDNS Timeout)",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(dial tcp:\s*lookup\s*([a-zA-Z0-9\.\-_]+):\s*no such host|EAI_AGAIN|Name or service not known|Server failure: NXDOMAIN|DNS resolution failed)",
            re.IGNORECASE,
        ),
        explanation="The application failed to resolve a domain name or Kubernetes internal service DNS name (e.g. servicename.namespace.svc.cluster.local).",
        confidence=0.96,
        remediations=[
            RemediationStep(
                order=1,
                action="Check CoreDNS health and pods in kube-system",
                type="investigative",
                command_or_yaml="kubectl get pods -n kube-system -l k8s-app=kube-dns",
                rationale="Ensures the cluster DNS resolver pods are running and not crashlooping.",
            ),
            RemediationStep(
                order=2,
                action="Verify target service exists and matches DNS name format",
                type="investigative",
                command_or_yaml="kubectl get svc -n <namespace>",
                rationale="Verifies that the target Kubernetes Service name and namespace are typed correctly.",
            ),
        ],
    ),
    DiagnosticRule(
        rule_id="K8S_NET_CONN_002",
        category=IssueCategory.NETWORK_DNS,
        title="Network Connection Refused or Timed Out",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(connect:\s*connection refused|i/o timeout|context deadline exceeded|upstream connect error or disconnect/reset before headers|503 Service Unavailable)",
            re.IGNORECASE,
        ),
        explanation="The application attempted to establish a TCP or HTTP connection to an upstream endpoint, but the endpoint was either not listening or network path was unreachable.",
        confidence=0.92,
        remediations=[
            RemediationStep(
                order=1,
                action="Verify upstream service endpoints are active",
                type="investigative",
                command_or_yaml="kubectl get endpoints <service-name> -n <namespace>",
                rationale="Checks if there are ready target pods receiving traffic behind the Service.",
            ),
            RemediationStep(
                order=2,
                action="Check for restrictive NetworkPolicies",
                type="investigative",
                command_or_yaml="kubectl get networkpolicies -n <namespace>",
                rationale="Determines if pod ingress/egress is blocked by Kubernetes network policies.",
            ),
        ],
    ),

    # 5. HEALTH CHECK / PROBE FAILURE
    DiagnosticRule(
        rule_id="K8S_PROBE_001",
        category=IssueCategory.PROBE_FAILURE,
        title="Liveness / Readiness Probe Failure",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"((?:Liveness|Readiness|Startup)\s*probe failed:.*(?:HTTP probe failed with statuscode:\s*(?:500|502|503|504)|connection refused|timeout))",
            re.IGNORECASE,
        ),
        explanation="Kubelet health check probe failed. Failing readiness probes remove the pod from Service endpoints, while failing liveness probes cause kubelet to kill and restart the container.",
        confidence=0.95,
        remediations=[
            RemediationStep(
                order=1,
                action="Check probe configuration and adjust timing thresholds",
                type="immediate",
                command_or_yaml="readinessProbe:\n  httpGet:\n    path: /healthz\n    port: 8080\n  initialDelaySeconds: 30\n  periodSeconds: 10\n  timeoutSeconds: 5\n  failureThreshold: 3",
                rationale="Gives slow-starting applications sufficient time to initialize before health probes evaluate.",
            ),
            RemediationStep(
                order=2,
                action="Check application logs during the probe execution window",
                type="investigative",
                command_or_yaml="kubectl logs <pod-name> -n <namespace> --tail=100",
                rationale="Identifies why the /healthz or probe endpoint returned a 5xx error or timed out.",
            ),
        ],
    ),

    # 6. STORAGE & VOLUME
    DiagnosticRule(
        rule_id="K8S_VOL_001",
        category=IssueCategory.STORAGE_VOLUME,
        title="PersistentVolume / Storage Mount Failure",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(MountVolume\.SetUp failed|Read-only file system|no space left on device|PVC.*is not bound|DiskPressure)",
            re.IGNORECASE,
        ),
        explanation="The container failed to attach, mount, or write to its storage volume, or the node disk has run out of space (DiskPressure).",
        confidence=0.94,
        remediations=[
            RemediationStep(
                order=1,
                action="Inspect PVC and PV binding status",
                type="investigative",
                command_or_yaml="kubectl get pvc,pv -n <namespace>",
                rationale="Verifies whether PersistentVolumeClaims are Bound or stuck in Pending status.",
            ),
            RemediationStep(
                order=2,
                action="Check node disk usage and events",
                type="investigative",
                command_or_yaml="kubectl describe node <node-name> | grep -A 5 Conditions",
                rationale="Identifies if the node is reporting DiskPressure condition.",
            ),
        ],
    ),

    # 7. RBAC & PERMISSIONS
    DiagnosticRule(
        rule_id="K8S_RBAC_001",
        category=IssueCategory.RBAC_PERMISSION,
        title="Kubernetes RBAC Authorization Denied (403 Forbidden)",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(403 Forbidden|User \"system:serviceaccount:[^\"]+\" cannot [^ ]+ resource \"[^\"]+\"|is forbidden:\s*User|permission denied)",
            re.IGNORECASE,
        ),
        explanation="The pod's ServiceAccount does not have the required RBAC Role or ClusterRole permissions to perform the requested API action.",
        confidence=0.97,
        remediations=[
            RemediationStep(
                order=1,
                action="Grant required RBAC permissions via RoleBinding",
                type="immediate",
                command_or_yaml="apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  namespace: <namespace>\n  name: <pod-role>\nrules:\n- apiGroups: [\"\"]\n  resources: [\"pods\", \"services\", \"configmaps\"]\n  verbs: [\"get\", \"list\", \"watch\"]",
                rationale="Provides the necessary Kubernetes API authorization to the ServiceAccount.",
            ),
        ],
    ),

    # 8. DATABASE & BACKEND DEPENDENCY
    DiagnosticRule(
        rule_id="APP_DB_001",
        category=IssueCategory.DATABASE_BACKEND,
        title="Database Connection / Pool Exhaustion Failure",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(psycopg2\.OperationalError|Connection pool exhausted|Too many connections|MongoServerError|Deadlock found when trying to get lock|Redis connection timed out|could not connect to server:\s*Connection refused)",
            re.IGNORECASE,
        ),
        explanation="The application failed to communicate with its database or downstream backend service due to connection limits, timeouts, or network refusal.",
        confidence=0.93,
        remediations=[
            RemediationStep(
                order=1,
                action="Check database pod/instance status and connection metrics",
                type="investigative",
                command_or_yaml="kubectl get pods -l app=database -n <namespace>",
                rationale="Verifies that the database backend is healthy and accepting connections.",
            ),
            RemediationStep(
                order=2,
                action="Tune client connection pool size and idle timeouts",
                type="immediate",
                command_or_yaml=None,
                rationale="Prevents client instances from holding onto idle connections during traffic bursts.",
            ),
        ],
    ),

    # 9. CONFIGURATION & SECRETS
    DiagnosticRule(
        rule_id="K8S_CONFIG_001",
        category=IssueCategory.CONFIG_SECRET,
        title="Missing Configuration, Secret, or Environment Variable",
        severity=SeverityLevel.MEDIUM,
        pattern=re.compile(
            r"(ConfigMap \"[^\"]+\" not found|Secret \"[^\"]+\" not found|KeyError:\s*'[A-Z0-9_]+'|environment variable [^\s]+ is not set|failed to load configuration|yaml:\s*unmarshal errors)",
            re.IGNORECASE,
        ),
        explanation="The application attempted to load a configuration key, secret, or environment variable that was missing or malformed.",
        confidence=0.91,
        remediations=[
            RemediationStep(
                order=1,
                action="Verify ConfigMap and Secret existence in the target namespace",
                type="investigative",
                command_or_yaml="kubectl get configmap,secret -n <namespace>",
                rationale="Ensures the configuration resources exist before pods start.",
            ),
        ],
    ),
]
