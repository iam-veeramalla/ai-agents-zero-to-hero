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

    # 10. CPU THROTTLING
    DiagnosticRule(
        rule_id="K8S_CPU_001",
        category=IssueCategory.CPU_THROTTLING,
        title="Container CPU Throttling (CFS Quota Throttled)",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(CPU throttling detected|container.*throttled|throttled_time|nr_throttled|cfs_quota exceeded|CPU quota exceeded|throttled periods:\s*[1-9]\d*|high CPU throttling)",
            re.IGNORECASE,
        ),
        explanation="The container exceeded its configured CPU CFS quota limit, causing the Linux kernel scheduler to throttle process execution cycles and introduce severe latency.",
        confidence=0.95,
        remediations=[
            RemediationStep(
                order=1,
                action="Increase or remove CPU limits in deployment specification",
                type="immediate",
                command_or_yaml="resources:\n  requests:\n    cpu: \"1000m\"\n  limits:\n    cpu: \"2000m\"",
                rationale="Prevents Linux Completely Fair Scheduler (CFS) quota throttling from penalizing active worker threads.",
            ),
            RemediationStep(
                order=2,
                action="Profile CPU utilization and thread concurrency",
                type="investigative",
                command_or_yaml="kubectl top pod <pod-name> -n <namespace> --containers",
                rationale="Identifies compute-heavy processing loops or thread starvation within the container.",
            ),
        ],
    ),

    # 11. NODE MEMORY PRESSURE
    DiagnosticRule(
        rule_id="K8S_NODE_MEM_001",
        category=IssueCategory.NODE_MEMORY_PRESSURE,
        title="Node Memory Pressure & Pod Eviction",
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(NodeHasMemoryPressure|eviction manager: evicting pod.*due to node memory pressure|The node was low on resource: memory|Node condition MemoryPressure is True|status:\s*MemoryPressure)",
            re.IGNORECASE,
        ),
        explanation="The Kubernetes worker node is experiencing severe memory exhaustion exceeding kubelet eviction thresholds, triggering pod eviction.",
        confidence=0.97,
        remediations=[
            RemediationStep(
                order=1,
                action="Inspect node memory utilization and describe node conditions",
                type="investigative",
                command_or_yaml="kubectl describe node <node-name> | grep -A 8 Conditions",
                rationale="Confirms MemoryPressure condition and allocatable memory status.",
            ),
            RemediationStep(
                order=2,
                action="Add node capacity or evict BestEffort workloads",
                type="immediate",
                command_or_yaml="kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data",
                rationale="Relieves memory pressure on the affected node and redistributes pods across healthy nodes.",
            ),
        ],
    ),

    # 12. NODE NOT READY
    DiagnosticRule(
        rule_id="K8S_NODE_NOTREADY_001",
        category=IssueCategory.NODE_NOT_READY,
        title="Kubernetes Node in NotReady State",
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(NodeNotReady|Node condition Ready is False|Kubelet stopped posting node status|PLEG is not healthy|container runtime is down|Node status is NotReady|Node.*NotReady)",
            re.IGNORECASE,
        ),
        explanation="The worker node has transitioned to NotReady status because kubelet stopped posting heartbeats or the container runtime became unresponsive.",
        confidence=0.98,
        remediations=[
            RemediationStep(
                order=1,
                action="Check kubelet and container runtime service logs on worker node",
                type="investigative",
                command_or_yaml="systemctl status kubelet containerd",
                rationale="Identifies systemd crashes, disk stalls, or PLEG timeouts causing kubelet failure.",
            ),
            RemediationStep(
                order=2,
                action="Restart kubelet and verify node network communication",
                type="immediate",
                command_or_yaml="systemctl restart kubelet",
                rationale="Restores node heartbeat reporting to kube-apiserver.",
            ),
        ],
    ),

    # 13. INCORRECT RESOURCE REQUESTS / LIMITS
    DiagnosticRule(
        rule_id="K8S_RES_001",
        category=IssueCategory.RESOURCE_LIMITS,
        title="Resource Requests Exceeding Node Capacity or Namespace Quota",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(Insufficient cpu|Insufficient memory|exceeded quota: compute-resources|request is greater than limit|failed quota|exceeded quota: requests\.(?:cpu|memory)|0/\d+ nodes are available: \d+ Insufficient)",
            re.IGNORECASE,
        ),
        explanation="Pod cannot be scheduled or admitted because its requested CPU or memory exceeds available node capacity or the namespace ResourceQuota limits.",
        confidence=0.96,
        remediations=[
            RemediationStep(
                order=1,
                action="Right-size container resource requests to match cluster node allocatable capacity",
                type="immediate",
                command_or_yaml="resources:\n  requests:\n    cpu: \"250m\"\n    memory: \"256Mi\"\n  limits:\n    cpu: \"500m\"\n    memory: \"512Mi\"",
                rationale="Ensures pod fits within available node capacity and satisfies namespace ResourceQuotas.",
            ),
            RemediationStep(
                order=2,
                action="Check namespace ResourceQuotas and node allocatable resources",
                type="investigative",
                command_or_yaml="kubectl get resourcequota -n <namespace>",
                rationale="Reveals used vs hard limits for CPU and memory in the namespace.",
            ),
        ],
    ),

    # 14. SERVICE HAS NO ENDPOINTS
    DiagnosticRule(
        rule_id="K8S_SVC_ENDPOINTS_001",
        category=IssueCategory.SERVICE_NO_ENDPOINTS,
        title="Kubernetes Service Has No Endpoints",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(Endpoints:\s*<none>|no endpoints available for service|Service has no endpoints|0 endpoints available|failed to find endpoints for service|no healthy endpoints)",
            re.IGNORECASE,
        ),
        explanation="The Kubernetes Service has 0 active endpoints. Either no pods match the Service's spec.selector or matching pods are failing readiness probes.",
        confidence=0.96,
        remediations=[
            RemediationStep(
                order=1,
                action="Verify Service selector matches Pod labels",
                type="investigative",
                command_or_yaml="kubectl get svc <service-name> -n <namespace> -o jsonpath='{.spec.selector}'\nkubectl get pods --show-labels -n <namespace>",
                rationale="Confirms whether selector label keys and values match the workload pod labels.",
            ),
            RemediationStep(
                order=2,
                action="Check readiness probe status of target pods",
                type="investigative",
                command_or_yaml="kubectl get pods -l <selector-key>=<selector-value> -n <namespace> -o wide",
                rationale="Determines whether pods are running but unready (0/1 Ready).",
            ),
        ],
    ),

    # 15. SERVICE ROUTES TO WRONG / UNHEALTHY PODS
    DiagnosticRule(
        rule_id="K8S_SVC_ROUTING_001",
        category=IssueCategory.SERVICE_ROUTING,
        title="Service Routing to Wrong or Unhealthy Pods",
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(traffic routed to wrong pod|targetPort mismatch|selector.*matches unexpected pods|Service routing to unhealthy pod|Endpoints:\s*.*\(NotReady\)|upstream connect error.*502 Bad Gateway|Service selector mismatch)",
            re.IGNORECASE,
        ),
        explanation="Traffic is being routed to incorrect or unready pods due to overly broad selector labels or mismatched targetPort definitions.",
        confidence=0.93,
        remediations=[
            RemediationStep(
                order=1,
                action="Disambiguate Service selector labels and verify targetPort",
                type="immediate",
                command_or_yaml="spec:\n  selector:\n    app.kubernetes.io/name: <app>\n    app.kubernetes.io/version: <v2>\n  ports:\n  - port: 80\n    targetPort: 8080",
                rationale="Prevents traffic bleed into canary or unintended deployments and ensures port alignment.",
            ),
            RemediationStep(
                order=2,
                action="Inspect active Service endpoints and target pod addresses",
                type="investigative",
                command_or_yaml="kubectl get endpoints <service-name> -n <namespace> -o yaml",
                rationale="Shows the exact IP addresses and readiness ports registered behind the Service.",
            ),
        ],
    ),
]
