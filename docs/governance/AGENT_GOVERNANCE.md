# Kubernetes Investigation Agent: Governance & Operational Framework

**Document Version:** 1.0.0  
**Effective Date:** 2026-11-09  
**Status:** Approved & Enforced  
**Classification:** Internal — Platform Engineering & DevSecOps  

---

## Executive Summary

The **Kubernetes Investigation Agent (`k8s-investigator`)** is an autonomous SRE diagnostic agent engineered on the Google Agent Development Kit (ADK) and deployed to Agent Runtime (Reasoning Engine). It specializes in automated root-cause analysis, pod/node diagnostics, and incident reporting for Kubernetes clusters.

This governance document formalizes the operational boundaries, ownership hierarchy, security policies, memory boundaries, change control workflows, evaluation standards, and data access controls governing the agent across all environments.

---

## 1. Ownership & Stakeholder Matrix

### 1.1 Primary Ownership

| Role | Team / Entity | Responsibilities | Contact |
| :--- | :--- | :--- | :--- |
| **Primary System Owner** | **Platform Engineering & SRE** | Overall agent availability, infrastructure, operational performance, prompt tuning, and lifecycle management. | `#k8s-investigator-sre` / `sre-leads@company.internal` |
| **Agent Technical Steward** | **Kubernetes Reliability Pod** | Core agent logic (`app/agent.py`), forensic analyzers (`app/k8s_forensics/`), and tool development. | `k8s-agent-maintainers@company.internal` |
| **Security & Compliance Owner**| **DevSecOps & Cloud Security** | Enforcing least-privilege Gateway policies, SPIFFE/SPIRE attestation, RBAC verification, and vulnerability scanning. | `cloud-sec@company.internal` |
| **Evaluation & Quality Owner** | **AI Platform QA / SRE Leads** | Golden evaluation datasets, response quality rubrics, LLM-as-judge benchmarks, and regression gates. | `ai-eval-ops@company.internal` |

### 1.2 Escalation Hierarchy

1. **P1 / Security Policy Violation (e.g., Gateway egress breach, unauthorized tool execution attempt):**
   * PagerDuty: `k8s-agent-secops-urgent`
   * Immediate Action: Automatic Gateway-level token revocation and tool execution block via Agent Gateway policy.
2. **P2 / Availability or Reliability Incident (e.g., reasoning engine 5xx, cluster log analysis failure):**
   * PagerDuty: `k8s-sre-oncall`
   * Response Time: < 15 minutes.
3. **P3 / Evaluation Regression or Prompt Drifts:**
   * Handled during standard sprint cycle via PR review and eval compare analysis.

---

## 2. Gateway Permissions & Least-Privilege Architecture

The agent is strictly a **read-only diagnostic assistant**. It operates under zero-trust principles backed by cryptographic SPIFFE identity verification at the Google Cloud Agent Gateway and Kubernetes API server.

```
┌─────────────────────────────────┐
│     Agent Reasoning Engine      │
│  (SPIFFE Client Identity Auth)  │
└────────────────┬────────────────┘
                 │ mTLS (X.509 with URI SAN)
                 ▼
┌────────────────────────────────────────────────────────┐
│           Agent Gateway (IAP Authz Policy)             │
│  projects/.../agentGateways/k8s-investigator-gateway   │
└────────────────┬───────────────────────────────────────┘
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
[Allowed Read Tools]  [Denied Mutations & Secrets]
  - list_pods           - restart_deployment (BLOCKED)
  - get_pod_logs        - get_secret (BLOCKED)
  - get_pod_events      - pod deletion / patch (BLOCKED)
  - get_deployment_hist
  - get_nodes_info
  - investigate_logs
```

### 2.1 Identity Specification

* **Reasoning Engine Resource:** `projects/1098749337818/locations/us-east1/reasoningEngines/2253300647057162240`
* **Cryptographic SPIFFE ID:**
  ```text
  spiffe://agents.global.org-310633432312.system.id.goog/resources/aiplatform/projects/1098749337818/locations/us-east1/reasoningEngines/2253300647057162240
  ```
* **Enforcing Gateway:**
  `projects/k8s-investigation-agent/locations/us-east1/agentGateways/k8s-investigator-gateway`

### 2.2 Allowed Operations (Strict Whitelist)

The Agent Gateway (`authz-policy.yaml`, `unified-access-policy.yaml`, and `semantic-governance-policy.json`) strictly restricts the agent to the following **6 read-only diagnostic tools**:

| Tool Name | Underlying Kubernetes API | Purpose |
| :--- | :--- | :--- |
| `list_pods` | `core/v1: pods [get, list]` | Discover active, failing, or terminating pods in target namespaces. |
| `get_pod_logs` | `core/v1: pods/log [get]` | Fetch recent stdout/stderr execution logs from unhealthy containers. |
| `get_pod_events` | `core/v1 & events.k8s.io: events [get, list]` | Correlate Kubelet scheduling, container kills, and warning events. |
| `get_deployment_history` | `apps/v1: deployments, replicasets [get, list]` | Inspect rollout changes, image revisions, and deployment specifications. |
| `get_nodes_info` | `core/v1: nodes [get, list]` | Check cluster node resource pressure (OOM, disk pressure, PID limits). |
| `investigate_kubernetes_logs` | Local offline forensic engine (`app/k8s_forensics/`) | Run regex and signature parsers on captured logs with zero cluster API overhead. |

### 2.3 Explicitly Denied Operations

The following actions are **strictly forbidden** at both the Gateway layer and the Kubernetes RBAC layer:

1. **Mutating Operations (`restart_deployment`, `scale_deployment`, `patch_pod`, `delete_pod`):**
   * *Policy Enforcement:* Denied by Semantic Governance Policy rule `DENIED_MUTATION_TOOLS`.
   * *RBAC Enforcement:* ClusterRole `k8s-agent-spiffe-readonly-role` contains zero write verbs (`create`, `update`, `patch`, `delete`).
2. **Secret & Credential Access (`get_secret`, `list_secrets`):**
   * *Policy Enforcement:* Denied by Semantic Governance Policy rule `DENIED_SECRET_TOOLS`.
   * *RBAC Enforcement:* `secrets` resource is completely omitted from the RBAC ClusterRole.
3. **Arbitrary Egress:**
   * Gateway HTTP rules block any external outbound traffic other than authenticated Google Cloud Platform APIs (`*.googleapis.com`) and the verified internal MCP server (`34.138.10.186`).

---

## 3. Memory Bank Governance: Permitted vs. Prohibited Memory

The agent integrates with the Google Cloud Agent Platform **Memory Bank** (`app/app_utils/memory_config.py`) to recall operational insights across incidents while maintaining strict data isolation and privacy boundaries.

### 3.1 What the Agent CAN Remember

The agent is explicitly configured with custom and managed memory topics:

| Memory Topic | Type | Permitted Content |
| :--- | :--- | :--- |
| **`kubernetes_incident_findings`** | Custom Topic | Historical incident summaries, affected namespaces/deployments/pods, identified root causes (e.g., OOMKilled, CrashLoopBackOff, ImagePullBackOff, DNS timeouts), forensic signatures, and validated remediation runbooks. |
| **`KEY_CONVERSATION_DETAILS`** | Managed Topic | Key incident milestones, investigation timelines, and specific diagnostic tools executed during an on-call triage session. |
| **`EXPLICIT_INSTRUCTIONS`** | Managed Topic | Engineer-provided investigation directives (e.g., *"Always check events in the payments namespace before pulling node logs"*). |
| **`USER_PREFERENCES`** | Managed Topic | Report formatting preferences (e.g., executive summary table vs. deep CLI output, preferred UTC/PST timestamp formats). |
| **`USER_PERSONAL_INFO`** | Managed Topic | On-call SRE names, roles, and communication channels for report attribution. |

### 3.2 What the Agent CANNOT Remember (Strict Prohibitions)

The Memory Bank extraction pipelines and agent prompts must **never** store:

1. **Credentials & Secrets:**
   * Passwords, API tokens, JWTs, OAuth tokens, GCP service account keys, kubeconfig credentials, or SSH/TLS private keys accidentally printed in pod stdout/stderr.
2. **Personally Identifiable Information (PII) / Sensitive Data:**
   * Customer names, email addresses, phone numbers, payment details (credit cards/PANs), or protected health information (PHI).
3. **Raw Log Ingestion Walls:**
   * Multi-megabyte raw log dumps. Only distilled forensic signatures and concise error lines may be committed to memory.
4. **Speculative or Unverified Claims:**
   * Hallucinated hypotheses not validated by tool outputs (e.g., claiming a network failure when tool outputs show an OOM exit code 137).

### 3.3 Data Retention & Purge Protocol

* **Retention Window:** Memory Bank facts are retained for a rolling **180-day** window to support seasonal reliability reviews.
* **Right to be Forgotten & Security Purge:** If a secret or sensitive token is inadvertently ingested into Memory Bank, Platform SREs can execute an on-demand topic purge via:
  ```bash
  python -m app.app_utils.memory_config --purge-topic kubernetes_incident_findings --incident-id <INCIDENT_REF>
  ```

---

## 4. Change Management & Review Governance

All modifications to the agent codebase, configuration, infrastructure, and evaluation datasets follow strict change control.

### 4.1 CODEOWNERS Review Grid

| Component | File Paths | Required Reviewers | Minimum Approvals |
| :--- | :--- | :--- | :--- |
| **Core Agent & Logic** | `app/agent.py`, `app/k8s_forensics/*` | SRE Reliability Pod + Senior Agent Engineer | 2 Approvals |
| **Security & Gateway Policies** | `app/policy.py`, `deployment/gateway/*`, `deployment/k8s/*` | DevSecOps Lead + Cloud Security Engineer | 2 Approvals (1 from Security is mandatory) |
| **Memory Bank Configuration** | `app/app_utils/memory_config.py` | SRE Lead + Data Privacy / Compliance Officer | 2 Approvals |
| **Evaluation Scenarios & Rubrics** | `tests/eval/*` | AI Platform QA Lead + Incident Commander | 2 Approvals |
| **Cloud Infrastructure (Terraform)** | `deployment/terraform/*` | Cloud Platform DevOps Team | 2 Approvals |

### 4.2 Pull Request Gates

Before any PR can be merged into `main`:
1. **Automated Unit & Integration Tests:** `uv run pytest tests/unit tests/integration` must pass with 100% success.
2. **Code Quality & Linting:** `agents-cli lint` must report zero errors or warnings.
3. **Least-Privilege Policy Verification:** Any changes to tool sets must be verified against `app/policy.py` and `deployment/k8s/agent-spiffe-least-privilege-policy.yaml`.
4. **Eval Regression Run:** An automated evaluation (`agents-cli eval run`) must run against the baseline dataset; `agents-cli eval compare` must confirm **no regressions** in response quality or memory accuracy.
5. **Deployment Approval Gate:** Production deployments (`agents-cli deploy`) require explicit, documented human authorization from the SRE Lead. Automated bot merges or unreviewed PRs to production are strictly blocked.

---

## 5. Evaluation & Quality Pass Criteria

To ensure reliable, hallucination-free incident diagnoses during critical outages, the agent must satisfy strict evaluation criteria before any release or promotion to staging/production.

### 5.1 Evaluation Metrics & Quality Flywheel

Evaluations are configured in `tests/eval/eval_config.yaml` and executed via `agents-cli eval run`:

| Metric Name | Evaluation Method | Target Threshold | Hard Fail Condition |
| :--- | :--- | :--- | :--- |
| **`custom_response_quality`** | LLM-as-a-Judge (`tests/eval/response_quality.py`) using `gemini-3.8-flash` on a 1–5 scale for accuracy, relevance, and clarity. | **>= 4.2 / 5.0** average across suite | Any individual incident scenario scoring **< 3.0** |
| **`memory_recall_accuracy`** | Exact fact matching over historical Memory Bank facts across multi-turn sessions. | **>= 0.85 (85%)** | Recall score **< 0.70** |
| **`agent_turn_count`** | ReAct loop efficiency (tool call roundtrips). | **<= 8 turns** average | Session exceeding **15 turns** (indicates infinite tool-looping) |
| **Negative Security Compliance** | Negative test cases attempting `restart_deployment` or `get_secret`. | **100% Block Rate** | Any allowed execution of unauthorized tools |
| **Execution Duration Budget** | End-to-end investigation latency (`deployment/monitoring/investigation-budget-alert.json`). | **P99 <= 120 seconds** | Latency **> 180 seconds** |
| **Token Budget Consumption** | Cumulative prompt + completion tokens per session. | **P99 <= 50,000 tokens** | Consumption **> 75,000 tokens** |

### 5.2 Mandatory Incident Test Coverage

The test dataset (`tests/eval/datasets/`) must validate detection of:
1. `OOMKilled` (Exit code 137 with container memory limit breaches).
2. `CrashLoopBackOff` (Application initialization exceptions and database connection timeouts).
3. `ImagePullBackOff` / `ErrImagePull` (Bad image tags and registry authentication errors).
4. RBAC Permission Denials (403 Forbidden on service account actions).
5. Cluster Node Pressure (Memory/Disk pressure causing pod eviction).

---

## 6. Telemetry & Data Access Governance

Telemetry is captured via OpenTelemetry and exported directly to Google Cloud services to facilitate operational monitoring, cost tracking, and security auditing.

```
┌────────────────────────────────┐
│   Agent Telemetry Producers    │
│  (ADK Agent Runtime + Gateway) │
└───────────────┬────────────────┘
                │
    ┌───────────┼───────────┐
    ▼           ▼           ▼
Cloud Trace   BigQuery    Cloud Logging
 (Spans)    (Completions) (Sink Logs)
```

### 6.1 Telemetry Infrastructure

* **BigQuery Dataset:** `k8s_investigator_telemetry` (`deployment/terraform/single-project/telemetry.tf`)
  * Table `completions`: Partitioned log table storing prompt inputs, model outputs, and token counts.
* **Cloud Trace:** Distributed traces capturing agent reasoning steps and MCP tool execution spans.
* **Cloud Logging Sink:** `k8s-investigator-genai-logs` routing `gen_ai.client.inference.operation.details` events.
* **GCS Log Bucket:** Backup archival bucket for raw NDJSON telemetry payloads.

### 6.2 Telemetry Access Control Matrix (IAM)

Access to agent telemetry data is controlled via Google Cloud IAM based on job function and least privilege:

| Persona / Team | Assigned IAM Roles | Data Access Scope | Purpose |
| :--- | :--- | :--- | :--- |
| **Site Reliability Engineers (SRE)** | `roles/bigquery.dataViewer`<br>`roles/bigquery.jobUser`<br>`roles/cloudtrace.user`<br>`roles/logging.viewer` | Read-only access to BigQuery telemetry, traces, and metrics. | Latency analysis, debugging tool failures, cost optimization, and prompt evaluation. |
| **Security & Compliance (InfoSec)** | `roles/logging.privateLogViewer`<br>`roles/bigquery.dataViewer`<br>`roles/monitoring.viewer` | Full access to Gateway denial logs, SPIFFE auth logs, and completion datasets. | Audit trail validation, data leakage prevention, and compliance reviews. |
| **Agent Runtime Service Account (`app_sa`)** | `roles/logging.logWriter`<br>`roles/monitoring.metricWriter`<br>`roles/cloudtrace.agent`<br>`roles/telemetry.writer` | Write-only access to publish logs, traces, and metrics. | Automated runtime telemetry ingestion. |
| **Application & Product Teams** | *No direct GCP telemetry access* | Access to finalized, sanitized markdown investigation summaries via Gemini Enterprise / Slack. | Incident post-mortem review and remediation execution. |

### 6.3 Data Privacy & Retention Policy

1. **Payload Masking:** Log sinks are configured with filters to prevent capturing environment variables containing sensitive secrets.
2. **BigQuery Table Retention:** Telemetry records in `completions` are automatically expired after **90 days**.
3. **GCS Lifecycle Policy:** Raw telemetry objects transition to Nearline storage after **30 days** and are permanently deleted after **90 days**.

---

## 7. Compliance Audit & Attestation

* **Review Frequency:** This governance document and associated Gateway policies are reviewed **quarterly** by the SRE Lead and DevSecOps Lead.
* **Automated Drifts Alerts:** Cloud Monitoring alerts trigger whenever Cloud Logging detects a SPIFFE denial event (`iap.googleapis.com/mcp.toolName` denial) or budget breach (`investigation-budget-alert.json`).
