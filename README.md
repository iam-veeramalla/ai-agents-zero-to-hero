# Kubernetes Log Investigation Agent

A Kubernetes Investigation Agent built in Python using Google **Agent Development Kit (ADK)** and **agents-cli**.

The agent accepts container and application logs as input, performs forensic investigation, identifies root causes, reconstructs an incident timeline, and delivers a detailed analysis backed by concrete **supporting evidence** (exact line numbers, timestamps, log excerpts, and error signals).

---

## Architecture & Features

- **Google ADK & agents-cli Native**: Defined in `app/agent.py` as an ADK `Agent` with tools in `app/tools.py`.
- **Pure Input-Based Analysis**: Ingests logs directly from prompt text, piped stdin, or log files on disk (no live cluster connection required).
- **Multi-Format Log Parser**:
  - Kubernetes CRI format (`2026-09-22T... stdout F ...`)
  - Container / Application JSON logs (`{"level":"error","msg":"..."}`)
  - Logfmt (`level=error msg="..." time="..."`)
  - Syslog & ISO-8601 timestamps
  - Multi-line stack trace stitching (Python tracebacks, Java JVM exceptions, Go panics)
- **Forensic Diagnostic Engine & Knowledge Base**:
  - **OOMKilled & Memory Leaks**: Exit code 137, cgroup limits, Java heap exhaustion (`OutOfMemoryError`).
  - **CrashLoopBackOff & Panics**: Unhandled exceptions, SIGSEGV, runtime panics, exit codes 1 and 2.
  - **Network & DNS Failures**: CoreDNS lookup failure (`no such host`), connect timeouts, Envoy 503 upstream errors.
  - **Probe Failures**: Liveness/Readiness probe failure (HTTP statuscode 500/502/503).
  - **RBAC Authorization Denials**: 403 Forbidden on ServiceAccounts and Kubernetes API resources.
  - **Database & Dependency Exhaustion**: Connection timeouts, connection pool exhaustion, connection refused.
  - **ImagePullBackOff & Config/Secret Issues**: Authentication errors, manifest unknown, missing ConfigMaps or Secrets.
- **Detailed Output with Supporting Evidence**:
  - **Executive Summary & Severity**: (CRITICAL, HIGH, MEDIUM, LOW)
  - **Root Cause Analysis (RCA)**: Underlying causes distinguished from downstream symptoms.
  - **Supporting Evidence**: Evidence ID, line numbers, timestamps, log excerpts, and forensic significance.
  - **Chronological Incident Timeline**: Milestones from baseline operation to warning signs and crash.
  - **Actionable Remediation**: Specific manifest patches (YAML), JVM ergonomics, and troubleshooting actions.

---

## Quick Start

### 1. Install Dependencies
```bash
agents-cli install
# or
uv sync
```

### 2. Run with `agents-cli`
Run one-off prompts with the ADK agent:
```bash
# Investigate a log file
agents-cli run "Please investigate the log file samples/oom_killed.log and provide a detailed analysis with supporting evidence"

# Or paste logs directly into the prompt
agents-cli run "Investigate these logs:
2026-09-22T10:15:22.502Z stderr F java.lang.OutOfMemoryError: Java heap space
2026-09-22T10:15:24.019Z stderr F cgroup out of memory: Killed process 42 (java)
2026-09-22T10:15:24.120Z stderr F Container terminated with exit code 137 (OOMKilled)"
```

### 3. Run with Interactive Playground
Launch the web UI playground for interactive exploration:
```bash
agents-cli playground
```

### 4. Run via Standalone CLI (`main.py`)
You can also run the investigation CLI directly from terminal without requiring API keys:

```bash
# Inspect a log file with Rich terminal tables
uv run python main.py -f samples/oom_killed.log

# Pipe logs via stdin
cat samples/crashloop_db_timeout.log | uv run python main.py

# Generate Markdown report
uv run python main.py -f samples/dns_lookup_failure.log --format markdown

# Generate structured JSON for CI/CD pipelines
uv run python main.py -f samples/rbac_forbidden.log --format json

# Save report to a file
uv run python main.py -f samples/oom_killed.log --format markdown -o report.md
```

---

## Sample Scenarios Included

| Scenario | Sample File | Detected Issue | Severity |
| :--- | :--- | :--- | :--- |
| **OOMKilled** | [`samples/oom_killed.log`](file:///Users/abhishekveeramalla/Downloads/k8s-investigation-agent/samples/oom_killed.log) | Java Heap Space Exhaustion & Linux cgroup OOM termination (Exit Code 137) | **CRITICAL** |
| **CrashLoop & DB Timeout** | [`samples/crashloop_db_timeout.log`](file:///Users/abhishekveeramalla/Downloads/k8s-investigation-agent/samples/crashloop_db_timeout.log) | PostgreSQL connection refusal, Readiness probe 500, CrashLoopBackOff | **CRITICAL** |
| **DNS Resolution Failure** | [`samples/dns_lookup_failure.log`](file:///Users/abhishekveeramalla/Downloads/k8s-investigation-agent/samples/dns_lookup_failure.log) | CoreDNS lookup failure (`no such host`) leading to Envoy 503 upstream error | **HIGH** |
| **RBAC Authorization Denied**| [`samples/rbac_forbidden.log`](file:///Users/abhishekveeramalla/Downloads/k8s-investigation-agent/samples/rbac_forbidden.log) | ServiceAccount lacking RBAC Role permissions (403 Forbidden on Secrets) | **HIGH** |

---

## Project Structure

```text
k8s-investigation-agent/
├── app/
│   ├── __init__.py
│   ├── agent.py               # ADK Root Agent (k8s_investigator) with Gemini 3.8 Flash
│   ├── tools.py               # ADK Tools (investigate_kubernetes_logs, investigate_log_file)
│   └── k8s_forensics/         # Core Forensic Diagnostic Engine
│       ├── __init__.py
│       ├── models.py          # Pydantic models (LogEntry, EvidenceItem, Timeline, Report)
│       ├── parser.py          # Multi-format parser (CRI, JSON, logfmt, stack traces)
│       ├── rules.py           # K8s failure diagnostic rules & signature catalog
│       └── analyzer.py        # Evidence extraction, anomaly detection & timeline builder
├── samples/                   # Real-world Kubernetes incident log samples
├── tests/
│   └── unit/                  # Unit tests for parser, analyzer, and tools
├── main.py                    # Standalone CLI runner with Rich terminal, Markdown, and JSON
├── agents-cli-manifest.yaml   # agents-cli project configuration
├── pyproject.toml             # Project dependencies and configurations
└── README.md
```
