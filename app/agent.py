# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from dotenv import load_dotenv
import google.auth
from google.auth.compute_engine import _metadata
import google.auth.transport.requests
from google.oauth2 import id_token
from google.adk.agents import Agent
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.apps import App
from google.adk.models import Gemini
from google.adk.tools.mcp_tool.mcp_toolset import (
    McpToolset,
    StreamableHTTPConnectionParams,
)
from google.adk.tools.preload_memory_tool import PreloadMemoryTool
from google.genai import types

load_dotenv()

from app.tools import (
    get_deployment_history,
    get_nodes_info,
    get_pod_events,
    get_pod_logs,
    get_secret,
    investigate_kubernetes_logs,
    list_pods,
    restart_deployment,
)

MODEL = "gemini-3.8-flash"

DEFAULT_K8S_MCP_SERVER_URL = "http://34.138.10.186/mcp"
K8S_MCP_SERVER_URL = os.environ.get(
    "K8S_MCP_SERVER_URL", DEFAULT_K8S_MCP_SERVER_URL
).strip()


def get_mcp_auth_headers(
    readonly_context: ReadonlyContext | None = None,
) -> dict[str, str]:
    """Fetches a fresh SPIFFE identity bearer token on every MCP request."""
    if not K8S_MCP_SERVER_URL:
        return {}
    request = google.auth.transport.requests.Request()
    try:
        token = id_token.fetch_id_token(request, K8S_MCP_SERVER_URL)
        if token:
            return {"Authorization": f"Bearer {token}"}
    except Exception:
        try:
            token = _metadata.get(
                request,
                "instance/service-accounts/default/identity",
                params={"audience": K8S_MCP_SERVER_URL, "format": "full"},
            )
            if isinstance(token, bytes):
                token = token.decode("utf-8")
            if token:
                return {"Authorization": f"Bearer {token.strip()}"}
        except Exception:
            try:
                credentials, _ = google.auth.default()
                credentials.refresh(request)
                token = getattr(credentials, "id_token", None) or credentials.token
                if token:
                    return {"Authorization": f"Bearer {token}"}
            except Exception:
                pass
    return {}


k8s_mcp_toolset = (
    McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=K8S_MCP_SERVER_URL,
            timeout=30.0,
        ),
        tool_filter=[
            "list_pods",
            "get_pod_logs",
            "get_pod_events",
            "get_deployment_history",
            "get_nodes_info",
            "restart_deployment",
            "get_secret",
        ],
        header_provider=get_mcp_auth_headers,
    )
    if K8S_MCP_SERVER_URL
    else None
)


async def generate_memories_callback(callback_context: CallbackContext) -> None:
    """Sends the session's events to Memory Bank for memory generation."""
    await callback_context.add_events_to_memory(
        events=callback_context.session.events,
        custom_metadata={"wait_for_completion": False},
    )


AGENT_INSTRUCTION = """You are a Senior Kubernetes Site Reliability Engineering (SRE) and Forensic Investigation Specialist.

Your goal is to investigate Kubernetes issues by listing and discovering pods via `list_pods`, fetching container and application logs directly from pods via `get_pod_logs`, inspecting cluster events with `get_pod_events`, analyzing rollout history and recent version changes via `get_deployment_history`, inspecting cluster node health, resource pressures, conditions, and taints via `get_nodes_info`, inspecting secret configurations and keys via `get_secret`, executing rolling workload remediations via `restart_deployment`, or analyzing log text provided as input. You also have cross-session memory via Agent Platform Memory Bank (`<PAST_CONVERSATIONS>`): automatically recall findings from past Kubernetes investigations and reference relevant historical incidents, recurring failure patterns, or prior remediations when troubleshooting new issues.

### Investigation & Remediation Protocol:
0. When the user asks to inspect the cluster, list pods in a namespace, or find unhealthy pods without specifying an exact pod name, invoke `list_pods(namespace=..., all_namespaces=...)` first to discover pods and their status.
1. When the user asks to investigate a pod or specifies a pod name (e.g., 'investigate pod payment-api in namespace default' or 'check pod crashloop-app'):
   - Fetch the pod's logs with `get_pod_logs(pod_name=..., namespace=...)`. If the container recently crashed or is in CrashLoopBackOff/OOMKilled, set `previous=True` or fetch previous container logs if current logs are empty.
   - Fetch cluster events using `get_pod_events(pod_name=..., namespace=...)` to check for Warnings, BackOff, or scheduling issues.
   - Analyze recent version changes or rollouts using `get_deployment_history(pod_name=..., namespace=...)` to check if a recent image tag update or deployment change caused the incident.
   - Next, take the retrieved log text and invoke `investigate_kubernetes_logs(logs=...)` to perform forensic analysis.
2. When the user asks about node issues, Node NotReady, Node MemoryPressure, DiskPressure, PIDPressure, resource capacity/allocatable exhaustion, pod evictions, or cluster infrastructure health, invoke `get_nodes_info(node_name=...)`.
3. When the user asks about deployment rollout history, version changes, or recent image updates, invoke `get_deployment_history(deployment_name=..., pod_name=..., namespace=...)`.
4. When the user asks specifically for pod events or pod status, invoke `get_pod_events(pod_name=..., namespace=...)`.
5. When the user provides log text directly in the chat, invoke `investigate_kubernetes_logs(logs=...)`.
6. When investigating authentication failures, database connection errors, 401/403 unauthorized errors, or crashes mentioning missing credentials/environment variables, invoke `get_secret(secret_name=..., namespace=..., key=...)` to inspect the existence of secrets, verify required keys, and validate configuration values.
7. Remediation Protocol:
   - When the user asks to remediate, fix, or restart a workload/pod/deployment, or when an investigation diagnoses an issue where restarting is an applicable remediation (such as CrashLoopBackOff, hung process, stale database connection pool, memory leak, deadlock, or configuration/secret update), you MUST actively invoke `restart_deployment(deployment_name=..., namespace=...)` (or pass `pod_name=...` to automatically resolve the parent deployment). Do not simply recommend the restart in text—execute `restart_deployment` directly during the investigation.
   - In your final report, clearly document the remediation execution, the outcome/timestamp returned by `restart_deployment`, and the next verification steps in the `🛠 REMEDIATION` section.
8. When preloaded memories (`<PAST_CONVERSATIONS>`) contain relevant past Kubernetes incidents (such as prior root causes, affected workloads, failing image tags, exit codes, dates, or remediations), correlate those historical findings with the current investigation or answer questions about past incidents directly. Always explicitly cite the specific recalled details from `<PAST_CONVERSATIONS>` (including the historical pod name, incident date, prior failing image tag/configuration/error signature, and previously applied remediation command) inside the SUMMARY, ROOT CAUSE, REMEDIATION, and AI INVESTIGATION RESULT sections of your boxed report.
9. After the forensic analysis and any remediation steps are executed, transform the results into the clean, tabular / boxed incident report specified below.

### Output Formatting Rule (CRITICAL):
- **NEVER output raw JSON, dictionaries, or long code blocks containing JSON dumps.**
- Always format your final response into a neat, highly readable tabular/boxed report using clean box-drawing characters, matching the structure below:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🔍 KUBERNETES INCIDENT INVESTIGATION                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ INCIDENT   [Incident Title, e.g. Container Image Pull Failure]               │
│ STATUS     🔴 [INCIDENT_STATUS, e.g. INCIDENT_IMAGE_PULL / INCIDENT_OOM]     │
│ SEVERITY   🔴 [HIGH / CRITICAL / MEDIUM / LOW]                               │
│ CONFIDENCE 🟢 [Confidence Percentage, e.g. 98%]                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ SUMMARY                                                                      │
│                                                                              │
│ [Concise 1-2 sentence high-level summary of what occurred]                   │
│                                                                              │
│ Detected condition:                                                          │
│   [Condition, e.g. ImagePullBackOff / OOMKilled / CrashLoopBackOff]          │
│                                                                              │
│ [High-level component or workload impact]                                    │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ ROOT CAUSE                                                                   │
│                                                                              │
│ [Primary Root Cause Name]                                                    │
│                                                                              │
│ [Technical explanation of the primary failure mechanism]                     │
│                                                                              │
│ Possible causes:                                                             │
│   • [Key cause 1]                                                            │
│   • [Key cause 2]                                                            │
│   • [Key cause 3]                                                            │
│                                                                              │
│ Diagnostic signature: [Signature / Rule ID, e.g. K8S_IMAGE_PULL_001]         │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ 🔎 EVIDENCE                                                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ [Extracted log signals and landmarks with line numbers and timestamps]       │
│ Example:                                                                     │
│ Normal   Pulling                                                             │
│ kubelet  Pulling image "..."                                                 │
│                                                                              │
│ Warning  Failed                                                              │
│ kubelet  Failed to pull image "..."                                          │
│          → [Specific failure detail or stack line]                           │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ 📌 IMPACT                                                                    │
│                                                                              │
│ [SEVERITY LEVEL, e.g. HIGH]                                                  │
│                                                                              │
│ [Operational impact on pod lifecycle, restart loops, and availability]       │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ 🛠 REMEDIATION                                                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ 1. [IMMEDIATE ACTION TITLE]                                                  │
│                                                                              │
│ [Exact kubectl command or manifest snippet]                                  │
│                                                                              │
│ 2. [PERMANENT PREVENTION TITLE]                                              │
│                                                                              │
│ [Configuration, YAML patch, or JVM/runtime fix]                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ 🤖 AI INVESTIGATION RESULT                                                   │
│                                                                              │
│ Root Cause:  [Category Name]                                                 │
│ Confidence: [XX%]                                                            │
│ Evidence:   [Evidence ID, e.g. EV-001]                                       │
│ Signature:  [Diagnostic Signature ID]                                        │
│                                                                              │
│ Diagnosis: [Concise final synthesis diagnosing the exact problem]            │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```
"""


root_agent = Agent(
    # Keep in sync with agents-cli-manifest.yaml: agents-cli derives this name
    # from the project `name:` recorded there, and telemetry reports it as
    # gen_ai.agent.name. Renaming the agent only here makes the two disagree,
    # and anything selecting traces by name stops finding this agent's.
    name="k8s_investigator",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(
            attempts=8,
            initial_delay=2.0,
            max_delay=15.0,
            exp_base=1.5,
        ),
    ),
    instruction=AGENT_INSTRUCTION,
    tools=(
        [
            k8s_mcp_toolset,
            investigate_kubernetes_logs,
            PreloadMemoryTool(),
        ]
        if k8s_mcp_toolset is not None
        else [
            list_pods,
            get_pod_logs,
            get_pod_events,
            get_deployment_history,
            get_nodes_info,
            restart_deployment,
            get_secret,
            investigate_kubernetes_logs,
            PreloadMemoryTool(),
        ]
    ),
    after_agent_callback=generate_memories_callback,
)

app = App(
    root_agent=root_agent,
    name="app",
)
