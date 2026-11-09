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

"""Least-Privilege Authorization Policy for Agent SPIFFE Identity.

Enforces read-only tool authorization boundaries on incoming SPIFFE callers:
- Allowed: list_pods, get_pod_logs, get_pod_events, get_deployment_history,
           get_nodes_info, investigate_kubernetes_logs
- Explicitly Denied: restart_deployment (mutations), get_secret (secrets)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Standard Agent Reasoning Engine SPIFFE identity
DEFAULT_AGENT_SPIFFE_ID = (
    "spiffe://agents.global.org-310633432312.system.id.goog/"
    "resources/aiplatform/projects/1098749337818/locations/us-east1/"
    "reasoningEngines/2253300647057162240"
)

# Standard Workload Identity trust domain for agent identities
SPIFFE_AGENT_TRUST_DOMAIN = "spiffe://agents.global.org-310633432312.system.id.goog"

# Strict whitelist of permitted read-only investigation tools
ALLOWED_READONLY_TOOLS: frozenset[str] = frozenset(
    {
        "list_pods",
        "get_pod_logs",
        "get_pod_events",
        "get_deployment_history",
        "get_nodes_info",
        "investigate_kubernetes_logs",
    }
)

# Explicitly forbidden mutating tools
DENIED_MUTATION_TOOLS: frozenset[str] = frozenset(
    {
        "restart_deployment",
    }
)

# Explicitly forbidden sensitive / credential tools
DENIED_SECRET_TOOLS: frozenset[str] = frozenset(
    {
        "get_secret",
    }
)


def is_spiffe_identity(identity: str | None) -> bool:
    """Checks whether an identity string conforms to a valid SPIFFE URI."""
    if not identity or not isinstance(identity, str):
        return False
    return identity.strip().startswith("spiffe://")


def evaluate_spiffe_tool_policy(spiffe_id: str, tool_name: str) -> dict[str, Any]:
    """Evaluates whether the given SPIFFE identity is permitted to execute a tool.

    Args:
        spiffe_id: Verified caller SPIFFE identity URI.
        tool_name: The name of the tool attempting execution.

    Returns:
        A dictionary with 'allowed' (bool), 'status' ('ALLOWED' or 'DENIED'),
        'tool_name', 'spiffe_id', and 'reason'.
    """
    clean_tool = (tool_name or "").strip()
    clean_id = (spiffe_id or "").strip()

    if not is_spiffe_identity(clean_id):
        return {
            "allowed": False,
            "status": "DENIED",
            "tool_name": clean_tool,
            "spiffe_id": clean_id,
            "reason": f"Authentication failure: Identity '{clean_id}' is not a valid SPIFFE identity.",
        }

    # 1. Explicitly Denied: Mutations
    if clean_tool in DENIED_MUTATION_TOOLS:
        reason = (
            f"Policy Violation: SPIFFE identity '{clean_id}' is explicitly denied from "
            f"executing mutation tool '{clean_tool}'."
        )
        logger.warning(reason)
        return {
            "allowed": False,
            "status": "DENIED",
            "tool_name": clean_tool,
            "spiffe_id": clean_id,
            "reason": reason,
        }

    # 2. Explicitly Denied: Secrets
    if clean_tool in DENIED_SECRET_TOOLS:
        reason = (
            f"Policy Violation: SPIFFE identity '{clean_id}' is explicitly denied from "
            f"accessing sensitive credential tool '{clean_tool}'."
        )
        logger.warning(reason)
        return {
            "allowed": False,
            "status": "DENIED",
            "tool_name": clean_tool,
            "spiffe_id": clean_id,
            "reason": reason,
        }

    # 3. Whitelisted Read-Only Tools
    if clean_tool in ALLOWED_READONLY_TOOLS:
        return {
            "allowed": True,
            "status": "ALLOWED",
            "tool_name": clean_tool,
            "spiffe_id": clean_id,
            "reason": f"Tool '{clean_tool}' is an approved read-only tool for SPIFFE identity '{clean_id}'.",
        }

    # 4. Default Deny for any unlisted tool
    reason = (
        f"Policy Violation: Tool '{clean_tool}' is not in the approved read-only whitelist "
        f"for SPIFFE identity '{clean_id}'."
    )
    logger.warning(reason)
    return {
        "allowed": False,
        "status": "DENIED",
        "tool_name": clean_tool,
        "spiffe_id": clean_id,
        "reason": reason,
    }
