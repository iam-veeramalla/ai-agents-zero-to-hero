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

package k8s.agent.authorization

import future.keywords.in

default allow := false

# Approved agent SPIFFE trust domain prefix
spiffe_trust_domain := "spiffe://agents.global.org-310633432312.system.id.goog/"

# Target agent Reasoning Engine SPIFFE identity
agent_spiffe_id := "spiffe://agents.global.org-310633432312.system.id.goog/resources/aiplatform/projects/1098749337818/locations/us-east1/reasoningEngines/2253300647057162240"

# Whitelist of approved read-only tools
allowed_readonly_tools := {
    "list_pods",
    "get_pod_logs",
    "get_pod_events",
    "get_deployment_history",
    "get_nodes_info",
    "investigate_kubernetes_logs",
}

# Blacklist of explicitly denied mutating tools
denied_mutation_tools := {
    "restart_deployment",
}

# Blacklist of explicitly denied sensitive/secret tools
denied_secret_tools := {
    "get_secret",
}

# Check if the incoming caller is an authorized SPIFFE identity
is_agent_spiffe_identity {
    startswith(input.spiffe_id, spiffe_trust_domain)
}

# Tool-Level Authorization: Allow rule
allow {
    is_agent_spiffe_identity
    input.tool_name in allowed_readonly_tools
    not deny[reason]
}

# Explicit Deny: Mutations (e.g., restart_deployment)
deny[reason] {
    is_agent_spiffe_identity
    input.tool_name in denied_mutation_tools
    reason := sprintf("Explicit Deny: SPIFFE identity '%v' attempted mutating tool '%v' (mutations are forbidden).", [input.spiffe_id, input.tool_name])
}

# Explicit Deny: Secrets (e.g., get_secret)
deny[reason] {
    is_agent_spiffe_identity
    input.tool_name in denied_secret_tools
    reason := sprintf("Explicit Deny: SPIFFE identity '%v' attempted accessing secret tool '%v' (secrets access is forbidden).", [input.spiffe_id, input.tool_name])
}

# Explicit Deny: Unrecognized or non-whitelisted tools
deny[reason] {
    is_agent_spiffe_identity
    not input.tool_name in allowed_readonly_tools
    not input.tool_name in denied_mutation_tools
    not input.tool_name in denied_secret_tools
    reason := sprintf("Explicit Deny: Tool '%v' is not in the read-only whitelist for SPIFFE identity '%v'.", [input.tool_name, input.spiffe_id])
}
