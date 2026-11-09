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

from pathlib import Path

import yaml

from app.policy import (
    ALLOWED_READONLY_TOOLS,
    DEFAULT_AGENT_SPIFFE_ID,
    DENIED_MUTATION_TOOLS,
    DENIED_SECRET_TOOLS,
    evaluate_spiffe_tool_policy,
    is_spiffe_identity,
)


def test_spiffe_identity_validation():
    assert is_spiffe_identity(DEFAULT_AGENT_SPIFFE_ID) is True
    assert is_spiffe_identity("spiffe://example.org/sa/test") is True
    assert is_spiffe_identity("invalid-identity") is False
    assert is_spiffe_identity(None) is False
    assert is_spiffe_identity("") is False


def test_allowed_readonly_tools():
    expected_tools = [
        "list_pods",
        "get_pod_logs",
        "get_pod_events",
        "get_deployment_history",
        "get_nodes_info",
        "investigate_kubernetes_logs",
    ]
    for tool in expected_tools:
        assert tool in ALLOWED_READONLY_TOOLS
        res = evaluate_spiffe_tool_policy(DEFAULT_AGENT_SPIFFE_ID, tool)
        assert res["allowed"] is True
        assert res["status"] == "ALLOWED"
        assert res["tool_name"] == tool


def test_explicitly_denied_mutations():
    assert "restart_deployment" in DENIED_MUTATION_TOOLS
    res = evaluate_spiffe_tool_policy(DEFAULT_AGENT_SPIFFE_ID, "restart_deployment")
    assert res["allowed"] is False
    assert res["status"] == "DENIED"
    assert "explicitly denied from executing mutation tool" in res["reason"]


def test_explicitly_denied_secrets():
    assert "get_secret" in DENIED_SECRET_TOOLS
    res = evaluate_spiffe_tool_policy(DEFAULT_AGENT_SPIFFE_ID, "get_secret")
    assert res["allowed"] is False
    assert res["status"] == "DENIED"
    assert "explicitly denied from accessing sensitive credential tool" in res["reason"]


def test_default_deny_for_arbitrary_tools():
    res = evaluate_spiffe_tool_policy(DEFAULT_AGENT_SPIFFE_ID, "delete_namespace")
    assert res["allowed"] is False
    assert res["status"] == "DENIED"
    assert "not in the approved read-only whitelist" in res["reason"]


def test_k8s_policy_manifest_structure():
    manifest_path = Path("deployment/k8s/agent-spiffe-least-privilege-policy.yaml")
    assert manifest_path.exists()

    with open(manifest_path, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    # Verify ClusterRole exists and only allows read-only resources
    cluster_roles = [d for d in docs if d and d.get("kind") == "ClusterRole"]
    assert len(cluster_roles) >= 1
    role = cluster_roles[0]
    rules = role["rules"]

    # Check that secrets is never in resources
    for r in rules:
        assert "secrets" not in r.get("resources", [])
        for verb in r.get("verbs", []):
            assert verb in ["get", "list", "watch"]

    # Verify ClusterRoleBinding binds to the SPIFFE ID user
    bindings = [d for d in docs if d and d.get("kind") == "ClusterRoleBinding"]
    assert len(bindings) >= 1
    binding = bindings[0]
    spiffe_subjects = [
        s for s in binding["subjects"] if s["kind"] == "User" and s["name"] == DEFAULT_AGENT_SPIFFE_ID
    ]
    assert len(spiffe_subjects) == 1

    # Verify ValidatingAdmissionPolicy denies mutations and secrets
    vap_docs = [d for d in docs if d and d.get("kind") == "ValidatingAdmissionPolicy"]
    assert len(vap_docs) >= 1
    vap = vap_docs[0]
    validations = vap["spec"]["validations"]
    expressions = [v["expression"] for v in validations]
    assert any("CREATE" in expr and "PATCH" in expr for expr in expressions)
    assert any("secrets" in expr for expr in expressions)


def test_agent_gateway_policies_structure():
    import json

    sgp_path = Path("deployment/gateway/semantic-governance-policy.json")
    assert sgp_path.exists()

    with open(sgp_path, encoding="utf-8") as f:
        sgp_data = json.load(f)

    rules = sgp_data["rules"]
    assert rules["enforcementMode"] == "ENFORCED"
    assert "list_pods" in rules["allowedTools"]
    assert "get_pod_logs" in rules["allowedTools"]
    assert "get_pod_events" in rules["allowedTools"]
    assert "get_deployment_history" in rules["allowedTools"]
    assert "get_nodes_info" in rules["allowedTools"]
    assert "investigate_kubernetes_logs" in rules["allowedTools"]
    assert "restart_deployment" in rules["deniedTools"]
    assert "get_secret" in rules["deniedTools"]

