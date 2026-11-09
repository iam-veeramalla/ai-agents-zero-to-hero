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

"""Shared Agent Platform Memory Bank configuration for Kubernetes incident investigations."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentplatform._genai.types import (
    AgentEngineConfig,
    ManagedTopicEnum,
    ReasoningEngineContextSpec,
)
from agentplatform._genai.types import (
    MemoryBankCustomizationConfig as CustomizationConfig,
)
from agentplatform._genai.types import (
    MemoryBankCustomizationConfigMemoryTopic as MemoryTopic,
)
from agentplatform._genai.types import (
    MemoryBankCustomizationConfigMemoryTopicCustomMemoryTopic as CustomMemoryTopic,
)
from agentplatform._genai.types import (
    MemoryBankCustomizationConfigMemoryTopicManagedMemoryTopic as ManagedMemoryTopic,
)
from agentplatform._genai.types import (
    ReasoningEngineContextSpecMemoryBankConfig as MemoryBankConfig,
)

# Define which memory topics the Agent Platform Memory Bank should extract and
# persist across Kubernetes investigation sessions.
memory_bank_config = MemoryBankConfig(
    customization_configs=[
        CustomizationConfig(
            memory_topics=[
                MemoryTopic(
                    custom_memory_topic=CustomMemoryTopic(
                        label="kubernetes_incident_findings",
                        description=(
                            "Findings from Kubernetes incident investigations, including "
                            "affected pods, deployments, namespaces, or nodes, root causes "
                            "(e.g., OOMKilled, CrashLoopBackOff, ImagePullBackOff, bad image "
                            "tag rollouts, node resource pressure), diagnostic signatures, "
                            "key log evidence, and remediation steps."
                        ),
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.KEY_CONVERSATION_DETAILS,
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.EXPLICIT_INSTRUCTIONS,
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.USER_PREFERENCES,
                    ),
                ),
                MemoryTopic(
                    managed_memory_topic=ManagedMemoryTopic(
                        managed_topic_enum=ManagedTopicEnum.USER_PERSONAL_INFO,
                    ),
                ),
            ],
        ),
    ],
)

context_spec = ReasoningEngineContextSpec(
    memory_bank_config=memory_bank_config,
)


def apply_memory_bank_config(
    agent_engine_name: str | None = None,
    project: str | None = None,
    location: str | None = None,
) -> str:
    """Apply ``memory_bank_config`` to an existing Agent Engine instance."""
    import agentplatform

    if not agent_engine_name:
        agent_engine_name = os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID")
    if not agent_engine_name:
        metadata_path = Path(__file__).resolve().parents[2] / "deployment_metadata.json"
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            agent_engine_name = metadata.get("remote_agent_runtime_id")

    if not agent_engine_name:
        raise ValueError(
            "No Agent Engine resource name provided or found in deployment_metadata.json."
        )

    parts = agent_engine_name.split("/")
    if len(parts) >= 4 and parts[0] == "projects" and parts[2] == "locations":
        project = project or parts[1]
        location = location or parts[3]

    project = project or os.environ.get("GOOGLE_CLOUD_PROJECT")
    location = (
        location
        or os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_LOCATION")
        or os.environ.get("GOOGLE_CLOUD_LOCATION", "us-east1")
    )

    client = agentplatform.Client(project=project, location=location)
    client.agent_engines.update(
        name=agent_engine_name,
        config=AgentEngineConfig(context_spec=context_spec),
    )
    return agent_engine_name


if __name__ == "__main__":
    updated_name = apply_memory_bank_config()
    print(f"Applied Memory Bank context_spec to: {updated_name}")

