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

"""Unit tests for Agent Platform Memory Bank configuration and wiring."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from google.adk.agents.run_config import RunConfig, StreamingMode
from google.adk.cli.service_registry import get_service_registry
from google.adk.memory import InMemoryMemoryService
from google.adk.memory.vertex_ai_memory_bank_service import VertexAiMemoryBankService
from google.adk.models.google_llm import Gemini
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.preload_memory_tool import PreloadMemoryTool
from google.genai import types

from app.agent import generate_memories_callback, root_agent
from app.app_utils import services
from app.app_utils.memory_config import context_spec, memory_bank_config


def test_memory_bank_config_topics() -> None:
    """Verify memory_bank_config defines the custom Kubernetes topic and managed topics."""
    assert context_spec.memory_bank_config == memory_bank_config
    assert memory_bank_config.customization_configs
    topics = memory_bank_config.customization_configs[0].memory_topics
    assert topics is not None

    custom_labels = [
        t.custom_memory_topic.label
        for t in topics
        if t.custom_memory_topic is not None
    ]
    assert "kubernetes_incident_findings" in custom_labels

    managed_enums = [
        t.managed_memory_topic.managed_topic_enum.value
        for t in topics
        if t.managed_memory_topic is not None
        and t.managed_memory_topic.managed_topic_enum is not None
    ]
    assert "KEY_CONVERSATION_DETAILS" in managed_enums
    assert "EXPLICIT_INSTRUCTIONS" in managed_enums
    assert "USER_PREFERENCES" in managed_enums
    assert "USER_PERSONAL_INFO" in managed_enums


def test_generate_memories_callback_calls_add_events_to_memory() -> None:
    """Verify generate_memories_callback delegates to callback_context.add_events_to_memory."""
    mock_ctx = MagicMock()
    mock_ctx.session.events = ["event-1"]
    mock_ctx.add_events_to_memory = AsyncMock()
    asyncio.run(generate_memories_callback(mock_ctx))
    mock_ctx.add_events_to_memory.assert_awaited_once_with(
        events=["event-1"],
        custom_metadata={"wait_for_completion": False},
    )


def test_services_get_memory_service_local_and_agent_engine(monkeypatch) -> None:
    """Verify get_memory_service returns InMemoryMemoryService locally and VertexAiMemoryBankService on Agent Engine."""
    services.get_memory_service.cache_clear()
    monkeypatch.delenv("MEMORY_SERVICE_URI", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_AGENT_ENGINE_ID", raising=False)

    local_svc = services.get_memory_service()
    assert isinstance(local_svc, InMemoryMemoryService)

    registry_svc = get_service_registry().create_memory_service(
        services.MEMORY_SERVICE_URI
    )
    assert registry_svc is local_svc

    services.get_memory_service.cache_clear()
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")
    monkeypatch.setenv("GOOGLE_CLOUD_AGENT_ENGINE_LOCATION", "us-east1")
    monkeypatch.setenv("GOOGLE_CLOUD_AGENT_ENGINE_ID", "1234567890")

    vertex_svc = services.get_memory_service()
    assert isinstance(vertex_svc, VertexAiMemoryBankService)
    services.get_memory_service.cache_clear()


def test_cross_session_incident_memory_persistence_and_recall() -> None:
    """Verify findings from Session 1 are saved to memory and preloaded into Session 2."""
    captured_requests = []

    async def _fake_generate_content(self, llm_request, stream=False):
        captured_requests.append(llm_request)
        yield LlmResponse(
            content=types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text=(
                            "Investigation finding: Pod payment-api in namespace default "
                            "crashed with OOMKilled (Exit Code 137) due to JVM heap exhaustion."
                        )
                    )
                ],
            ),
            turn_complete=True,
        )

    session_service = InMemorySessionService()
    memory_service = InMemoryMemoryService()

    runner = Runner(
        agent=root_agent,
        session_service=session_service,
        memory_service=memory_service,
        app_name="test_k8s_memory",
    )

    with (
        patch.object(Gemini, "generate_content_async", _fake_generate_content),
        patch.object(root_agent, "tools", [PreloadMemoryTool()]),
    ):
        # Session 1: Investigate payment-api incident -> after_agent_callback saves to memory
        session_1 = session_service.create_session_sync(
            user_id="sre_user", app_name="test_k8s_memory"
        )
        list(
            runner.run(
                new_message=types.Content(
                    role="user",
                    parts=[
                        types.Part.from_text(
                            text="Investigate payment-api OOMKilled incident in namespace default"
                        )
                    ],
                ),
                user_id="sre_user",
                session_id=session_1.id,
                run_config=RunConfig(streaming_mode=StreamingMode.SSE),
            )
        )

        # Session 2: New session troubleshooting payment-api -> PreloadMemoryTool injects past findings
        session_2 = session_service.create_session_sync(
            user_id="sre_user", app_name="test_k8s_memory"
        )
        list(
            runner.run(
                new_message=types.Content(
                    role="user",
                    parts=[
                        types.Part.from_text(
                            text="What happened to payment-api in past incidents?"
                        )
                    ],
                ),
                user_id="sre_user",
                session_id=session_2.id,
                run_config=RunConfig(streaming_mode=StreamingMode.SSE),
            )
        )

    assert len(captured_requests) == 2
    second_request = captured_requests[1]
    all_parts_text = "\n".join(
        part.text
        for content in second_request.contents
        if content.parts
        for part in content.parts
        if part.text
    )
    assert "<PAST_CONVERSATIONS>" in all_parts_text
    assert "OOMKilled" in all_parts_text
