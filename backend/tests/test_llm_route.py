"""
Tests for backend/routes/llm.py

Covers:
- Route accepts valid request and returns NDJSON stream
- context-preview returns deterministic output
- Validation errors on missing/bad messages
- _to_domain conversion correctness
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import pytest
from unittest.mock import patch, MagicMock

from routes.llm import _to_domain, ChatRequestIn, MessageIn


class TestToDomain:
    def _base_request(self, **kw):
        defaults = {
            "messages": [MessageIn(role="user", content="What is happening?")],
        }
        defaults.update(kw)
        return ChatRequestIn(**defaults)

    def test_messages_converted(self):
        req_in = self._base_request()
        domain = _to_domain(req_in)
        assert len(domain.messages) == 1
        assert domain.messages[0].role == "user"
        assert domain.messages[0].content == "What is happening?"

    def test_scope_defaults(self):
        req_in = self._base_request()
        domain = _to_domain(req_in)
        assert domain.scope.mode == "full_capture"
        assert domain.scope.entity_type is None
        assert domain.scope.entity_id is None

    def test_provider_kind_passed(self):
        from routes.llm import ProviderIn
        req_in = self._base_request(provider=ProviderIn(kind="openai", model="gpt-4o-mini"))
        domain = _to_domain(req_in)
        assert domain.provider.kind == "openai"
        assert domain.provider.model == "gpt-4o-mini"

    def test_selection_node_ids_passed(self):
        from routes.llm import SelectionIn
        req_in = self._base_request(
            selection=SelectionIn(node_ids=["10.0.0.5", "10.0.0.6"])
        )
        domain = _to_domain(req_in)
        assert domain.selection.node_ids == ["10.0.0.5", "10.0.0.6"]

    def test_viewer_state_passed(self):
        from routes.llm import ViewerStateIn
        req_in = self._base_request(
            viewer_state=ViewerStateIn(time_start=1000.0, time_end=2000.0, search="10.0.0.5")
        )
        domain = _to_domain(req_in)
        assert domain.viewer_state.time_start == 1000.0
        assert domain.viewer_state.time_end == 2000.0
        assert domain.viewer_state.search == "10.0.0.5"


class TestContextPreviewEndpoint:
    """
    Tests the context-preview endpoint returns deterministic output.
    Uses FastAPI's TestClient.
    """

    def _get_client(self):
        try:
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            from routes.llm import router
            app = FastAPI()
            app.include_router(router)
            return TestClient(app)
        except ImportError:
            pytest.skip("FastAPI testclient not available")

    def test_context_preview_returns_tags_and_packet(self):
        client = self._get_client()

        # Mock the service function so it doesn't need a real store
        fake_result = {
            "tags": ["broad_overview"],
            "context_packet": {
                "scope": {"mode": "full_capture", "question_tags": ["broad_overview"]},
                "capture_meta": {"loaded": False},
                "overview": {"note": "No capture loaded."},
                "retrieval_manifest": {"already_retrieved": [], "available_for_expansion": []},
                "limitations": {"items": ["No capture is currently loaded."]},
            }
        }

        with patch('routes.llm.build_context_only', return_value=fake_result):
            resp = client.post(
                "/api/llm/context-preview",
                json={
                    "messages": [{"role": "user", "content": "What is happening?"}],
                }
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "tags" in data
        assert "context_packet" in data
        assert data["tags"] == ["broad_overview"]

    def test_context_preview_rejects_empty_messages(self):
        client = self._get_client()
        resp = client.post("/api/llm/context-preview", json={"messages": []})
        assert resp.status_code == 400

    def test_context_preview_rejects_no_user_message(self):
        client = self._get_client()
        resp = client.post(
            "/api/llm/context-preview",
            json={"messages": [{"role": "system", "content": "test"}]}
        )
        assert resp.status_code == 400


class TestChatEndpoint:
    def _get_client(self):
        try:
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            from routes.llm import router
            app = FastAPI()
            app.include_router(router)
            return TestClient(app)
        except ImportError:
            pytest.skip("FastAPI testclient not available")

    def _fake_stream_events(self):
        """Yield a complete minimal stream."""
        yield {"type": "meta", "request_id": "test_001", "provider": "ollama", "model": "test"}
        yield {"type": "context", "scope_mode": "full_capture", "snapshot_id": "snap_001", "surfaces": [], "tags": ["broad_overview"]}
        yield {"type": "delta", "text": "## Answer\nThis is a test answer."}
        yield {"type": "final", "snapshot_id": "snap_001", "answer_markdown": "## Answer\nThis is a test answer.", "usage": {"input_tokens": 0, "output_tokens": 0}}

    def test_chat_streams_ndjson(self):
        client = self._get_client()

        with patch('routes.llm.stream_chat', return_value=self._fake_stream_events()):
            resp = client.post(
                "/api/llm/chat",
                json={
                    "messages": [{"role": "user", "content": "What is happening?"}],
                }
            )

        assert resp.status_code == 200
        # Parse NDJSON lines
        lines = [l for l in resp.text.strip().split('\n') if l.strip()]
        events = [json.loads(l) for l in lines]
        types = [e["type"] for e in events]
        assert "meta" in types
        assert "context" in types
        assert "delta" in types
        assert "final" in types

    def test_chat_rejects_empty_messages(self):
        client = self._get_client()
        resp = client.post("/api/llm/chat", json={"messages": []})
        assert resp.status_code == 400
