"""Unit tests for local user sync helpers."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import cast

import httpx
import pytest
from cribl_control_plane.models.security import Security

import snc_cribl_mcp.operations.users as users_module


def _resolved(name: str, base_url: str, http_client: httpx.AsyncClient) -> SimpleNamespace:
    """Return a resolved-server stand-in for user sync tests."""
    return SimpleNamespace(
        server_name=name,
        config=SimpleNamespace(base_url_str=base_url, timeout_ms=1000),
        client=SimpleNamespace(sdk_configuration=SimpleNamespace(async_client=http_client)),
        security=Security(bearer_auth="token"),
    )


def test_resolve_user_password_prefers_explicit_then_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """User password resolution should support prompt and env-driven workflows."""
    monkeypatch.setenv("TEST_USER_PASSWORD", "env-secret")

    assert users_module.resolve_user_password("test-user", password="prompt-secret") == ("prompt-secret", "prompt", [])
    assert users_module.resolve_user_password("test-user", password_env="TEST_USER_PASSWORD") == (
        "env-secret",
        "TEST_USER_PASSWORD",
        ["TEST_USER_PASSWORD"],
    )
    resolved, source, checked = users_module.resolve_user_password("test-user", target_server="golden.oak.new")

    assert resolved == "env-secret"
    assert source == "TEST_USER_PASSWORD"
    assert "SNC_CRIBL_MCP_GOLDEN_OAK_NEW_TEST_USER_PASSWORD" in checked


@pytest.mark.asyncio
async def test_sync_user_replicates_profile_and_uses_env_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replicating a missing target user should fetch source metadata and supply a password."""
    monkeypatch.setenv("TEST_USER_PASSWORD", "env-secret")
    requests: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        url = str(request.url)
        if request.method == "GET" and url == "https://source.example/api/v1/system/users/test-user":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "username": "test-user",
                            "id": "test-user",
                            "first": "Test",
                            "last": "User",
                            "email": "test.user@example.invalid",
                            "roles": ["admin"],
                        }
                    ],
                    "count": 1,
                },
            )
        if request.method == "GET" and url == "https://target.example/api/v1/system/users/test-user":
            if sum(req.method == "GET" and str(req.url) == url for req in requests) == 1:
                return httpx.Response(404, text="missing")
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "username": "test-user",
                            "id": "test-user",
                            "first": "Test",
                            "last": "User",
                            "email": "test.user@example.invalid",
                            "roles": ["admin"],
                        }
                    ],
                    "count": 1,
                },
            )
        if request.method == "POST" and url == "https://target.example/api/v1/system/users":
            payload = request.read()
            assert b"env-secret" in payload
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "username": "test-user",
                            "id": "test-user",
                            "first": "Test",
                            "last": "User",
                            "email": "test.user@example.invalid",
                            "roles": ["admin"],
                        }
                    ],
                    "count": 1,
                },
            )
        return httpx.Response(500, text=f"unexpected {request.method} {url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http_client:

        @asynccontextmanager
        async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
            yield (
                _resolved("source", "https://source.example/api/v1", http_client),
                _resolved("target", "https://target.example/api/v1", http_client),
            )

        monkeypatch.setattr(users_module, "connect_server_pair", _pair)
        result = await users_module.sync_user(
            source_server="source",
            target_server="target",
            username="test-user",
        )

    assert result["action"] == "created"
    assert result["password_source"] == "TEST_USER_PASSWORD"
    assert result["user"]["username"] == "test-user"
    assert result["validation"]["status"] == "in_sync"
    assert "password" not in result["user"]


@pytest.mark.asyncio
async def test_sync_user_requires_password_when_creating_missing_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """Creating a user without a source still requires password material."""
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(404, text="missing"))
    ) as http_client:

        @asynccontextmanager
        async def _target(_target: str) -> AsyncGenerator[SimpleNamespace]:
            yield _resolved("target", "https://target.example/api/v1", http_client)

        monkeypatch.setattr(users_module, "connect_to_server", _target)
        with pytest.raises(ValueError, match="requires a password"):
            await users_module.sync_user(
                target_server="target",
                username="test-user",
            )


def test_type_placeholder() -> None:
    """Keep pyright aware that SimpleNamespace stand-ins are intentionally dynamic."""
    assert cast("object", _resolved) is not None
