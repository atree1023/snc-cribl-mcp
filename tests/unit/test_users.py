"""Unit tests for local user sync helpers."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

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


def test_public_user_payload_strips_common_secret_field_names() -> None:
    """User responses should avoid known credential-bearing fields."""
    assert users_module._public_user_payload(
        {
            "username": "test-user",
            "password": "hidden",
            "apiKey": "hidden",
            "sshPrivateKey": "hidden",
            "roles": ["admin"],
        }
    ) == {"username": "test-user", "roles": ["admin"]}


def test_extract_single_user_handles_empty_malformed_and_non_object_items() -> None:
    """Counted user responses should return None for malformed item shapes."""
    assert users_module._extract_single_user({"items": []}) is None
    assert users_module._extract_single_user({"items": "not-a-list"}) is None
    assert users_module._extract_single_user({"items": ["not-an-object"]}) is None


@pytest.mark.asyncio
async def test_user_request_json_requires_httpx_client_and_uses_fresh_security() -> None:
    """Direct user API calls should validate the SDK HTTP client and refresh security when possible."""
    bad_resolved = SimpleNamespace(
        config=SimpleNamespace(base_url_str="https://target.example/api/v1", timeout_ms=1000),
        client=SimpleNamespace(sdk_configuration=SimpleNamespace(async_client=object())),
        security=Security(bearer_auth="old-token"),
    )
    with pytest.raises(TypeError, match=r"does not expose an httpx\.AsyncClient"):
        await users_module._request_user_json(
            cast("users_module.ResolvedControlPlane", bad_resolved),
            method="GET",
            url="https://target.example/api/v1/system/users/test-user",
        )

    requests: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"items": [{"username": "test-user"}], "count": 1})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http_client:
        resolved = _resolved("target", "https://target.example/api/v1", http_client)
        resolved.get_security = AsyncMock(return_value=Security(bearer_auth="fresh-token"))

        result = await users_module._request_user_json(
            cast("users_module.ResolvedControlPlane", resolved),
            method="GET",
            url="https://target.example/api/v1/system/users/test-user",
        )

    assert result["items"] == [{"username": "test-user"}]
    assert requests[0].headers["Authorization"] == "Bearer fresh-token"
    resolved.get_security.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_user_reraises_non_404_http_errors() -> None:
    """Only 404 local-user lookups should be translated to None."""
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(500, text="boom"))
    ) as http_client:
        resolved = _resolved("target", "https://target.example/api/v1", http_client)

        with pytest.raises(httpx.HTTPStatusError):
            await users_module._get_user(cast("users_module.ResolvedControlPlane", resolved), "test-user")


def test_build_user_payload_applies_optional_overrides_and_strips_secrets() -> None:
    """User payload construction should preserve profile overrides without copying secret fields."""
    payload = users_module._build_user_payload(
        username="test-user",
        source_user={"username": "old", "password": "hidden", "apiKey": "hidden", "roles": ["reader"]},
        password="new-secret",
        first="Test",
        last="User",
        email="test.user@example.invalid",
        roles=["admin"],
        disabled=True,
    )

    assert payload == {
        "username": "test-user",
        "id": "test-user",
        "password": "new-secret",
        "first": "Test",
        "last": "User",
        "email": "test.user@example.invalid",
        "roles": ["admin"],
        "disabled": True,
    }


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


@pytest.mark.asyncio
async def test_sync_user_preserves_existing_target_fields_when_patching_without_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Password rotation should patch from the existing target profile plus overrides."""
    requests: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        url = str(request.url)
        existing_user = {
            "username": "test-user",
            "id": "test-user",
            "first": "Existing",
            "last": "User",
            "email": "existing@example.invalid",
            "roles": ["admin"],
            "disabled": False,
        }
        updated_user = {**existing_user, "disabled": True}
        if request.method == "GET" and url == "https://target.example/api/v1/system/users/test-user":
            if sum(req.method == "GET" and str(req.url) == url for req in requests) == 1:
                return httpx.Response(200, json={"items": [existing_user], "count": 1})
            return httpx.Response(200, json={"items": [updated_user], "count": 1})
        if request.method == "PATCH" and url == "https://target.example/api/v1/system/users/test-user":
            payload = json.loads(request.content)
            assert payload["password"] == "new-secret"
            assert payload["roles"] == ["admin"]
            assert payload["first"] == "Existing"
            assert payload["disabled"] is True
            return httpx.Response(200, json={"items": [updated_user], "count": 1})
        return httpx.Response(500, text=f"unexpected {request.method} {url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http_client:

        @asynccontextmanager
        async def _target(_target: str) -> AsyncGenerator[SimpleNamespace]:
            yield _resolved("target", "https://target.example/api/v1", http_client)

        monkeypatch.setattr(users_module, "connect_to_server", _target)
        result = await users_module.sync_user(
            target_server="target",
            username="test-user",
            password="new-secret",
            disabled=True,
        )

    assert result["action"] == "updated"
    assert result["validation"]["status"] == "in_sync"
    assert result["user"]["roles"] == ["admin"]
    assert result["user"]["disabled"] is True


@pytest.mark.asyncio
async def test_sync_user_overwrite_false_skips_existing_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing users should be left untouched when overwrite is disabled."""

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"items": [{"username": "test-user", "id": "test-user"}], "count": 1})
        return httpx.Response(500, text="unexpected mutation")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http_client:

        @asynccontextmanager
        async def _target(_target: str) -> AsyncGenerator[SimpleNamespace]:
            yield _resolved("target", "https://target.example/api/v1", http_client)

        monkeypatch.setattr(users_module, "connect_to_server", _target)
        result = await users_module.sync_user(
            target_server="target",
            username="test-user",
            overwrite=False,
        )

    assert result["action"] == "skipped"
    assert result["target_user"] == {"username": "test-user", "id": "test-user"}


@pytest.mark.asyncio
async def test_sync_user_source_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replication should fail clearly when the source user is absent."""
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(404))) as http_client:

        @asynccontextmanager
        async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
            yield (
                _resolved("source", "https://source.example/api/v1", http_client),
                _resolved("target", "https://target.example/api/v1", http_client),
            )

        monkeypatch.setattr(users_module, "connect_server_pair", _pair)
        with pytest.raises(ValueError, match="was not found on source server"):
            await users_module.sync_user(
                source_server="source",
                target_server="target",
                username="missing-user",
                password="secret",
            )


@pytest.mark.asyncio
async def test_sync_user_missing_explicit_password_env_lists_checked_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing explicit password env var should be surfaced in the create error."""
    monkeypatch.delenv("MISSING_USER_PASSWORD", raising=False)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(404, text="missing"))
    ) as http_client:

        @asynccontextmanager
        async def _target(_target: str) -> AsyncGenerator[SimpleNamespace]:
            yield _resolved("target", "https://target.example/api/v1", http_client)

        monkeypatch.setattr(users_module, "connect_to_server", _target)
        with pytest.raises(ValueError, match="MISSING_USER_PASSWORD"):
            await users_module.sync_user(
                target_server="target",
                username="test-user",
                password_env="MISSING_USER_PASSWORD",
            )


@pytest.mark.asyncio
async def test_sync_user_to_target_can_skip_post_write_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_after=false should avoid the post-write user lookup."""
    target = SimpleNamespace(
        server_name="target",
        config=SimpleNamespace(base_url_str="https://target.example/api/v1", timeout_ms=1000),
    )
    get_user = AsyncMock(return_value=None)
    request_user_json = AsyncMock(return_value={"items": [{"username": "test-user", "id": "test-user"}]})
    monkeypatch.setattr(users_module, "_get_user", get_user)
    monkeypatch.setattr(users_module, "_request_user_json", request_user_json)

    result = await users_module._sync_user_to_target(
        target=cast("users_module.ResolvedControlPlane", target),
        target_server="target",
        username="test-user",
        source_user=None,
        password="secret",
        password_source="prompt",
        checked_env=[],
        first=None,
        last=None,
        email=None,
        roles=None,
        disabled=None,
        overwrite=True,
        validate_after=False,
    )

    assert result["action"] == "created"
    assert "validation" not in result
    assert get_user.await_count == 1


@pytest.mark.asyncio
async def test_sync_user_to_target_preserves_write_when_validation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Post-write validation errors should be reported without discarding the write result."""
    target = SimpleNamespace(
        server_name="target",
        config=SimpleNamespace(base_url_str="https://target.example/api/v1", timeout_ms=1000),
    )
    get_user = AsyncMock(side_effect=[None, RuntimeError("validation unavailable")])
    request_user_json = AsyncMock(return_value={"items": [{"username": "test-user", "id": "test-user"}]})
    monkeypatch.setattr(users_module, "_get_user", get_user)
    monkeypatch.setattr(users_module, "_request_user_json", request_user_json)

    result = await users_module._sync_user_to_target(
        target=cast("users_module.ResolvedControlPlane", target),
        target_server="target",
        username="test-user",
        source_user=None,
        password="secret",
        password_source="prompt",
        checked_env=[],
        first=None,
        last=None,
        email=None,
        roles=None,
        disabled=None,
        overwrite=True,
        validate_after=True,
    )

    assert result["action"] == "created"
    assert result["validation_error"] == {"type": "RuntimeError", "message": "validation unavailable"}


def test_type_placeholder() -> None:
    """Keep pyright aware that SimpleNamespace stand-ins are intentionally dynamic."""
    assert cast("object", _resolved) is not None
