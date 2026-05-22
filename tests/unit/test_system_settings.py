"""Unit tests for system settings sync helpers."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import httpx
import pytest
from cribl_control_plane.models.security import Security

import snc_cribl_mcp.operations.system_settings as system_settings_module


def _settings(worker_count: int) -> dict[str, object]:
    """Return a minimal serialized system settings payload."""
    return {
        "api": {},
        "backups": {},
        "pii": {},
        "proxy": {},
        "rollback": {},
        "shutdown": {},
        "sni": {},
        "system": {},
        "tls": {},
        "upgradeGroupSettings": {},
        "upgradeSettings": {},
        "workers": {"count": worker_count},
    }


def _resolved(name: str) -> SimpleNamespace:
    """Return a minimal resolved-server stand-in for system setting tests."""
    return SimpleNamespace(server_name=name, config=SimpleNamespace(timeout_ms=1000), client=object())


def _direct_resolved(name: str, base_url: str, http_client: httpx.AsyncClient) -> SimpleNamespace:
    """Return a resolved-server stand-in with an SDK-owned HTTP client."""
    return SimpleNamespace(
        server_name=name,
        config=SimpleNamespace(base_url_str=base_url, timeout_ms=1000),
        client=SimpleNamespace(sdk_configuration=SimpleNamespace(async_client=http_client)),
        security=Security(bearer_auth="token"),
    )


def test_system_settings_http_client_requires_httpx_client() -> None:
    """Direct settings calls should reject non-httpx SDK clients."""
    resolved = SimpleNamespace(client=SimpleNamespace(sdk_configuration=SimpleNamespace(async_client=object())))

    with pytest.raises(TypeError, match=r"does not expose an httpx\.AsyncClient"):
        system_settings_module._http_client(cast("system_settings_module.ResolvedControlPlane", resolved))


@pytest.mark.asyncio
async def test_system_settings_resolved_security_prefers_provider() -> None:
    """Direct settings calls should use fresh security when a provider exists."""
    fresh_security = Security(bearer_auth="fresh-token")
    resolved = SimpleNamespace(get_security=AsyncMock(return_value=fresh_security), security=Security(bearer_auth="old"))

    assert (
        await system_settings_module._resolved_security(cast("system_settings_module.ResolvedControlPlane", resolved))
        is fresh_security
    )
    resolved.get_security.assert_awaited_once()


def test_first_settings_item_rejects_missing_and_malformed_payloads() -> None:
    """System settings responses should contain one JSON object item."""
    with pytest.raises(RuntimeError, match="did not include an item"):
        system_settings_module._first_settings_item({"items": []})

    with pytest.raises(RuntimeError, match="did not include an item"):
        system_settings_module._first_settings_item({"items": "not-a-list"})

    with pytest.raises(TypeError, match="was not a JSON object"):
        system_settings_module._first_settings_item({"items": ["not-an-object"]})


@pytest.mark.asyncio
async def test_patch_system_settings_uses_direct_patch_api() -> None:
    """System settings patching should send the raw settings payload to the direct endpoint."""
    requests: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"items": [{"id": "conf"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http_client:
        resolved = cast(
            "system_settings_module.ResolvedControlPlane",
            _direct_resolved("target", "https://cribl.example.com/api/v1", http_client),
        )

        await system_settings_module._patch_system_settings(resolved, {"api": {"retryCount": 120}})

    assert requests[0].method == "PATCH"
    assert requests[0].headers["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_get_system_settings_uses_direct_api_and_preserves_sparse_payload() -> None:
    """Direct reads should keep valid live payloads that the SDK model rejects."""
    requests: list[httpx.Request] = []
    payload = {"items": [{**_settings(1), "api": {"ssl": {"disabled": True}}}], "count": 1}

    def _handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as http_client:
        resolved = cast(
            "system_settings_module.ResolvedControlPlane",
            _direct_resolved("source", "https://cribl.example.com/api/v1", http_client),
        )

        result = await system_settings_module._get_system_settings(resolved)

    assert result["api"] == {"ssl": {"disabled": True}}
    assert requests[0].method == "GET"
    assert str(requests[0].url) == "https://cribl.example.com/api/v1/system/settings/conf"
    assert requests[0].headers["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_validate_system_settings_sync_reports_difference(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validation should compare the single global settings payload."""
    source = _resolved("source")
    target = _resolved("target")

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield source, target

    get_system_settings = AsyncMock(side_effect=[_settings(1), _settings(2)])
    monkeypatch.setattr(system_settings_module, "connect_server_pair", _pair)
    monkeypatch.setattr(system_settings_module, "_get_system_settings", get_system_settings)

    result = await system_settings_module.validate_system_settings_sync("source", "target")

    assert result["in_sync"] is False
    assert result["items"][0]["status"] == "different"
    assert result["items"][0]["differing_paths"] == ["workers.count"]


@pytest.mark.asyncio
async def test_replicate_system_settings_updates_target_and_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replication should patch the raw target settings and validate afterward."""
    source = _resolved("source")
    target = _resolved("target")

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield source, target

    get_system_settings = AsyncMock(side_effect=[_settings(1), _settings(2), _settings(1)])
    patch_system_settings = AsyncMock()
    monkeypatch.setattr(system_settings_module, "connect_server_pair", _pair)
    monkeypatch.setattr(system_settings_module, "_get_system_settings", get_system_settings)
    monkeypatch.setattr(system_settings_module, "_patch_system_settings", patch_system_settings)

    result = await system_settings_module.replicate_system_settings("source", "target")

    assert result["action"] == "updated"
    assert result["validation"]["status"] == "in_sync"
    patch_system_settings.assert_awaited_once_with(target, _settings(1))


@pytest.mark.asyncio
async def test_replicate_system_settings_skips_when_already_in_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    """Already matching settings should not be patched."""
    source = _resolved("source")
    target = _resolved("target")

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield source, target

    get_system_settings = AsyncMock(side_effect=[_settings(1), _settings(1), _settings(1)])
    patch_system_settings = AsyncMock()
    monkeypatch.setattr(system_settings_module, "connect_server_pair", _pair)
    monkeypatch.setattr(system_settings_module, "_get_system_settings", get_system_settings)
    monkeypatch.setattr(system_settings_module, "_patch_system_settings", patch_system_settings)

    result = await system_settings_module.replicate_system_settings("source", "target")

    assert result["action"] == "skipped"
    assert result["reason"] == "Target system settings are already in sync."
    patch_system_settings.assert_not_awaited()


@pytest.mark.asyncio
async def test_replicate_system_settings_can_skip_post_write_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_after=false should not fetch target settings after the write."""
    source = _resolved("source")
    target = _resolved("target")

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield source, target

    get_system_settings = AsyncMock(side_effect=[_settings(1), _settings(2)])
    patch_system_settings = AsyncMock()
    monkeypatch.setattr(system_settings_module, "connect_server_pair", _pair)
    monkeypatch.setattr(system_settings_module, "_get_system_settings", get_system_settings)
    monkeypatch.setattr(system_settings_module, "_patch_system_settings", patch_system_settings)

    result = await system_settings_module.replicate_system_settings("source", "target", validate_after=False)

    assert result["action"] == "updated"
    assert "validation" not in result
    assert get_system_settings.await_count == 2


@pytest.mark.asyncio
async def test_replicate_system_settings_reports_post_write_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed post-write validation should not hide the successful patch."""
    source = _resolved("source")
    target = _resolved("target")

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield source, target

    get_system_settings = AsyncMock(side_effect=[_settings(1), _settings(2), RuntimeError("settings unavailable")])
    patch_system_settings = AsyncMock()
    monkeypatch.setattr(system_settings_module, "connect_server_pair", _pair)
    monkeypatch.setattr(system_settings_module, "_get_system_settings", get_system_settings)
    monkeypatch.setattr(system_settings_module, "_patch_system_settings", patch_system_settings)

    result = await system_settings_module.replicate_system_settings("source", "target")

    assert result["action"] == "updated"
    assert result["validation_error"] == {"type": "RuntimeError", "message": "settings unavailable"}


@pytest.mark.asyncio
async def test_replicate_system_settings_respects_overwrite_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """Overwrite=false should skip mutation when settings differ."""
    source = _resolved("source")
    target = _resolved("target")

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield source, target

    get_system_settings = AsyncMock(side_effect=[_settings(1), _settings(2), _settings(2)])
    patch_system_settings = AsyncMock()
    monkeypatch.setattr(system_settings_module, "connect_server_pair", _pair)
    monkeypatch.setattr(system_settings_module, "_get_system_settings", get_system_settings)
    monkeypatch.setattr(system_settings_module, "_patch_system_settings", patch_system_settings)

    result = await system_settings_module.replicate_system_settings("source", "target", overwrite=False)

    assert result["action"] == "skipped"
    assert result["reason"] == "Target system settings differ and overwrite is disabled."
    patch_system_settings.assert_not_awaited()
