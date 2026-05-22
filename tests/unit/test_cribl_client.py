"""Unit tests for Cribl Control Plane connection helpers."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.security import Security

import snc_cribl_mcp.client.cribl_client as cribl_client_module
from snc_cribl_mcp.config import CriblConfig


def _config(server_name: str | None = "resolved") -> CriblConfig:
    """Return a minimal valid on-prem config for client helper tests."""
    return CriblConfig(
        url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
        server_name=server_name,
    )


@pytest.mark.asyncio
async def test_connect_to_server_resolves_security_and_yields_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """connect_to_server should resolve config, fetch security, and yield metadata."""
    config = _config()
    security = object()
    manager = SimpleNamespace(get_security=AsyncMock(return_value=security))
    client = MagicMock()

    @asynccontextmanager
    async def _create_control_plane(
        cp_config: CriblConfig,
        *,
        security: object | None = None,
    ) -> AsyncGenerator[MagicMock]:
        assert cp_config is config
        assert security is not None
        yield client

    def _resolve_config(_server: str | None) -> CriblConfig:
        return config

    def _get_token_manager(_config: CriblConfig) -> SimpleNamespace:
        return manager

    monkeypatch.setattr(cribl_client_module.CriblConfig, "resolve", staticmethod(_resolve_config))
    monkeypatch.setattr(cribl_client_module, "get_token_manager", _get_token_manager)
    monkeypatch.setattr(cribl_client_module, "create_control_plane", _create_control_plane)

    async with cribl_client_module.connect_to_server("golden.oak") as resolved:
        assert resolved.server_name == "resolved"
        assert resolved.config is config
        assert resolved.client is client

    manager.get_security.assert_awaited_once()


@pytest.mark.asyncio
async def test_connect_to_server_uses_requested_name_when_config_name_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The requested server name should be used when config has no server_name."""
    config = _config(server_name=None)
    manager = SimpleNamespace(get_security=AsyncMock(return_value=object()))

    @asynccontextmanager
    async def _create_control_plane(
        _config: CriblConfig,
        *,
        security: object | None = None,
    ) -> AsyncGenerator[MagicMock]:
        _ = security
        yield MagicMock()

    def _resolve_config(_server: str | None) -> CriblConfig:
        return config

    def _get_token_manager(_config: CriblConfig) -> SimpleNamespace:
        return manager

    monkeypatch.setattr(cribl_client_module.CriblConfig, "resolve", staticmethod(_resolve_config))
    monkeypatch.setattr(cribl_client_module, "get_token_manager", _get_token_manager)
    monkeypatch.setattr(cribl_client_module, "create_control_plane", _create_control_plane)

    async with cribl_client_module.connect_to_server("golden.oak") as resolved:
        assert resolved.server_name == "golden.oak"


@pytest.mark.asyncio
async def test_connect_server_pair_yields_source_and_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """connect_server_pair should compose two resolved connection contexts."""
    config = _config()
    entered: list[str | None] = []

    @asynccontextmanager
    async def _connect_to_server(server: str | None) -> AsyncGenerator[cribl_client_module.ResolvedControlPlane]:
        entered.append(server)
        yield cribl_client_module.ResolvedControlPlane(
            server_name=server or "default",
            config=config,
            client=MagicMock(),
            security=Security(bearer_auth="token"),
        )

    monkeypatch.setattr(cribl_client_module, "connect_to_server", _connect_to_server)

    async with cribl_client_module.connect_server_pair("source", "target") as (source, target):
        assert source.server_name == "source"
        assert target.server_name == "target"

    assert entered == ["source", "target"]


@pytest.mark.asyncio
async def test_resolved_control_plane_get_security_returns_static_security() -> None:
    """Resolved metadata should reuse the initial security when no provider is present."""
    security = Security(bearer_auth="initial-token")
    resolved = cribl_client_module.ResolvedControlPlane(
        server_name="target",
        config=_config(),
        client=MagicMock(),
        security=security,
    )

    assert await resolved.get_security() is security


@pytest.mark.asyncio
async def test_resolved_control_plane_get_security_uses_provider() -> None:
    """Resolved metadata should ask the provider for fresh security when available."""
    initial_security = Security(bearer_auth="initial-token")
    fresh_security = Security(bearer_auth="fresh-token")
    provider = AsyncMock(return_value=fresh_security)
    resolved = cribl_client_module.ResolvedControlPlane(
        server_name="target",
        config=_config(),
        client=MagicMock(),
        security=initial_security,
        security_provider=provider,
    )

    assert await resolved.get_security() is fresh_security
    provider.assert_awaited_once()
