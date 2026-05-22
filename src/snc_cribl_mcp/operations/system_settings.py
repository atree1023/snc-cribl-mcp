"""Validate and replicate Cribl global system settings."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, cast

import httpx
from cribl_control_plane.models.security import Security

from ..client.cribl_client import ResolvedControlPlane, connect_server_pair
from .common import get_auth_headers
from .sync import _apply_validate_response_limit, _compare_items, _serialize_copy_error


def _settings_url(resolved: ResolvedControlPlane) -> str:
    """Return the direct global system settings API URL."""
    return f"{resolved.config.base_url_str.rstrip('/')}/system/settings/conf"


def _http_client(resolved: ResolvedControlPlane) -> httpx.AsyncClient:
    """Return the SDK-owned HTTP client for direct system-settings calls."""
    http_client = resolved.client.sdk_configuration.async_client
    if not isinstance(http_client, httpx.AsyncClient):
        msg = "Cribl SDK client does not expose an httpx.AsyncClient."
        raise TypeError(msg)
    return http_client


async def _resolved_security(resolved: ResolvedControlPlane) -> Security:
    """Return fresh security for direct system-settings API calls when available."""
    get_security = cast("Callable[[], Awaitable[Security]] | None", getattr(resolved, "get_security", None))
    if get_security is not None:
        return await get_security()
    return resolved.security


async def _request_settings_json(
    resolved: ResolvedControlPlane,
    *,
    method: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call the direct system-settings endpoint and return JSON."""
    security = await _resolved_security(resolved)
    response = await _http_client(resolved).request(
        method,
        _settings_url(resolved),
        headers={**get_auth_headers(security), "Content-Type": "application/json"},
        json=body,
        timeout=resolved.config.timeout_ms / 1000,
    )
    response.raise_for_status()
    payload = cast("object", response.json())
    return cast("dict[str, Any]", payload) if isinstance(payload, dict) else {}


def _first_settings_item(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract the single system settings item from Cribl's counted response."""
    items = cast("object", payload.get("items", []))
    if not isinstance(items, list) or not items:
        msg = "Cribl system settings response did not include an item."
        raise RuntimeError(msg)
    first = cast("object", items[0])
    if not isinstance(first, dict):
        msg = "Cribl system settings item was not a JSON object."
        raise TypeError(msg)
    return cast("dict[str, Any]", first)


async def _get_system_settings(resolved: ResolvedControlPlane) -> dict[str, Any]:
    """Fetch global system settings through direct HTTP.

    The installed SDK models can reject valid live payloads where optional SSL
    fields are omitted while SSL is disabled, so this workflow intentionally
    keeps the raw API shape.
    """
    return _first_settings_item(await _request_settings_json(resolved, method="GET"))


async def _patch_system_settings(resolved: ResolvedControlPlane, settings: dict[str, Any]) -> None:
    """Patch global system settings through direct HTTP."""
    await _request_settings_json(resolved, method="PATCH", body=settings)


def _compare_system_settings(
    item_id: str,
    source_settings: dict[str, Any],
    target_settings: dict[str, Any],
    *,
    include_payloads: bool = False,
) -> dict[str, Any]:
    """Compare raw system settings using the generic JSON diff path."""
    return _compare_items(
        "raw",
        item_id,
        source_settings,
        target_settings,
        include_payloads=include_payloads,
    )


def _system_settings_response(
    *,
    source: ResolvedControlPlane,
    target: ResolvedControlPlane,
    item_result: dict[str, Any],
) -> dict[str, Any]:
    """Build the public validation response for global system settings."""
    return _apply_validate_response_limit(
        {
            "resource_kind": "system_settings",
            "scope": "global",
            "source_server": source.server_name,
            "target_server": target.server_name,
            "in_sync": item_result["status"] == "in_sync",
            "items": [item_result],
        }
    )


async def validate_system_settings_sync(
    source_server: str,
    target_server: str,
    *,
    include_payloads: bool = False,
) -> dict[str, Any]:
    """Validate whether two leaders have matching global system settings."""
    async with connect_server_pair(source_server, target_server) as (source, target):
        source_settings = await _get_system_settings(source)
        target_settings = await _get_system_settings(target)
        item_result = _compare_system_settings(
            "system_settings",
            source_settings,
            target_settings,
            include_payloads=include_payloads,
        )
        return _system_settings_response(source=source, target=target, item_result=item_result)


async def replicate_system_settings(
    source_server: str,
    target_server: str,
    *,
    overwrite: bool = True,
    validate_after: bool = True,
) -> dict[str, Any]:
    """Copy global system settings from one leader to another."""
    async with connect_server_pair(source_server, target_server) as (source, target):
        source_settings = await _get_system_settings(source)
        target_settings = await _get_system_settings(target)
        before = _compare_system_settings("system_settings", source_settings, target_settings)

        if before["status"] == "in_sync":
            action = "skipped"
            reason = "Target system settings are already in sync."
        elif not overwrite:
            action = "skipped"
            reason = "Target system settings differ and overwrite is disabled."
        else:
            action = "updated"
            reason = None
            await _patch_system_settings(target, source_settings)

        result: dict[str, Any] = {
            "resource_kind": "system_settings",
            "scope": "global",
            "source_server": source.server_name,
            "target_server": target.server_name,
            "action": action,
            "updated_count": 1 if action == "updated" else 0,
            "skipped_count": 1 if action == "skipped" else 0,
            "before": before,
        }
        if reason is not None:
            result["reason"] = reason
        if validate_after:
            try:
                target_after = await _get_system_settings(target)
                result["validation"] = _compare_system_settings("system_settings", source_settings, target_after)
            except Exception as exc:  # noqa: BLE001 - keep mutation result visible
                result["validation_error"] = _serialize_copy_error(exc)
        return result


__all__ = [
    "replicate_system_settings",
    "validate_system_settings_sync",
]
