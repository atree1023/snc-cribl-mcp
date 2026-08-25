"""Create and replicate local Cribl users between leaders."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from typing import Any, cast
from urllib.parse import quote

import httpx
from cribl_control_plane.models.security import Security

from ..client.cribl_client import ResolvedControlPlane, connect_server_pair, connect_to_server
from .common import HTTP_NOT_FOUND, get_auth_headers
from .sync import _compare_items, _serialize_copy_error

_SENSITIVE_USER_FIELD_NAMES = {
    "api_key",
    "apikey",
    "newpassword",
    "passwd",
    "password",
    "private_key",
    "privatekey",
    "secret",
    "ssh_private_key",
    "sshprivatekey",
    "token",
}


def _server_env_fragment(value: str) -> str:
    """Return an env-safe fragment for server and user names."""
    return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")


def _password_env_candidates(username: str, *, target_server: str | None = None) -> tuple[str, ...]:
    """Return supported environment variable names for a local user's password."""
    user_fragment = _server_env_fragment(username)
    candidates: list[str] = []
    if target_server is not None:
        server_fragment = _server_env_fragment(target_server)
        if server_fragment and user_fragment:
            candidates.extend(
                [
                    f"SNC_CRIBL_MCP_{server_fragment}_{user_fragment}_PASSWORD",
                    f"CRIBL_{server_fragment}_{user_fragment}_PASSWORD",
                ]
            )
    if user_fragment:
        candidates.extend(
            [
                f"SNC_CRIBL_MCP_USER_{user_fragment}_PASSWORD",
                f"CRIBL_USER_{user_fragment}_PASSWORD",
                f"{user_fragment}_PASSWORD",
                f"{user_fragment}_PASS",
            ]
        )
    return tuple(dict.fromkeys(candidates))


def resolve_user_password(
    username: str,
    *,
    password: str | None = None,
    password_env: str | None = None,
    target_server: str | None = None,
) -> tuple[str | None, str | None, list[str]]:
    """Resolve a local-user password from an explicit value or environment variable."""
    checked: list[str] = []
    if password:
        return password, "prompt", checked

    if password_env:
        checked.append(password_env)
        resolved = os.getenv(password_env)
        if resolved:
            return resolved, password_env, checked
        return None, None, checked

    for env_name in _password_env_candidates(username, target_server=target_server):
        checked.append(env_name)
        resolved = os.getenv(env_name)
        if resolved:
            return resolved, env_name, checked

    return None, None, checked


def _users_url(resolved: ResolvedControlPlane, username: str | None = None) -> str:
    """Return the direct local-users API URL."""
    base_url = resolved.config.base_url_str.rstrip("/")
    if username is None:
        return f"{base_url}/system/users"
    return f"{base_url}/system/users/{quote(username, safe='')}"


async def _resolved_security(resolved: ResolvedControlPlane) -> Security:
    """Return fresh security for direct user API calls when available."""
    get_security = cast("Callable[[], Awaitable[Security]] | None", getattr(resolved, "get_security", None))
    if get_security is not None:
        return await get_security()
    return resolved.security


async def _request_user_json(
    resolved: ResolvedControlPlane,
    *,
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Perform a direct local-user JSON API request."""
    http_client = resolved.client.sdk_configuration.async_client
    if not isinstance(http_client, httpx.AsyncClient):
        msg = "Cribl SDK client does not expose an httpx.AsyncClient."
        raise TypeError(msg)

    security = await _resolved_security(resolved)
    response = await http_client.request(
        method,
        url,
        headers={**get_auth_headers(security), "Content-Type": "application/json"},
        json=body,
        timeout=resolved.config.timeout_ms / 1000,
    )
    response.raise_for_status()
    payload = cast("object", response.json())
    return cast("dict[str, Any]", payload) if isinstance(payload, dict) else {}


def _extract_single_user(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a single user from Cribl's counted response shape."""
    items = cast("object", payload.get("items", []))
    if not isinstance(items, list) or not items:
        return None
    typed_items = cast("list[object]", items)
    first = typed_items[0]
    return cast("dict[str, Any]", first) if isinstance(first, dict) else None


async def _get_user(resolved: ResolvedControlPlane, username: str) -> dict[str, Any] | None:
    """Fetch a local user or return None when it is absent."""
    try:
        return _extract_single_user(
            await _request_user_json(
                resolved,
                method="GET",
                url=_users_url(resolved, username),
            )
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == HTTP_NOT_FOUND:
            return None
        raise


def _strip_sensitive_user_fields(user: dict[str, Any]) -> dict[str, Any]:
    """Remove password/token material from a user payload."""
    return {
        key: value
        for key, value in user.items()
        if re.sub(r"[^a-z0-9]+", "", key.casefold()) not in _SENSITIVE_USER_FIELD_NAMES
    }


def _build_user_payload(
    *,
    username: str,
    source_user: dict[str, Any] | None = None,
    password: str | None = None,
    first: str | None = None,
    last: str | None = None,
    email: str | None = None,
    roles: list[str] | None = None,
    disabled: bool | None = None,
) -> dict[str, Any]:
    """Build the payload used to create or update a local user."""
    payload: dict[str, Any] = _strip_sensitive_user_fields(source_user or {})
    payload["username"] = username
    payload["id"] = username
    if password is not None:
        payload["password"] = password
    if first is not None:
        payload["first"] = first
    if last is not None:
        payload["last"] = last
    if email is not None:
        payload["email"] = email
    if roles is not None:
        payload["roles"] = roles
    if disabled is not None:
        payload["disabled"] = disabled
    return payload


def _public_user_payload(user: dict[str, Any]) -> dict[str, Any]:
    """Return a user payload safe to include in tool responses."""
    return _strip_sensitive_user_fields(user)


async def sync_user(
    *,
    target_server: str,
    username: str,
    source_server: str | None = None,
    password: str | None = None,
    password_env: str | None = None,
    first: str | None = None,
    last: str | None = None,
    email: str | None = None,
    roles: list[str] | None = None,
    disabled: bool | None = None,
    overwrite: bool = True,
    validate_after: bool = True,
) -> dict[str, Any]:
    """Create or replicate a local Cribl user on a target leader."""
    resolved_password, password_source, checked_env = resolve_user_password(
        username,
        password=password,
        password_env=password_env,
        target_server=target_server,
    )

    if source_server is None:
        async with connect_to_server(target_server) as target:
            return await _sync_user_to_target(
                target=target,
                target_server=target_server,
                username=username,
                source_user=None,
                password=resolved_password,
                password_source=password_source,
                checked_env=checked_env,
                first=first,
                last=last,
                email=email,
                roles=roles,
                disabled=disabled,
                overwrite=overwrite,
                validate_after=validate_after,
            )

    async with connect_server_pair(source_server, target_server) as (source, target):
        source_user = await _get_user(source, username)
        if source_user is None:
            msg = f"User '{username}' was not found on source server '{source.server_name}'."
            raise ValueError(msg)
        return await _sync_user_to_target(
            target=target,
            target_server=target_server,
            username=username,
            source_user=source_user,
            password=resolved_password,
            password_source=password_source,
            checked_env=checked_env,
            first=first,
            last=last,
            email=email,
            roles=roles,
            disabled=disabled,
            overwrite=overwrite,
            validate_after=validate_after,
            source_server_name=source.server_name,
        )


async def _sync_user_to_target(
    *,
    target: ResolvedControlPlane,
    target_server: str,
    username: str,
    source_user: dict[str, Any] | None,
    password: str | None,
    password_source: str | None,
    checked_env: list[str],
    first: str | None,
    last: str | None,
    email: str | None,
    roles: list[str] | None,
    disabled: bool | None,
    overwrite: bool,
    validate_after: bool,
    source_server_name: str | None = None,
) -> dict[str, Any]:
    """Apply a local user payload to a resolved target leader."""
    target_user = await _get_user(target, username)
    if target_user is None and password is None:
        msg = (
            f"Creating user '{username}' requires a password. Provide password, password_env, "
            f"or one of these environment variables: {', '.join(checked_env)}."
        )
        raise ValueError(msg)

    base_user = source_user if source_user is not None else target_user
    payload = _build_user_payload(
        username=username,
        source_user=base_user,
        password=password,
        first=first,
        last=last,
        email=email,
        roles=roles,
        disabled=disabled,
    )

    if target_user is None:
        action = "created"
        written = _extract_single_user(
            await _request_user_json(
                target,
                method="POST",
                url=_users_url(target),
                body=payload,
            )
        )
    elif not overwrite:
        return {
            "action": "skipped",
            "source_server": source_server_name,
            "target_server": target.server_name,
            "username": username,
            "password_source": password_source,
            "password_env_checked": checked_env,
            "reason": "Target user already exists and overwrite is disabled.",
            "target_user": _public_user_payload(target_user),
        }
    else:
        action = "updated"
        written = _extract_single_user(
            await _request_user_json(
                target,
                method="PATCH",
                url=_users_url(target, username),
                body=payload,
            )
        )

    expected = _public_user_payload(payload)
    result: dict[str, Any] = {
        "action": action,
        "source_server": source_server_name,
        "target_server": target.server_name or target_server,
        "username": username,
        "password_source": password_source,
        "password_env_checked": checked_env,
        "user": _public_user_payload(written or expected),
    }
    if validate_after:
        try:
            target_after = await _get_user(target, username)
            target_payload = _public_user_payload(target_after) if target_after is not None else None
            result["validation"] = _compare_items(
                "raw",
                username,
                expected,
                target_payload,
            )
        except Exception as exc:  # noqa: BLE001 - preserve successful writes even when validation fails
            result["validation_error"] = _serialize_copy_error(exc)
    return result


__all__ = [
    "resolve_user_password",
    "sync_user",
]
