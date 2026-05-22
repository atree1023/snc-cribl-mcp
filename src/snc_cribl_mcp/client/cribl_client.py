"""Cribl Control Plane client setup and helpers.

Provides the async context manager to create a configured ``CriblControlPlane``
client instance with shared HTTP settings.
"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.security import Security
from cribl_control_plane.utils import BackoffStrategy, RetryConfig

from ..config import CriblConfig
from .token_manager import get_token_manager

type SecurityProvider = Callable[[], Awaitable[Security]]


@dataclass(frozen=True, slots=True)
class ResolvedControlPlane:
    """Resolved server metadata bundled with an authenticated SDK client."""

    server_name: str
    config: CriblConfig
    client: CriblControlPlane
    security: Security
    security_provider: SecurityProvider | None = None

    async def get_security(self) -> Security:
        """Return fresh bearer security when a provider is available."""
        if self.security_provider is None:
            return self.security
        return await self.security_provider()


@asynccontextmanager
async def create_control_plane(
    config: CriblConfig,
    *,
    security: Security | Callable[[], Security] | None = None,
) -> AsyncGenerator[CriblControlPlane]:
    """Create a configured Cribl Control Plane client.

    Args:
        config: The configuration containing base URL, TLS verification, and timeouts.
        security: Optional security configuration (token or callback).

    Yields:
        Configured CriblControlPlane client instance.

    """
    timeout = httpx.Timeout(config.timeout_ms / 1000)
    retry_config = RetryConfig(
        "backoff",
        BackoffStrategy(1, 50, 1.1, 100),
        retry_connection_errors=True,
    )  # Default retry strategy
    async with httpx.AsyncClient(verify=config.verify_ssl, timeout=timeout) as client:
        control_plane = CriblControlPlane(
            server_url=config.base_url_str,
            security=security,
            async_client=client,
            retry_config=retry_config,
        )
        async with control_plane:
            yield control_plane


@asynccontextmanager
async def connect_to_server(server: str | None) -> AsyncGenerator[ResolvedControlPlane]:
    """Resolve a configured server name and yield an authenticated SDK client."""
    config = CriblConfig.resolve(server)
    token_manager = get_token_manager(config)
    security = await token_manager.get_security()
    resolved_name = config.server_name or server or "default"
    async with create_control_plane(config, security=security) as client:
        yield ResolvedControlPlane(
            server_name=resolved_name,
            config=config,
            client=client,
            security=security,
            security_provider=token_manager.get_security,
        )


@asynccontextmanager
async def connect_server_pair(
    source_server: str,
    target_server: str,
) -> AsyncGenerator[tuple[ResolvedControlPlane, ResolvedControlPlane]]:
    """Yield authenticated SDK clients for a source/target server pair."""
    async with connect_to_server(source_server) as source, connect_to_server(target_server) as target:
        yield source, target


__all__ = [
    "ResolvedControlPlane",
    "connect_server_pair",
    "connect_to_server",
    "create_control_plane",
]
