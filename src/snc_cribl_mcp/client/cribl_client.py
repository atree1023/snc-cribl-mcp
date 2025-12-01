"""Cribl Control Plane client setup and helpers.

Provides the async context manager to create a configured ``CriblControlPlane``
client instance with shared HTTP settings.
"""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.security import Security
from cribl_control_plane.utils import BackoffStrategy, RetryConfig

from ..config import CriblConfig


@asynccontextmanager
async def create_control_plane(
    config: CriblConfig,
    *,
    security: Security | Callable[[], Security] | None = None,
) -> AsyncIterator[CriblControlPlane]:
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


__all__ = ["create_control_plane"]
