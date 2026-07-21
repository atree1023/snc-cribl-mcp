"""Unit tests for Cribl version-control MCP tool wrappers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.tools.version_control import register


class _FakeApp:
    """Minimal FastMCP stand-in that captures registered version-control tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {}
        self.annotations: dict[str, dict[str, Any] | None] = {}

    def tool(
        self,
        *,
        name: str,
        description: str,
        annotations: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Callable[..., Awaitable[dict[str, Any]]]]:
        """Capture one tool registration."""

        def _decorator(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
            assert description
            self.tools[name] = func
            self.annotations[name] = annotations
            return func

        return _decorator


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like mock with async logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_read_tools_forward_status_and_diff_arguments(mock_ctx: Context) -> None:
    """Read-only wrappers should preserve product scope and diff controls."""
    status_impl = AsyncMock(return_value={"targets": []})
    diff_impl = AsyncMock(return_value={"diff": {}})
    app = _FakeApp()
    register(
        app,  # type: ignore[arg-type]
        status_impl=status_impl,
        diff_impl=diff_impl,
        commit_impl=AsyncMock(),
        deploy_impl=AsyncMock(),
        commit_deploy_impl=AsyncMock(),
        commit_deploy_all_impl=AsyncMock(),
        push_impl=AsyncMock(),
    )

    status = await app.tools["get_group_git_status"](mock_ctx, server="prod", product="edge", group="Fleet One")
    diff = await app.tools["get_group_git_diff"](
        mock_ctx,
        group="Fleet One",
        product="edge",
        server="prod",
        compare_to="head",
        filename="local/edge/inputs.yml",
        diff_line_limit=0,
    )

    assert status == {"targets": []}
    assert diff == {"diff": {}}
    status_impl.assert_awaited_once_with("prod", product="edge", group="Fleet One")
    diff_impl.assert_awaited_once_with(
        "prod",
        product=ProductsCore.EDGE,
        group="Fleet One",
        compare_to="head",
        filename="local/edge/inputs.yml",
        diff_line_limit=0,
    )
    assert app.annotations["get_group_git_status"] == {
        "title": "Get group and fleet Git status",
        "readOnlyHint": True,
        "idempotentHint": True,
    }


@pytest.mark.asyncio
async def test_mutation_tools_forward_review_and_workflow_arguments(mock_ctx: Context) -> None:
    """Mutation wrappers should forward plan hashes and workflow switches exactly."""
    commit_impl = AsyncMock(return_value={"status": "committed"})
    deploy_impl = AsyncMock(return_value={"status": "deployed"})
    commit_deploy_impl = AsyncMock(return_value={"status": "deployed"})
    commit_deploy_all_impl = AsyncMock(return_value={"status": "completed"})
    push_impl = AsyncMock(return_value={"status": "pushed"})
    app = _FakeApp()
    register(
        app,  # type: ignore[arg-type]
        status_impl=AsyncMock(),
        diff_impl=AsyncMock(),
        commit_impl=commit_impl,
        deploy_impl=deploy_impl,
        commit_deploy_impl=commit_deploy_impl,
        commit_deploy_all_impl=commit_deploy_all_impl,
        push_impl=push_impl,
    )

    await app.tools["commit_group_config"](
        mock_ctx,
        group="workers",
        message="Commit",
        product="stream",
        server="prod",
        files=["local/cribl/inputs.yml"],
        effective=False,
        push=True,
        dry_run=False,
        expected_plan_sha256="commit-plan",
    )
    await app.tools["deploy_group_config"](
        mock_ctx,
        group="workers",
        version="abc123",
        product="stream",
        server="prod",
        push=True,
        dry_run=False,
        expected_plan_sha256="deploy-plan",
    )
    await app.tools["commit_and_deploy_group"](
        mock_ctx,
        group="fleet",
        message="Rollout",
        product="edge",
        server="prod",
        files=None,
        effective=True,
        push=False,
        dry_run=False,
        expected_plan_sha256="group-plan",
    )
    await app.tools["commit_and_deploy_all"](
        mock_ctx,
        message="All rollout",
        server="prod",
        product="all",
        effective=True,
        push=True,
        stop_on_error=False,
        dry_run=False,
        expected_plan_sha256="all-plan",
    )
    await app.tools["push_config_git"](
        mock_ctx,
        server="prod",
        dry_run=False,
        expected_plan_sha256="push-plan",
    )

    commit_impl.assert_awaited_once_with(
        "prod",
        product=ProductsCore.STREAM,
        group="workers",
        message="Commit",
        files=["local/cribl/inputs.yml"],
        effective=False,
        push=True,
        dry_run=False,
        expected_plan_sha256="commit-plan",
    )
    deploy_impl.assert_awaited_once_with(
        "prod",
        product=ProductsCore.STREAM,
        group="workers",
        version="abc123",
        push=True,
        dry_run=False,
        expected_plan_sha256="deploy-plan",
    )
    commit_deploy_impl.assert_awaited_once_with(
        "prod",
        product=ProductsCore.EDGE,
        group="fleet",
        message="Rollout",
        files=None,
        effective=True,
        push=False,
        dry_run=False,
        expected_plan_sha256="group-plan",
    )
    commit_deploy_all_impl.assert_awaited_once_with(
        "prod",
        message="All rollout",
        product="all",
        effective=True,
        push=True,
        stop_on_error=False,
        dry_run=False,
        expected_plan_sha256="all-plan",
    )
    push_impl.assert_awaited_once_with(
        "prod",
        dry_run=False,
        expected_plan_sha256="push-plan",
    )
    assert app.annotations["commit_and_deploy_all"] == {
        "title": "Commit and deploy all groups and fleets",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
    }
