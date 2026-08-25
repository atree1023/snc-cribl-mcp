"""Unit tests for Cribl version-control and deployment operations."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import unquote

import pytest
from cribl_control_plane.models.productscore import ProductsCore

from snc_cribl_mcp.client.cribl_client import ResolvedControlPlane
from snc_cribl_mcp.operations import version_control as vc


class _FakeModel:
    """Small generated-model stand-in for SDK response tests."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, **_: object) -> dict[str, Any]:
        """Return the configured serialized payload."""
        return self.payload


class _Counted:
    """Small counted SDK response stand-in."""

    def __init__(self, *items: dict[str, Any], count: int | None = None) -> None:
        self.items = [_FakeModel(item) for item in items]
        self.count = len(items) if count is None else count


class _Page:
    """Small paginated SDK wrapper for group inventory tests."""

    def __init__(self, *items: dict[str, Any], next_page: object | None = None) -> None:
        self.result = _Counted(*items)
        self._next_page = next_page

    async def next(self) -> object | None:
        """Return the configured next page."""
        return self._next_page


def _group_payload(
    group_id: str,
    *,
    product: ProductsCore,
    committed: str = "commit-1",
    deployed: str = "commit-0",
    local_changes: int = 1,
    inherits: str | None = None,
) -> dict[str, Any]:
    """Build mutable group/fleet state for the fake SDK harness."""
    return {
        "id": group_id,
        "name": f"Name {group_id}",
        "description": f"Description {group_id}",
        "type": product.value,
        "inherits": inherits,
        "configVersion": deployed,
        "git": {"commit": committed, "localChanges": local_changes},
        "workerCount": 3,
        "deployingWorkerCount": 0,
        "incompatibleWorkerCount": 0,
    }


class _Harness:
    """Stateful fake Cribl SDK surface for end-to-end workflow tests."""

    def __init__(self, *groups: tuple[ProductsCore, dict[str, Any]]) -> None:
        self.states = {(product, str(payload["id"])): payload for product, payload in groups}
        self.client = MagicMock()
        self.global_dirty = False
        self.global_ahead = 0
        self.global_behind = 0
        self.global_conflicts: list[str] = []
        self.remote: str | bool = "https://user:secret@git.example.test/cribl/config.git"
        self.versioning = True
        self.commit_order: list[str] = []
        self.deploy_order: list[str] = []
        self.diff_calls: list[dict[str, Any]] = []
        self.push_count = 0
        self.push_error: Exception | None = None
        self.commit_error_for: str | None = None
        self.deploy_error_for: str | None = None
        self.dirty_leader_on_group_commit = False
        self.inherit_on_commit: dict[str, list[str]] = {}
        self.changed_paths_by_group: dict[str, list[str]] = {}
        self.diff_paths_by_group: dict[str, list[str]] = {}
        self._commit_sequence = 1

        self.client.groups.list_async = AsyncMock(side_effect=self._list_groups)
        self.client.groups.get_async = AsyncMock(side_effect=self._get_group)
        self.client.groups.deploy_async = AsyncMock(side_effect=self._deploy)
        self.client.versions.statuses.get_async = AsyncMock(side_effect=self._status)
        self.client.versions.commits.list_async = AsyncMock(side_effect=self._history)
        self.client.versions.commits.diff_async = AsyncMock(side_effect=self._diff)
        self.client.versions.commits.create_async = AsyncMock(side_effect=self._commit)
        self.client.versions.commits.push_async = AsyncMock(side_effect=self._push)
        self.client.versions.configs.get_async = AsyncMock(side_effect=self._git_info)

    @staticmethod
    def _scope_group(server_url: str | None) -> str | None:
        if server_url is None or "/m/" not in server_url:
            return None
        return unquote(server_url.rsplit("/", maxsplit=1)[-1])

    def _state_for_id(self, group_id: str) -> dict[str, Any]:
        matches = [payload for (_, candidate), payload in self.states.items() if candidate == group_id]
        if len(matches) != 1:
            msg = f"Expected one fake state for {group_id}."
            raise AssertionError(msg)
        return matches[0]

    async def _list_groups(self, *, product: ProductsCore, **_: object) -> _Counted:
        return _Counted(*(payload for (candidate, _), payload in self.states.items() if candidate == product))

    async def _get_group(self, *, product: ProductsCore, id: str, **_: object) -> _Counted:  # noqa: A002
        return _Counted(self.states[(product, id)])

    async def _status(self, *, server_url: str | None = None, **_: object) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            changed = [vc._LEADER_METADATA_PATH] if self.global_dirty else []
            return _Counted(
                {
                    "ahead": self.global_ahead,
                    "behind": self.global_behind,
                    "conflicted": self.global_conflicts,
                    "created": [],
                    "current": "main",
                    "deleted": [],
                    "files": [{"path": path, "index": "M", "working_dir": "M"} for path in changed],
                    "modified": changed,
                    "not_added": [],
                    "renamed": [],
                    "staged": [],
                }
            )

        state = self._state_for_id(group_id)
        dirty = bool(cast("dict[str, Any]", state["git"])["localChanges"])
        changed = self.changed_paths_by_group.get(group_id, [f"local/cribl/{group_id}.yml"] if dirty else [])
        return _Counted(
            {
                "ahead": 0,
                "behind": 0,
                "conflicted": [],
                "created": [],
                "current": "main",
                "deleted": [],
                "files": [{"path": path, "index": "M", "working_dir": "M"} for path in changed],
                "modified": changed,
                "not_added": [],
                "renamed": [],
                "staged": [],
            }
        )

    async def _history(self, *, server_url: str | None = None, **_: object) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            return _Counted()
        state = self._state_for_id(group_id)
        return _Counted({"hash": cast("dict[str, Any]", state["git"])["commit"]})

    @staticmethod
    def _diff_file(group_id: str) -> dict[str, Any]:
        return {
            "addedLines": 2,
            "blocks": [],
            "deletedLines": 1,
            "isBinary": False,
            "isCombined": False,
            "isGitDiff": True,
            "isTooBig": False,
            "language": "yaml",
            "newName": f"local/cribl/{group_id}.yml",
            "oldName": f"local/cribl/{group_id}.yml",
        }

    async def _diff(
        self,
        *,
        commit: str | None = None,
        filename: str | None = None,
        diff_line_limit: int | None = None,
        server_url: str | None = None,
        **_: object,
    ) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            msg = "Expected a group-scoped diff call."
            raise AssertionError(msg)
        self.diff_calls.append(
            {
                "group": group_id,
                "commit": commit,
                "filename": filename,
                "diff_line_limit": diff_line_limit,
            }
        )
        state = self._state_for_id(group_id)
        git = cast("dict[str, Any]", state["git"])
        dirty = bool(git["localChanges"])
        differs_from_commit = commit is not None and commit != git["commit"]
        configured_paths = self.diff_paths_by_group.get(group_id)
        if configured_paths is not None:
            files = [
                {
                    **self._diff_file(group_id),
                    "newName": path,
                    "oldName": path,
                }
                for path in configured_paths
            ]
        else:
            files = [self._diff_file(group_id)] if dirty or differs_from_commit else []
        return _Counted({"diffJson": files})

    async def _commit(
        self,
        *,
        message: str,
        server_url: str | None = None,
        files: list[str] | None = None,
        **_: object,
    ) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            self.global_dirty = False
            self.global_ahead += 1
            return _Counted(
                {
                    "branch": "main",
                    "commit": "leader-sync",
                    "summary": {"changes": 1, "insertions": 1, "deletions": 1},
                    "files": {"modified": files or []},
                }
            )
        if group_id == self.commit_error_for:
            msg = f"commit failed for {group_id}"
            raise RuntimeError(msg)
        self._commit_sequence += 1
        version = f"commit-{group_id}-{self._commit_sequence}"
        state = self._state_for_id(group_id)
        cast("dict[str, Any]", state["git"])["commit"] = version
        cast("dict[str, Any]", state["git"])["localChanges"] = 0
        self.commit_order.append(group_id)
        if self.dirty_leader_on_group_commit:
            self.global_dirty = True
        for descendant in self.inherit_on_commit.get(group_id, []):
            cast("dict[str, Any]", self._state_for_id(descendant)["git"])["localChanges"] = 1
        return _Counted(
            {
                "branch": "main",
                "commit": version,
                "summary": {"changes": 1, "insertions": 2, "deletions": 1},
                "files": {"modified": [f"local/cribl/{group_id}.yml"]},
                "message": message,
            }
        )

    async def _deploy(
        self,
        *,
        product: ProductsCore,
        id: str,  # noqa: A002
        version: str,
        **_: object,
    ) -> _Counted:
        if id == self.deploy_error_for:
            msg = f"deploy failed for {id}"
            raise RuntimeError(msg)
        state = self.states[(product, id)]
        state["configVersion"] = version
        self.deploy_order.append(id)
        self.global_dirty = True
        return _Counted(state)

    async def _git_info(self, **_: object) -> _Counted:
        return _Counted({"remote": self.remote, "versioning": self.versioning})

    async def _push(self, **_: object) -> _Counted:
        if self.push_error is not None:
            raise self.push_error
        self.push_count += 1
        self.global_ahead = 0
        return _Counted({"result": "pushed"})


def _install_harness(monkeypatch: pytest.MonkeyPatch, harness: _Harness) -> None:
    """Patch the operation module to use one stateful fake control plane."""

    @asynccontextmanager
    async def _connect(_server: str | None) -> AsyncGenerator[ResolvedControlPlane]:
        resolved = SimpleNamespace(
            server_name="test",
            config=SimpleNamespace(base_url_str="https://cribl.example.test/api/v1", timeout_ms=1000),
            client=harness.client,
        )
        yield cast("ResolvedControlPlane", resolved)

    monkeypatch.setattr(vc, "connect_to_server", _connect)


def test_group_target_helpers_and_serialization() -> None:
    """Target and SDK response helpers should normalize common shapes."""
    payload = _group_payload("edge child", product=ProductsCore.EDGE, inherits="parent")
    target = vc.GroupTarget.from_payload(ProductsCore.EDGE, payload)

    assert target.group_id == "edge child"
    assert target.inherits == "parent"
    assert target.local_changes == 1
    assert target.deploying_worker_count == 0
    assert target.incompatible_worker_count == 0
    assert target.as_dict()["deployed_version"] == "commit-0"
    zero_target = vc.GroupTarget.from_payload(
        ProductsCore.STREAM,
        _group_payload("zero", product=ProductsCore.STREAM, local_changes=0),
    )
    assert zero_target.local_changes == 0
    assert zero_target.worker_count == 3
    assert vc._group_server_url("https://example/api/v1/", "edge child") == "https://example/api/v1/m/edge%20child"
    assert vc._serialize_counted_response(_Counted({"id": "one"}, count=None))["count"] == 1
    assert vc._first_counted_item(_Counted()) is None
    assert vc._optional_int(True) is None  # noqa: FBT003
    assert vc._optional_int("12") == 12
    assert vc._optional_int(object()) is None
    with pytest.raises(TypeError, match="Expected an SDK model"):
        vc._serialize_model(object())
    with pytest.raises(ValueError, match="did not include an id"):
        vc.GroupTarget.from_payload(ProductsCore.STREAM, {})


def test_status_diff_and_remote_helpers_cover_response_shapes() -> None:
    """Status, diff, and remote helpers should retain safety-relevant metadata."""
    status = {
        "current": "main",
        "ahead": 2.0,
        "behind": 1,
        "conflicted": ["conflict.yml"],
        "created": ["created.yml"],
        "deleted": [],
        "modified": ["modified.yml"],
        "notAdded": ["new.yml"],
        "staged": [],
        "files": [{"path": "from-files.yml"}],
        "renamed": [{"from": "old.yml", "to": "new-name.yml"}],
    }
    summary = vc._status_summary(status)
    assert summary["ahead"] == 2
    assert summary["behind"] == 1
    assert summary["clean"] is False
    assert "new-name.yml" in summary["changed_paths"]

    diff_payload = {"items": [{"diffJson": [_Harness._diff_file("default")]}]}
    diff_summary = vc._diff_summary(diff_payload)
    assert diff_summary["file_count"] == 1
    assert diff_summary["added_lines"] == 2
    assert diff_summary["deleted_lines"] == 1
    assert vc._canonical_digest(vc._diff_files(diff_payload)) == vc._canonical_digest(vc._diff_files(diff_payload))
    assert vc._safe_remote("https://user:password@git.example.test/repo.git") == "https://git.example.test/repo.git"
    assert vc._safe_remote("git@example.test:repo.git") == "configured"
    bounded_error = vc._error_payload(RuntimeError("x" * 3000))
    assert len(bounded_error["message"]) == vc._MAX_ERROR_MESSAGE_CHARS
    assert bounded_error["message_truncated"] is True


@pytest.mark.asyncio
async def test_large_change_plan_and_execution_results_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Large replications should return one capped path preview and no raw mutation payloads."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    paths = [f"local/cribl/config-{index:03}.yml" for index in range(107)]
    harness.changed_paths_by_group["default"] = paths
    harness.diff_paths_by_group["default"] = paths
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Replicate complete configuration",
    )
    plan = cast("dict[str, Any]", planned["plan"])
    changes = cast("dict[str, Any]", plan["changes"])

    assert changes["changed_count"] == 107
    assert len(changes["changed_paths"]) == vc._MAX_STATUS_PATHS
    assert changes["changed_paths_truncated"] is True
    assert len(changes["changed_paths_sha256"]) == 64
    assert "changed_paths" not in plan["git"]
    assert "pending_diff" not in plan
    assert json.dumps(planned).count(paths[0]) == 1
    assert len(json.dumps(planned)) < 12_000

    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Replicate complete configuration",
        dry_run=False,
        expected_plan_sha256=plan["plan_sha256"],
    )
    serialized_result = json.dumps(result)

    assert result["status"] == "deployed"
    assert result["executed_plan_sha256"] == plan["plan_sha256"]
    assert "plan" not in result
    assert "commit_response" not in result
    assert "deployment" not in result
    assert all(path not in serialized_result for path in paths)
    assert len(serialized_result) < 4_000


def test_deployment_order_is_parent_first_and_validates_hierarchy() -> None:
    """Edge Fleet topological ordering should handle levels, missing parents, and cycles."""
    stream = vc.GroupTarget(ProductsCore.STREAM, "stream-b")
    parent = vc.GroupTarget(ProductsCore.EDGE, "parent")
    child = vc.GroupTarget(ProductsCore.EDGE, "child", inherits="parent")
    grandchild = vc.GroupTarget(ProductsCore.EDGE, "grandchild", inherits="child")

    order = vc._deployment_order([grandchild, child, stream, parent])
    assert [target.group_id for target in order] == ["stream-b", "parent", "child", "grandchild"]
    with pytest.raises(ValueError, match="unknown fleet"):
        vc._deployment_order([child])
    with pytest.raises(ValueError, match="contains a cycle"):
        vc._deployment_order(
            [
                vc.GroupTarget(ProductsCore.EDGE, "one", inherits="two"),
                vc.GroupTarget(ProductsCore.EDGE, "two", inherits="one"),
            ]
        )


@pytest.mark.asyncio
async def test_collect_status_supports_one_subfleet_without_parent_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """A targeted read should not require the parent Fleet to be in the selected result."""
    child = _group_payload("child", product=ProductsCore.EDGE, local_changes=0, inherits="hidden-parent")
    harness = _Harness((ProductsCore.EDGE, child))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="edge", group="Name child")

    assert result["count"] == 1
    assert result["targets"][0]["target"]["id"] == "child"
    assert result["targets"][0]["git"]["deployment_pending"] is True
    with pytest.raises(ValueError, match="product must be"):
        await vc.collect_group_git_status("test", product="all", group="child")


@pytest.mark.asyncio
async def test_collect_status_omits_internal_search_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stream status should cover worker groups without mutating internal Search groups."""
    workers = _group_payload("workers", product=ProductsCore.STREAM, local_changes=0)
    search = _group_payload("search", product=ProductsCore.STREAM, local_changes=0)
    search.update({"type": "search", "isSearch": True})
    harness = _Harness((ProductsCore.STREAM, search), (ProductsCore.STREAM, workers))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream")

    assert result["count"] == 1
    assert result["targets"][0]["target"]["id"] == "workers"


@pytest.mark.asyncio
async def test_collect_status_reads_current_sdk_group_result_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Git status inventory should not turn SDK 0.11 group wrappers into zero targets."""
    workers = _group_payload("workers", product=ProductsCore.STREAM, local_changes=0)
    harness = _Harness((ProductsCore.STREAM, workers))

    async def _wrapped_groups(*, product: ProductsCore, **_: object) -> SimpleNamespace:
        payloads = [payload for (candidate, _), payload in harness.states.items() if candidate == product]
        return SimpleNamespace(result=_Counted(*payloads))

    harness.client.groups.list_async = AsyncMock(side_effect=_wrapped_groups)
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream")

    assert result["count"] == 1
    assert result["targets"][0]["target"]["id"] == "workers"


@pytest.mark.asyncio
async def test_collect_status_exhausts_sdk_group_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    """Version-control target discovery should include groups from every SDK page."""
    first = _group_payload("first", product=ProductsCore.STREAM, local_changes=0)
    second = _group_payload("second", product=ProductsCore.STREAM, local_changes=0)
    harness = _Harness((ProductsCore.STREAM, first), (ProductsCore.STREAM, second))
    harness.client.groups.list_async = AsyncMock(return_value=_Page(first, next_page=_Page(second)))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream")

    assert result["count"] == 2
    assert [entry["target"]["id"] for entry in result["targets"]] == ["first", "second"]


@pytest.mark.asyncio
async def test_collect_diff_uses_deployed_baseline_and_full_pending_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Diff reads should compare with configVersion and hash the complete pending diff."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_diff(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        compare_to="deployed",
        filename="local/cribl/default.yml",
        diff_line_limit=10,
    )

    assert result["comparison_commit"] == "commit-0"
    assert result["summary"]["file_count"] == 1
    assert len(result["pending_diff_sha256"]) == 64
    assert harness.diff_calls[0]["commit"] == "commit-0"
    assert harness.diff_calls[1] == {
        "group": "default",
        "commit": None,
        "filename": None,
        "diff_line_limit": 0,
    }
    with pytest.raises(ValueError, match="zero or greater"):
        await vc.collect_group_git_diff(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            diff_line_limit=-1,
        )


@pytest.mark.asyncio
async def test_commit_group_requires_reviewed_plan_and_reports_push_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Commit-only execution should enforce plan drift and preserve a successful commit on push failure."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Validated source update",
        push=True,
    )
    plan_hash = planned["plan"]["plan_sha256"]
    with pytest.raises(ValueError, match="stale"):
        await vc.commit_group_config(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            message="Validated source update",
            push=True,
            dry_run=False,
            expected_plan_sha256="stale",
        )

    harness.push_error = RuntimeError("remote rejected")
    result = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Validated source update",
        push=True,
        dry_run=False,
        expected_plan_sha256=plan_hash,
    )

    assert result["status"] == "partial_failure"
    assert result["completed_steps"] == ["group_commit"]
    assert result["commit"]["version"].startswith("commit-default-")
    assert result["push"]["status"] == "failed"
    assert "plan" not in result
    assert "commit_response" not in result


@pytest.mark.asyncio
async def test_deploy_explicit_version_commits_leader_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit deploy should use the requested hash and make a scoped Leader metadata commit."""
    state = _group_payload("default", product=ProductsCore.STREAM, local_changes=0)
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.deploy_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        version="rollback-123",
    )
    result = await vc.deploy_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        version="rollback-123",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "deployed"
    assert result["version"] == "rollback-123"
    assert result["leader_commit"]["files"] == ["local/cribl/groups.yml"]
    assert result["control_plane_version_confirmed"] is True
    assert harness.deploy_order == ["default"]

    harness.global_conflicts = ["unrelated-conflict.yml"]
    blocked = await vc.deploy_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        version="next-version",
    )
    assert "Leader Git working tree contains conflicts" in blocked["plan"]["blocked_reasons"][0]
    with pytest.raises(ValueError, match="contains conflicts"):
        await vc.deploy_group_config(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            version="next-version",
            dry_run=False,
            expected_plan_sha256=blocked["plan"]["plan_sha256"],
        )


@pytest.mark.asyncio
async def test_commit_and_deploy_group_runs_complete_workflow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Single-target workflow should commit, deploy, sync the Leader, and push in order."""
    state = _group_payload("fleet", product=ProductsCore.EDGE)
    harness = _Harness((ProductsCore.EDGE, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.EDGE,
        group="fleet",
        message="Tune Edge source",
        push=True,
    )
    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.EDGE,
        group="fleet",
        message="Tune Edge source",
        push=True,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "deployed"
    assert result["completed_steps"] == ["group_commit", "deploy", "leader_commit", "push"]
    assert harness.commit_order == ["fleet"]
    assert harness.deploy_order == ["fleet"]
    assert harness.push_count == 1


@pytest.mark.asyncio
async def test_commit_and_deploy_group_rechecks_leader_before_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Leader metadata drift after a group commit should stop before deployment."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    harness.dirty_leader_on_group_commit = True
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Guard Leader state",
    )
    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Guard Leader state",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "failed"
    assert result["completed_steps"] == ["group_commit"]
    assert "changed after planning" in result["error"]["message"]
    assert harness.deploy_order == []


@pytest.mark.asyncio
async def test_targeted_subfleet_blocks_until_parent_is_committed_and_deployed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A specific subfleet workflow should not leapfrog pending parent configuration."""
    parent = _group_payload("parent", product=ProductsCore.EDGE, local_changes=1)
    child = _group_payload("child", product=ProductsCore.EDGE, local_changes=1, inherits="parent")
    harness = _Harness((ProductsCore.EDGE, child), (ProductsCore.EDGE, parent))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.EDGE,
        group="child",
        message="Update one subfleet",
    )

    assert planned["plan"]["edge_ancestors"][0]["target"]["id"] == "parent"
    assert "pending configuration" in planned["plan"]["blocked_reasons"][0]
    with pytest.raises(ValueError, match="parent chain first"):
        await vc.commit_and_deploy_group(
            "test",
            product=ProductsCore.EDGE,
            group="child",
            message="Update one subfleet",
            dry_run=False,
            expected_plan_sha256=planned["plan"]["plan_sha256"],
        )


@pytest.mark.asyncio
async def test_commit_and_deploy_all_rechecks_descendants_and_deploys_parent_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All-target workflow should capture inherited changes and preserve Edge hierarchy order."""
    parent = _group_payload("parent", product=ProductsCore.EDGE, local_changes=1)
    child = _group_payload("child", product=ProductsCore.EDGE, local_changes=0, inherits="parent")
    grandchild = _group_payload("grandchild", product=ProductsCore.EDGE, local_changes=0, inherits="child")
    harness = _Harness(
        (ProductsCore.EDGE, grandchild),
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, parent),
    )
    harness.inherit_on_commit = {"parent": ["child"], "child": ["grandchild"]}
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all("test", message="Roll out inherited Edge settings", product="edge")
    result = await vc.commit_and_deploy_all(
        "test",
        message="Roll out inherited Edge settings",
        product="edge",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "completed"
    assert harness.commit_order == ["parent", "child", "grandchild"]
    assert harness.deploy_order == ["parent", "child", "grandchild"]
    assert result["leader_commit"]["status"] == "committed"
    assert all(item["control_plane_version_confirmed"] for item in result["deploy_results"])


@pytest.mark.asyncio
async def test_commit_and_deploy_all_stops_before_deploy_after_commit_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default all-target failure handling should avoid starting a partial deployment phase."""
    first = _group_payload("a", product=ProductsCore.STREAM)
    second = _group_payload("b", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, first), (ProductsCore.STREAM, second))
    harness.commit_error_for = "b"
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all("test", message="Stream rollout", product="stream")
    result = await vc.commit_and_deploy_all(
        "test",
        message="Stream rollout",
        product="stream",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "partial_failure"
    assert result["errors"][0]["phase"] == "commit"
    assert harness.commit_order == ["a"]
    assert harness.deploy_order == []


@pytest.mark.asyncio
async def test_commit_and_deploy_all_skips_descendants_after_parent_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Continue-on-error mode must keep failed Edge parents ahead of, and block, descendants."""
    parent = _group_payload("parent", product=ProductsCore.EDGE)
    child = _group_payload("child", product=ProductsCore.EDGE, inherits="parent")
    sibling = _group_payload("sibling", product=ProductsCore.EDGE)
    harness = _Harness(
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, sibling),
        (ProductsCore.EDGE, parent),
    )
    harness.commit_error_for = "parent"
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleets",
        product="edge",
        stop_on_error=False,
    )
    result = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleets",
        product="edge",
        stop_on_error=False,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    child_result = next(item for item in result["commit_results"] if item["target"]["id"] == "child")
    assert child_result["status"] == "skipped_dependency"
    assert child_result["blocked_by"] == "parent"
    assert harness.commit_order == ["sibling"]
    assert harness.deploy_order == ["sibling"]
    assert result["deploy_results"][0]["control_plane_version_confirmed"] is True


@pytest.mark.asyncio
async def test_commit_and_deploy_all_skips_descendant_deploy_after_parent_deploy_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An Edge parent deployment failure must block descendant deployments in continue mode."""
    parent = _group_payload("parent", product=ProductsCore.EDGE)
    child = _group_payload("child", product=ProductsCore.EDGE, inherits="parent")
    sibling = _group_payload("sibling", product=ProductsCore.EDGE)
    harness = _Harness(
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, sibling),
        (ProductsCore.EDGE, parent),
    )
    harness.deploy_error_for = "parent"
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleet deploys",
        product="edge",
        stop_on_error=False,
    )
    result = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleet deploys",
        product="edge",
        stop_on_error=False,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    child_result = next(item for item in result["deploy_results"] if item["target"]["id"] == "child")
    assert child_result["status"] == "skipped_dependency"
    assert child_result["blocked_by"] == "parent"
    assert harness.deploy_order == ["sibling"]


@pytest.mark.asyncio
async def test_push_config_git_preflight_and_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remote push should be review-gated and block unsafe remote states."""
    harness = _Harness()
    harness.global_ahead = 2
    _install_harness(monkeypatch, harness)

    planned = await vc.push_config_git("test")
    assert planned["plan"]["git_integration"]["remote"] == "https://git.example.test/cribl/config.git"
    result = await vc.push_config_git(
        "test",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == "pushed"

    harness.remote = False
    harness.global_ahead = 1
    blocked = await vc.push_config_git("test")
    with pytest.raises(ValueError, match="No remote Git repository"):
        await vc.push_config_git(
            "test",
            dry_run=False,
            expected_plan_sha256=blocked["plan"]["plan_sha256"],
        )

    harness.remote = "https://git.example.test/cribl/config.git"
    harness.versioning = False
    versioning_blocked = await vc.push_config_git("test")
    with pytest.raises(ValueError, match="versioning is disabled"):
        await vc.push_config_git(
            "test",
            dry_run=False,
            expected_plan_sha256=versioning_blocked["plan"]["plan_sha256"],
        )


@pytest.mark.asyncio
async def test_noop_paths_and_plan_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean and already deployed targets should return no-op results without mutations."""
    state = _group_payload(
        "default",
        product=ProductsCore.STREAM,
        committed="same",
        deployed="same",
        local_changes=0,
    )
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="No changes",
    )
    with pytest.raises(ValueError, match="required"):
        await vc.commit_and_deploy_group(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            message="No changes",
            dry_run=False,
        )
    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="No changes",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == "noop"
    assert harness.commit_order == []
    assert harness.deploy_order == []

    state["configVersion"] = "older"
    harness.remote = False
    commit_only_plan = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Do not deploy",
        push=True,
    )
    assert commit_only_plan["plan"]["action"] == "noop"
    assert commit_only_plan["plan"]["blocked_reasons"] == []
    assert commit_only_plan["plan"]["git_integration"] is None
    commit_only_result = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Do not deploy",
        push=True,
        dry_run=False,
        expected_plan_sha256=commit_only_plan["plan"]["plan_sha256"],
    )
    assert commit_only_result["status"] == "noop"

    push_plan = await vc.push_config_git("test")
    push_result = await vc.push_config_git(
        "test",
        dry_run=False,
        expected_plan_sha256=push_plan["plan"]["plan_sha256"],
    )
    assert push_result["status"] == "noop"
