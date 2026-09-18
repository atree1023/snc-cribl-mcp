"""Tests for durable manifest plan and receipt storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from snc_cribl_mcp.operations.manifest_state import ManifestStateStore


def test_plans_and_receipts_survive_store_restart(tmp_path: Path) -> None:
    """Reviewed hashes and apply receipts must survive an MCP process restart."""
    path = tmp_path / "state.sqlite3"
    first = ManifestStateStore(path)
    first.save_plan(
        plan_sha256="plan-1",
        operation="replicate_config_manifest",
        intent_sha256="intent-1",
        manifest_path="wave.yaml",
        created_at="now",
        payload={"plan_sha256": "plan-1", "targets": []},
    )
    first.save_receipt(
        receipt_sha256="receipt-1",
        job_id="job-1",
        intent_sha256="intent-1",
        manifest_path="wave.yaml",
        created_at="later",
        payload={"receipt_sha256": "receipt-1", "targets": {}},
    )

    restored = ManifestStateStore(path)
    assert restored.get_plan("plan-1", operation="replicate_config_manifest")["targets"] == []
    assert restored.get_receipt(job_id="job-1")["receipt_sha256"] == "receipt-1"
    assert restored.get_receipt(receipt_sha256="receipt-1")["targets"] == {}

    with pytest.raises(ValueError, match="belongs to operation"):
        restored.get_plan("plan-1", operation="commit_and_deploy_manifest")
    with pytest.raises(ValueError, match="apply_receipt_sha256 or apply_job_id"):
        restored.get_receipt()
    with pytest.raises(ValueError, match="Unknown"):
        restored.get_plan("missing")


def test_latest_receipt_requires_same_path_and_source_intent(tmp_path: Path) -> None:
    """New plans must never adopt another manifest's or source snapshot's writes."""
    store = ManifestStateStore(tmp_path / "state.sqlite3")
    assert store.latest_receipt(manifest_path="wave.yaml", intent_sha256="intent") is None
    for index, (path, intent) in enumerate(
        [("wave.yaml", "intent"), ("wave.yaml", "intent"), ("wave.yaml", "changed-source"), ("other.yaml", "intent")]
    ):
        store.save_receipt(
            receipt_sha256=f"receipt-{index}",
            job_id=f"job-{index}",
            intent_sha256=intent,
            manifest_path=path,
            created_at="same-timestamp",
            payload={"receipt_sha256": f"receipt-{index}"},
        )
    store.close()
    assert store.latest_receipt(manifest_path="wave.yaml", intent_sha256="intent") == {"receipt_sha256": "receipt-1"}
    assert store.latest_receipt(manifest_path="wave.yaml", intent_sha256="missing") is None
