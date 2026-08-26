"""Tests for semantic config object comparison."""

from typing import Any

from snc_cribl_mcp.operations.semantic_diff import compare_config_objects, semantic_validation_from_sync_result


def test_compare_config_objects_treats_identity_and_volatile_differences_as_non_blocking() -> None:
    """Environment identity and volatile metadata should not block equivalence."""
    source = {
        "id": "splunk:hec",
        "type": "splunk_hec",
        "servers": ["splunk-phx-1.example.com:8088"],
        "url": "https://cribl-ldr.phx.example.com/api/v1",
        "updated": "2026-05-01T00:00:00Z",
        "conf": {"maxBatchSize": 500},
    }
    target = {
        "id": "splunk:hec-aus",
        "type": "splunk_hec",
        "servers": ["splunk-aus-1.example.com:8088"],
        "url": "https://cribl-ldr.aus.example.com/api/v1",
        "updated": "2026-05-08T00:00:00Z",
        "conf": {"maxBatchSize": 500},
    }

    result = compare_config_objects("destinations", source, target)

    assert result["status"] == "functionally_equivalent"
    assert result["functional_differences"] == []
    assert {difference["path"] for difference in result["identity_differences"]} == {
        "id",
        "servers[0]",
        "url",
    }
    assert result["volatile_differences"] == [
        {
            "path": "updated",
            "reason": "volatile metadata",
        }
    ]


def test_compare_config_objects_reports_pipeline_behavior_as_functional_difference() -> None:
    """Pipeline behavior changes should be reported as functional drift."""
    source = {
        "id": "parse_firewall",
        "conf": {
            "functions": [
                {
                    "id": "eval",
                    "filter": "true",
                    "conf": {"add": [{"name": "site", "value": "'phx'"}]},
                }
            ]
        },
    }
    target = {
        "id": "parse_firewall_copy",
        "conf": {
            "functions": [
                {
                    "id": "eval",
                    "filter": "true",
                    "conf": {"add": [{"name": "site", "value": "'aus'"}]},
                }
            ]
        },
    }

    result = compare_config_objects("pipelines", source, target)

    assert result["status"] == "functional_difference"
    assert result["identity_differences"] == [
        {
            "path": "id",
            "reason": "object identity",
        }
    ]
    assert result["functional_differences"] == [
        {
            "path": "conf.functions[0].conf.add[0].value",
            "reason": "functional configuration",
        }
    ]


def test_compare_config_objects_treats_generated_route_ids_as_identity_only() -> None:
    """Generated route IDs should not make equivalent route tables fail."""
    source = {
        "id": "default",
        "routes": [
            {
                "id": "route-phx-123",
                "name": "firewall",
                "filter": "__inputId.startsWith('syslog')",
                "pipeline": "parse_firewall",
                "output": "splunk:firewall",
            }
        ],
    }
    target = {
        "id": "default",
        "routes": [
            {
                "id": "route-aus-456",
                "name": "firewall",
                "filter": "__inputId.startsWith('syslog')",
                "pipeline": "parse_firewall",
                "output": "splunk:firewall",
            }
        ],
    }

    result = compare_config_objects("routes", source, target)

    assert result["status"] == "functionally_equivalent"
    assert result["functional_differences"] == []
    assert result["identity_differences"] == [
        {
            "path": "routes[0].id",
            "reason": "object identity",
        }
    ]


def test_compare_config_objects_treats_function_ids_as_functional() -> None:
    """Pipeline function IDs are behavior, not generated object identity."""
    source: dict[str, Any] = {"conf": {"functions": [{"id": "eval", "conf": {}}]}}
    target: dict[str, Any] = {"conf": {"functions": [{"id": "mask", "conf": {}}]}}

    result = compare_config_objects("pipelines", source, target)

    assert result["status"] == "functional_difference"
    assert result["functional_differences"] == [
        {
            "path": "conf.functions[0].id",
            "reason": "functional configuration",
        }
    ]
    assert result["identity_differences"] == []


def test_compare_config_objects_classifies_tls_identity_and_list_length() -> None:
    """Credential references and endpoint list lengths should be reported separately."""
    source: dict[str, Any] = {
        "tls": {"certPath": "/opt/cribl/source.pem"},
        "servers": ["one.example.com"],
    }
    target: dict[str, Any] = {
        "tls": {"certPath": "/opt/cribl/target.pem"},
        "servers": ["one.example.com", "two.example.com"],
    }

    result = compare_config_objects("destinations", source, target)

    assert result["status"] == "functional_difference"
    assert result["functional_differences"] == [
        {
            "path": "servers.length",
            "reason": "functional configuration",
        }
    ]
    assert result["identity_differences"] == [
        {
            "path": "tls.certPath",
            "reason": "environment credential reference",
        },
    ]


def test_compare_config_objects_caps_large_dict_diffs() -> None:
    """Large object diffs should be capped at the configured maximum."""
    source: dict[str, Any] = {f"key_{index:03d}": index for index in range(101)}
    target: dict[str, Any] = {}

    result = compare_config_objects("lookups", source, target)

    assert result["difference_count"] == 100
    assert len(result["functional_differences"]) == 100


def test_compare_config_objects_caps_large_list_diffs() -> None:
    """Large list diffs should also stop walking once the cap is reached."""
    source = {"values": list(range(101))}
    target = {"values": list(range(101, 202))}

    result = compare_config_objects("lookups", source, target)

    assert result["difference_count"] == 100
    assert result["functional_differences"][-1] == {
        "path": "values[99]",
        "reason": "functional configuration",
    }


def test_semantic_validation_from_sync_result_handles_items_without_payloads() -> None:
    """Sync items without payloads should retain their availability status."""
    result = semantic_validation_from_sync_result(
        "sources",
        {
            "resource_kind": "sources",
            "in_sync": False,
            "counts": {"different": 1},
            "items": [
                {"item_id": "in_sync", "status": "in_sync"},
                {"item_id": "changed", "status": "different"},
                "not-an-item",
            ],
        },
    )

    assert result["semantic_in_sync"] is False
    assert result["semantic_counts"] == {
        "functionally_equivalent": 1,
        "functional_difference": 0,
        "missing_on_source": 0,
        "missing_on_target": 0,
        "missing": 0,
        "not_evaluated": 1,
        "unavailable": 0,
    }
    assert result["items"][0]["semantic_status"] == "functionally_equivalent"
    assert result["items"][1] == {
        "item_id": "changed",
        "sync_status": "different",
        "semantic_status": "not_evaluated",
        "functional_differences": [],
        "identity_differences": [],
        "volatile_differences": [],
        "warnings": ["Source and target payloads were not available for semantic comparison."],
    }


def test_semantic_validation_trusts_explicit_in_sync_result() -> None:
    """An explicit in_sync result should remain semantically in sync even without item details."""
    result = semantic_validation_from_sync_result(
        "sources",
        {
            "resource_kind": "sources",
            "in_sync": True,
            "items": [],
        },
    )

    assert result["semantic_in_sync"] is True


def test_semantic_validation_from_sync_result_is_not_in_sync_when_omitted_items_may_differ() -> None:
    """Truncated validation output should not report semantic equivalence from returned items only."""
    result = semantic_validation_from_sync_result(
        "sources",
        {
            "resource_kind": "sources",
            "in_sync": False,
            "response_truncated": True,
            "returned_item_count": 1,
            "omitted_item_count": 2,
            "items": [
                {
                    "item_id": "returned",
                    "status": "different",
                    "source": {"id": "returned", "host": "phx"},
                    "target": {"id": "returned-aus", "host": "aus"},
                }
            ],
        },
    )

    assert result["semantic_in_sync"] is False
    assert result["semantic_evaluation_complete"] is False
    assert result["warnings"] == [
        "Semantic validation was incomplete because 2 item result(s) were omitted from the sync response."
    ]
