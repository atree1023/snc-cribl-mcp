#!/usr/bin/env python3
"""
Split collectors.json into individual files based on the 'id' parameter.

The collectors.json file can be obtained from the Cribl API `/api/v1/m/<groupName>/collectors` endpoint.
"""

import json
from pathlib import Path
from typing import Any, cast


def split_collectors() -> None:
    """Read collectors.json and split each collector into individual files.

    Reads the 'items' array from collectors.json, filters out internal collectors
    (those with group='_internal_'), and writes each remaining collector's id and
    schema to a separate JSON file named after the collector id.
    """
    # Read the collectors.json file
    collectors_path = Path(__file__).parent / "collectors.json"
    with collectors_path.open() as f:
        raw_data: object = json.load(f)

    # Extract the items array from the JSON object
    if not isinstance(raw_data, dict) or "items" not in raw_data:
        print("Error: collectors.json does not contain a JSON object with 'items' array")
        return

    data = cast(dict[str, object], raw_data)
    items = data["items"]

    if not isinstance(items, list):
        print("Error: 'items' is not an array")
        return

    collectors = cast(list[dict[str, Any]], items)

    print(f"Found {len(collectors)} collectors to process")

    # Create individual files for each collector
    created_count = 0
    skipped_internal = 0

    for collector in collectors:
        if "id" not in collector:
            print(f"Warning: Skipping object without 'id' field: {collector}")
            continue

        # Skip objects with group="_internal_"
        if collector.get("group") == "_internal_":
            skipped_internal += 1
            continue

        collector_id: str = collector["id"]
        output_path = collectors_path.parent / f"{collector_id}.json"

        # Create output with only id and schema fields
        output: dict[str, Any] = {"id": collector["id"]}

        # Include schema if it exists
        if "schema" in collector:
            output["schema"] = collector["schema"]

        with output_path.open("w") as f:
            json.dump(output, f, indent=2)

        print(f"Created {output_path.name}")
        created_count += 1

    print(f"\nSuccessfully created {created_count} files")
    if skipped_internal > 0:
        print(f"Skipped {skipped_internal} internal collectors")


if __name__ == "__main__":
    split_collectors()
