#!/usr/bin/env python3
"""
Split functions.json into individual files based on the 'id' parameter.

The functions.json file can be obtained from the Cribl API `/api/v1/m/<groupName>/functions` endpoint.
"""

import json
from pathlib import Path
from typing import Any, cast


def split_functions() -> None:
    """Read functions.json and split each function into individual files.

    Reads the 'items' array from functions.json, filters out internal functions
    (those with group='_internal_'), and writes each remaining function's id and
    schema to a separate JSON file named after the function id.
    """
    # Read the functions.json file
    functions_path = Path(__file__).parent / "functions.json"
    with functions_path.open() as f:
        raw_data: object = json.load(f)

    # Extract the items array from the JSON object
    if not isinstance(raw_data, dict) or "items" not in raw_data:
        print("Error: functions.json does not contain a JSON object with 'items' array")
        return

    data = cast(dict[str, object], raw_data)
    items = data["items"]

    if not isinstance(items, list):
        print("Error: 'items' is not an array")
        return

    functions = cast(list[dict[str, Any]], items)

    print(f"Found {len(functions)} functions to process")

    # Create individual files for each function
    created_count = 0
    skipped_internal = 0

    for function in functions:
        if "id" not in function:
            print(f"Warning: Skipping object without 'id' field: {function}")
            continue

        # Skip objects with group="_internal_"
        if function.get("group") == "_internal_":
            skipped_internal += 1
            continue

        function_id: str = function["id"]
        output_path = functions_path.parent / f"{function_id}.json"

        # Create output with only id and schema fields
        output: dict[str, Any] = {"id": function["id"]}

        # Include schema if it exists
        if "schema" in function:
            output["schema"] = function["schema"]

        with output_path.open("w") as f:
            json.dump(output, f, indent=2)

        print(f"Created {output_path.name}")
        created_count += 1

    print(f"\nSuccessfully created {created_count} files")
    if skipped_internal > 0:
        print(f"Skipped {skipped_internal} internal functions")


if __name__ == "__main__":
    split_functions()
