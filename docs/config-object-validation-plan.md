# Config Object Validation Plan

This plan validates the consolidated config object tooling without requiring destructive changes to any Cribl leader.

## Mock Client Validation

Run these checks after code changes:

```bash
uv run pytest tests/unit/test_config_objects.py tests/unit/test_semantic_diff.py --no-cov
uv run pytest tests/unit/test_get_config_objects_tool.py tests/unit/test_validate_config_objects_tool.py --no-cov
uv run pytest
```

The unit tests cover:

- Bounded config object summaries with cursors.
- Full payload retrieval when a selector narrows the result.
- Dependency extraction for sources and routes.
- Semantic comparison that treats hostnames, endpoint lists, generated IDs, and volatile metadata as non-blocking.
- Functional drift detection for pipeline behavior.
- Tool wiring for `get_config_objects` and `validate_config_objects`.

## Dev Leader Smoke Validation

Use configured server names from `config.toml`; do not paste credentials into commands or logs.

1. Confirm the MCP server starts:

   ```bash
   uv run snc-cribl-mcp
   ```

2. From an MCP client, call `get_config_objects` against each dev leader:

   ```json
   {
     "kind": "pipelines",
     "server": "<dev-server-name>",
     "product": "stream",
     "detail": "summary",
     "limit": 25
   }
   ```

3. Verify large result handling:
   - `returned_count` is less than or equal to `limit`.
   - `truncated` is `true` when more records exist.
   - `next_cursor` can be passed into a follow-up call.

4. Verify dependency extraction:

   ```json
   {
     "kind": "routes",
     "server": "<dev-server-name>",
     "product": "stream",
     "group_id": "<group-selector>",
     "detail": "refs",
     "include_dependencies": true
   }
   ```

   Confirm route records report referenced `pipelines` and `destinations`.

5. Verify semantic validation between two leaders:

   ```json
   {
     "resource_kind": "destinations",
     "source_server": "<source-dev-server>",
     "target_server": "<target-dev-server>",
     "source_group": "<source-group-selector>",
     "target_group": "<target-group-selector>",
     "product": "stream"
   }
   ```

   Expected behavior:
   - Hostname, endpoint list, generated ID, and volatile metadata differences appear under `identity_differences` or `volatile_differences`.
   - Pipeline logic, route filters, enabled state, and source/destination type differences appear under `functional_differences`.
   - `semantic_in_sync` is `true` only when all returned items are functionally equivalent.

## Safety Boundaries

- `get_config_objects` and `validate_config_objects` are read-only.
- The existing `copy_resource_config` tool remains the mutating path.
- Future replication planning should run as a dry-run plan before any apply tool is added or invoked.
