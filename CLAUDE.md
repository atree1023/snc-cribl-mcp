# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP server exposing Cribl deployment metadata through tools. Uses FastMCP 3 and the cribl-control-plane SDK.

**Key components:**

- Seventeen tools: list_groups, list_sources, list_destinations, list_pipelines, list_routes, list_breakers, list_lookups, list_packs, get_pack, install_pack, upload_pack, update_pack, delete_pack, get_config_objects, validate_config_objects, copy_resource_config, validate_resource_sync
- Eight resources mirroring read-oriented tools (cribl://groups, cribl://sources, cribl://destinations, cribl://pipelines, cribl://routes, cribl://breakers, cribl://lookups, cribl://packs)
- Four prompts for common Cribl workflows
- Token-based authentication with automatic refresh

## Before Making Changes

**Always do these first:**

1. Run `uv run ruff check` to see current lint status
2. Run `uv run pyright` to see current type errors
3. Run `uv run pytest` to establish baseline test status
4. Read the specific module you're modifying and its tests

**When working with external libraries:**

- Inspect the actual installed package in `.venv/` rather than relying on memory
- For `cribl-control-plane` SDK: check `docs/CRIBL-CONTROL-PLANE-README.md` for examples, documentation and best practices
- For endpoints where the SDK does not have a dedicated function, consult the [Cribl API reference](https://docs.cribl.io/api/) or place a local OpenAPI spec at `docs/cribl-apidocs-4.17.1-b862732f.yml` (gitignored; download from Cribl)
- For FastMCP: Check `docs/fastmcp-llms.txt` for links to latest documentation from gofastmcp.com

## Commands

```bash
# Development
uv run snc-cribl-mcp                       # run server via console script
uv run python -m snc_cribl_mcp.server      # run server via module

# Testing (run in this order before committing)
uv run pytest                              # all tests
uv run pytest tests/unit/test_server.py   # single file
uv run pytest --cov=src/snc_cribl_mcp     # with coverage report

# Quality (run all three before committing)
uv run ruff format                         # format first
uv run ruff check --fix                    # then fix lint issues
uv run pyright                             # then type check
```

## Architecture Decisions

**Why three layers?**

- **Client** (`client/`): Isolates authentication complexity; token refresh happens here
- **Operations** (`operations/`): Contains all Cribl API logic; makes testing easier
- **Tools** (`tools/`): Thin wrappers that register MCP tools; keeps FastMCP coupling minimal

**Why two collection patterns?**

- `collect_items_via_sdk`: Use when SDK method exists and returns complete data
- `collect_items_via_http`: Use when SDK method is missing OR when SDK validation drops fields

**Why `extra="allow"` on Pydantic models?**

- Cribl adds fields frequently; strict validation would break on API upgrades
- We preserve unknown fields for forward compatibility

**Per-group scoping:**

- Distributed Cribl requires `/m/{group_id}/` in URLs
- Always pass `server_url=f"{base}/m/{group_id}"` to SDK client factory
- Pack tools support both leader-level and distributed use. When `group` is provided, resolve it against the requested `product` (`stream` or `edge`) and pass `server_url=f"{base}/m/{resolved_group_id}"` to the SDK Pack methods.
- `get_pack` is the single Pack inspection surface: without `kind`, it returns a bounded summary of Pack metadata, sources, destinations, pipelines, routes, settings, and knowledge; with `kind`, `object_id`, and `detail`, it drills into a Pack section or object.
- Prefer SDK Pack subresources for `sources`, `destinations`, `pipelines`, and `routes`; use read-only direct HTTP against `/p/{pack}/...` for Pack knowledge/settings categories that are missing from the installed SDK.

**Consolidated config object tooling:**

- `get_config_objects` is the preferred read path for broad queries because it returns bounded summaries, cursors, and optional dependency references.
- `validate_config_objects` wraps the existing sync validation path with semantic comparison so environment identity differences are visible but non-blocking.
- Keep using SDK-backed collectors when available; use direct HTTP collectors for unsupported SDK endpoints such as breakers and lookups.
- Semantic validation should preserve target-local identity values such as hostnames, endpoint server lists, generated IDs, credential references, and volatile metadata.

## Adding a New Tool

Follow this checklist:

1. **Create operations function** in `src/snc_cribl_mcp/operations/<resource>.py`
   - Make it async
   - Accept: client factory, product, timeout_ms, ctx
   - Return: list of serialized items or error response dict

2. **Create tool registration** in `src/snc_cribl_mcp/tools/list_<resource>.py`
   - Import `ToolConfig` and `generic_list_tool` from `tools/common.py`
   - Define `register(app, deps)` function using `@app.tool()` decorator
   - Reference `tools/list_sources.py` as the canonical example

3. **Register the tool** in `src/snc_cribl_mcp/server.py`
   - Add import in the tools section
   - Call `register()` in `_register_capabilities()`

4. **Add tests** in `tests/unit/test_<resource>.py`
   - Test successful collection with mocked HTTP responses
   - Test error handling (validation errors, timeouts)
   - Test edge cases (empty responses, missing fields)

5. **Verify before committing:**

   ```bash
   uv run ruff format && uv run ruff check --fix && uv run pyright && uv run pytest
   ```

## Error Handling Patterns

**SDK validation errors** (when API response doesn't match SDK schema):

- Caught in `collect_items_via_sdk()` and `collect_items_via_http()`
- Returns structured dict with `status: "validation_error"`, affected object info
- Never raises to caller; always returns gracefully

**Authentication errors:**

- TokenManager handles refresh automatically
- If token refresh fails, operation fails with clear error message

**Timeout handling:**

- All operations accept `timeout_ms` parameter
- Default: 10000ms (from `config.toml` defaults or per-server overrides)

## Testing Patterns

- Use `pytest-asyncio` (mode=auto configured in pyproject.toml)
- Use `pytest-httpx` to mock all Cribl API calls
- Never make real HTTP calls in tests
- Place tests in `tests/unit/test_<module>.py` mirroring source structure

**Example mock pattern:**

```python
@pytest.mark.asyncio
async def test_collect_sources(httpx_mock):
    httpx_mock.add_response(
        url="https://cribl.example.com/api/v1/m/default/system/inputs",
        json={"items": [{"id": "syslog:in_syslog", "type": "syslog"}]}
    )
    # ... test logic
```

## Configuration

Configuration file (`config.toml`) loaded by `src/snc_cribl_mcp/config.py`:

- `config.toml` must live at the repository root.
- `[defaults]` provides shared values that are overridden per server section.
- Each server section name (for example, `[golden.oak]`) is the server name used in tool calls.
- When no server is provided, the first non-`[defaults]` section is used as the default.
- `url` is used as the base URL and auto-appends `/api/v1` if missing.
- Cribl.Cloud URLs (ending in `.cribl.cloud`) require `client_id`/`client_secret`.
- On-prem URLs ultimately require a resolved `username`/`password`, but `username` defaults to the local macOS user and
  `password` defaults to the configured `keychain_name` from `[defaults]` or the server section before per-server env
  fallbacks such as `GOLDEN_OAK_PASS`. If `keychain_name` is omitted, the macOS Keychain service defaults to
  `snc-cribl-mcp:<server-name>`.
- `${VAR}` placeholders in `config.toml` expand using `.env` or environment variables and take precedence when set
  explicitly.
- Logging remains controlled via the `LOG_LEVEL` environment variable.

## File Locations

When you need to find something:

- **Tool definitions**: `src/snc_cribl_mcp/tools/list_*.py`
- **API logic**: `src/snc_cribl_mcp/operations/*.py`
- **Pydantic models**: `src/snc_cribl_mcp/models/`
- **SDK examples**: `docs/CRIBL-CONTROL-PLANE-README.md`
- **Tests**: `tests/unit/test_*.py`
