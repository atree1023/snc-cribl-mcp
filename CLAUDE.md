# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP server exposing Cribl deployment metadata through tools. Uses FastMCP 2 and the cribl-control-plane SDK.

**Key components:**

- Seven tools: list_groups, list_sources, list_destinations, list_pipelines, list_routes, list_breakers, list_lookups
- Seven resources mirroring tools (cribl://groups, cribl://sources, etc.)
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
- For `cribl-control-plane` SDK: check `docs/examples/` for authentication and API patterns
- For FastMCP: use web search tools to get latest documentation from gofastmcp.com
- For pipeline functions: reference `docs/pipeline_functions/<id>.json` schemas
- For collectors: reference `docs/collectors/<id>.json` schemas

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
- On-prem URLs require `username`/`password`.
- `${VAR}` placeholders in `config.toml` expand using `.env` or environment variables.
- Logging remains controlled via the `LOG_LEVEL` environment variable.

## File Locations

When you need to find something:

- **Tool definitions**: `src/snc_cribl_mcp/tools/list_*.py`
- **API logic**: `src/snc_cribl_mcp/operations/*.py`
- **Pydantic models**: `src/snc_cribl_mcp/models/`
- **SDK examples**: `docs/examples/`
- **Function schemas**: `docs/pipeline_functions/<id>.json`
- **Collector schemas**: `docs/collectors/<id>.json`
- **Tests**: `tests/unit/test_*.py`
