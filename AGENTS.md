# SNC Cribl MCP

MCP server providing tools to query Cribl Stream and Edge deployments. Uses FastMCP 3 and the cribl-control-plane SDK.

> **For Claude Code users:** See `CLAUDE.md` for detailed guidance on architecture decisions, workflows, and patterns.

## Quick Start

```bash
uv sync                                    # install dependencies
uv run snc-cribl-mcp                       # run server
uv run pytest                              # run tests
```

## Dev Environment

- **Package manager:** uv
- **Virtual env:** `.venv/` (created by `uv sync`)
- **Entry point:** `src/snc_cribl_mcp/server.py`
- **Python version:** 3.14+

## Build & Test

```bash
# Tests
uv run pytest                             # all tests
uv run pytest --cov=src/snc_cribl_mcp     # with coverage
uv run pytest tests/unit/test_server.py   # specific file

# Quality checks (run all before committing)
uv run ruff format                         # format
uv run ruff check --fix                    # lint and auto-fix
uv run pyright                             # type check
```

## Code Style

- Python 3.14+ with complete type hints
- Ruff: line length 128 (see `pyproject.toml` for full config)
- Pyright: strict mode
- Docstrings: Google style
- Async/await for all I/O operations
- Pydantic for data models

## Documentation Resources

Before writing code:

1. **Cribl SDK:** Check `docs/CRIBL-SDK-README.md` for examples, documentation and best practices
2. **Cribl API:** Refer to the [Cribl API reference](https://docs.cribl.io/cribl-as-code/api/) for available endpoints (prefer SDK over direct calls); if you need a local OpenAPI spec, download it from Cribl and place it at `docs/cribl-openapi-spec.yml` (gitignored)
3. **Cribl:** Check `docs/cribl-llms.txt` for product documentation links and use fetch/search to retrieve details
4. **FastMCP:** Check `docs/fastmcp-llms.txt` for links to latest docs from gofastmcp.com
5. **All:** Use the Context7 and Exa tools to search for the latest library documentation and examples
6. **All:** Inspect the installed packages in `.venv/` rather than relying on memory

**Critical SDK notes:**

- "On-prem", "onprem", and "customer managed" are equivalent terms
- Distributed environments require `/m/{group_id}/` URL scoping
- Pack management tools support distributed scoping with `product` plus `group`; resolve the group selector before calling SDK Pack methods with `server_url`.

## File Structure

```text
src/snc_cribl_mcp/
├── server.py              # FastMCP app, entry point
├── config.py              # Environment config loading
├── prompts.py             # MCP prompt definitions
├── resources.py           # MCP resource definitions
├── client/                # Token management, client factory
├── models/                # Pydantic models (collectors, pipeline functions)
├── operations/            # Business logic for Cribl API
└── tools/                 # MCP tool registrations

tests/unit/                # pytest tests
docs/                      # SDK docs, schemas, examples
```

## MCP Capabilities

**Tools:** get_leader_overview, get_edge_info, list_groups, list_sources, list_destinations, list_pipelines, list_routes, list_breakers, list_lookups, list_variables, list_packs, get_pack, install_pack, upload_pack, update_pack, delete_pack, get_config_objects, validate_config_objects, copy_resource_config, validate_resource_sync, sync_user, replicate_group_config, validate_group_config, replicate_system_settings, validate_system_settings

**Resources:** cribl://groups, cribl://sources, cribl://destinations, cribl://pipelines, cribl://routes, cribl://breakers, cribl://lookups, cribl://variables, cribl://packs

**Prompts:** Summarize Cribl Configuration, Find Broken Sources, Analyze Pipeline, Troubleshoot Destination

**Subset sync:** `copy_resource_config`, `validate_resource_sync`, and `validate_config_objects` support item ID filters with `item_pattern` wildcard boolean expressions such as `oodp-* but not oodp-source-*`, `item_regex`, exclude filters, and `case_sensitive`. Use `dry_run=true` on copy calls to inspect matched configs and planned actions before writing.

## Common Workflows

### Add New Tool

1. Create `src/snc_cribl_mcp/operations/<resource>.py`
2. Create `src/snc_cribl_mcp/tools/list_<resource>.py` (follow `list_sources.py` pattern)
3. Register in `server.py` `_register_capabilities()`
4. Add `tests/unit/test_<resource>.py`
5. Run: `uv run ruff format && uv run ruff check --fix && uv run pyright && uv run pytest`

### Update Dependencies

```bash
uv add package-name           # runtime dependency
uv add --dev package-name     # dev dependency
uv sync                       # sync lockfile
```

## Definition of Done

- [ ] All tests pass (`uv run pytest`)
- [ ] Type check passes (`uv run pyright`)
- [ ] Lint passes (`uv run ruff check`)
- [ ] Test coverage ≥80%
- [ ] Docstrings reflect implementation
- [ ] README.md/CLAUDE.md/AGENTS.md updated if needed
