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
- SDK 0.11 paginated list responses carry counted collections under `response.result`; shared response helpers must accept wrapped and legacy direct counted shapes, exhaust `response.next()`, and reject unknown shapes instead of returning silent empty results.
- Keep `cribl-control-plane` constrained to the validated `>=0.11.0,<0.12` line; the SDK is a Preview feature and generated minor releases can contain breaking model and response changes.
- `copy_resource_config` defaults to `dry_run=true` and requires the returned `plan_sha256` as `expected_plan_sha256` for exposed execution. Its drift digest excludes runtime-only status metadata while preserving write-relevant config state. Semantically identical targets are skipped; real updates include bounded added/changed/removed config-path summaries.
- Version-control mutations default to `dry_run=true` and require the returned `plan_sha256` as `expected_plan_sha256` for execution. Group/fleet commits and diffs are scoped under `/m/{group_id}`; deploy an immutable commit and then commit only `local/cribl/groups.yml` at Leader scope.
- Mutation execution returns a durable `job_id`; poll `get_config_deployment_job` for its bounded final result or add `target` for per-target detail. Targets that have not started return `pending`. SQLite-backed jobs survive process restarts as `interrupted`, run off the MCP event loop, and are serialized per configured server so status/diff reads remain responsive.
- Multi-leader manifests are strict schema-1 YAML loaded only beneath `manifest_root`. `write_manifest` validates and persists agent-generated YAML; `delete_manifest` performs digest-guarded cleanup. Replication plans expose bounded item identities and dependency order; execution reports item-level progress plus revalidation counters and separates skipped from failed targets. `validate_config_manifest` has pageable difference/all-item detail with create/update/noop splits and treats environment identity drift as non-blocking. `check_manifest_receipt_validity` provides read-only receipt preflight. `commit_and_deploy_manifest` requires a durable apply receipt, includes affected Edge descendants, reports fleet-level progress, and applies drift skip policy to Leader blockers.
- Review plans return one capped changed-path preview and complete drift digests. Mutation results must not return full plans, diffs, path arrays, or raw SDK commit/deployment payloads.
- Commit/deploy-all workflows must process Edge parents before descendants, plan clean descendants of an ancestor commit as `deploy_inherited`, and re-evaluate each descendant after its parent commit so inherited changes are captured. Commit line counts must come from the reviewed pre-commit diff because SDK 0.11 commit summaries can lose deletions. Treat node rollout convergence as a follow-up status check, not part of the completed job's deployment guarantee.
- Targeted Edge subfleet mutations must preflight the ancestor chain and block while any parent has uncommitted or undeployed configuration.

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

**Tools:** get_leader_overview, get_edge_info, list_groups, list_sources, list_destinations, list_pipelines, list_routes, list_breakers, list_lookups, list_variables, list_packs, get_pack, install_pack, upload_pack, update_pack, delete_pack, get_config_objects, validate_config_objects, copy_resource_config, validate_resource_sync, sync_user, replicate_group_config, validate_group_config, replicate_system_settings, validate_system_settings, write_manifest, delete_manifest, replicate_config_manifest, validate_config_manifest, check_manifest_receipt_validity, commit_and_deploy_manifest, get_group_git_status, get_group_git_diff, get_leader_git_diff, get_config_deployment_job, commit_group_config, deploy_group_config, commit_and_deploy_group, commit_and_deploy_all, push_config_git

**Resources:** cribl://groups, cribl://sources, cribl://destinations, cribl://pipelines, cribl://routes, cribl://breakers, cribl://lookups, cribl://variables, cribl://packs

**Prompts:** Summarize Cribl Configuration, Find Broken Sources, Analyze Pipeline, Troubleshoot Destination

**Subset sync:** `copy_resource_config`, `validate_resource_sync`, and `validate_config_objects` support item ID filters with `item_pattern` wildcard boolean expressions such as `oodp-* but not oodp-source-*`, `item_regex`, exclude filters, and `case_sensitive`. Copy calls default to `dry_run=true`; return the exact `plan_sha256` as `expected_plan_sha256` with `dry_run=false` to execute.

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
