# SNC Cribl MCP

[![Python](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Checked with pyright](https://microsoft.github.io/pyright/img/pyright_badge.svg)](https://microsoft.github.io/pyright/)
[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-green.svg)](https://opensource.org/licenses/MIT-0)

A Model Context Protocol (MCP) server that provides tools for querying Cribl deployments.

![SNC Cribl MCP Architecture](assets/explorer_map_infographic.png)

## Table of Contents

- [What It Does](#what-it-does)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Running the MCP Server](#running-the-mcp-server)
  - [Available MCP Tools](#available-mcp-tools)
  - [Example Integration with Claude](#example-integration-with-claude)
- [Project Structure](#project-structure)
- [Development](#development)
- [Authentication](#authentication)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## What It Does

This MCP server connects to Cribl Stream and Edge deployments to retrieve and compare metadata about leaders, worker groups, fleets, sources, destinations, pipelines, routes, variables, and Packs. It also supports targeted cross-leader copy and validation workflows for local users, group/fleet contents, and global system settings so AI assistants can help keep multiple leaders aligned without passing entire configs through context.

The server handles authentication with bearer tokens, manages token refresh automatically, and provides a clean JSON interface for exploring your Cribl infrastructure.

## Features

- **Comprehensive Discovery**: List all worker groups (Stream) and fleets (Edge) in your deployment.
- **Configuration Retrieval**:
  - Retrieve configured sources across all products and groups.
  - Retrieve configured destinations across all products and groups.
  - Retrieve configured pipelines across all products and groups, with full function configuration details.
  - Retrieve configured routes across all products and groups.
  - Retrieve configured event breakers across all products and groups.
  - Retrieve configured lookups across all products and groups.
  - Retrieve configured variables across all products and groups.
- **Edge Teleport Reads**:
  - Read or search files on Edge nodes through the leader-proxied `/w/{nodeId}` teleport API.
  - Resolve the leader from the three-letter datacenter token in hosts such as `cribl01.fra0`.
- **Pack Management**:
  - List and inspect installed Packs.
  - Install Packs from IDs, URLs, Git repositories, or previously uploaded Pack files.
  - Upload, upgrade, and uninstall Packs through the cribl-control-plane SDK.
- **Cross-Leader Sync Workflows**:
  - Copy supported resources between configured leaders.
  - Validate whether supported resources are in sync between configured leaders.
  - Resolve different source and target group selectors during copy and validation workflows.
  - Select config subsets by wildcard boolean expressions such as `oodp-* but not oodp-source-*`, regular expressions, and explicit exclude filters.
  - Dry-run copy workflows to inspect matched configs and planned create/update/append/skip actions before writing.
  - Create or replicate local users, using explicit or environment-sourced passwords because Cribl does not return passwords from the API.
  - Replicate and validate complete Stream worker groups or Edge fleets, including group/fleet settings, variables, event breakers, lookups, destinations, pipelines, sources, and routes.
  - Replicate and validate global system settings from the Global Settings page.
  - Validate and persist agent-generated manifests beneath the configured safe root without direct filesystem access.
  - Plan, apply, and semantically validate one strict YAML manifest across many configured leaders with bounded parallelism.
  - Snapshot each manifest source item once, emit per-target drift hashes, and require a durable apply receipt before commit/deploy.
- **Git-Safe Commit and Deployment Workflows**:
  - Inspect Git status and compare the current configuration with either the deployed version or the current group/fleet commit.
  - Commit or deploy one Stream worker group, Edge fleet, or subfleet, including controlled deployment of an existing commit for rollback.
  - Commit and deploy all selected targets, ordering Edge parents before descendants and re-evaluating inherited subfleet changes after each parent commit.
  - Push committed configuration to the Leader's configured Git remote with conflict, behind-branch, and drift preflights.
  - Preview every mutation as a dry-run plan and execute only with the matching plan digest.
  - Run reviewed mutations as non-blocking jobs so status and diff tools remain responsive during long deployments.
  - Persist jobs, progress, per-target failure detail, plans, and receipts in SQLite so interrupted manifest work can resume after restart.
  - Keep review and execution responses bounded with one capped changed-path preview, complete drift digests, and compact final results.
- **Typed Pipeline Models**: 41 Pydantic models for pipeline function configurations (eval, mask, sampling, regex_extract, etc.) with full type safety.
- **Typed Collector Models**: 9 Pydantic models for collector source configurations (S3, REST, database, Splunk, Azure Blob, GCS, filesystem, script, health check) with full type safety.
- **Graceful Error Handling**: SDK validation errors return structured, user-friendly responses with actionable guidance instead of crashing. Repeated errors with the same field and cause are collapsed into one counted entry.
- **Robust Authentication**: Automatic token management and refresh for customer-managed deployments.
- **FastMCP Integration**: Built with [FastMCP 3.x](https://gofastmcp.com) for easy integration with Claude and other AI assistants.
- **Quality Assurance**: Comprehensive unit test coverage with full typing support.

## Installation

**Prerequisites:**

- Python 3.14 or higher
- [uv](https://github.com/astral-sh/uv) package manager (required)
- Access to a Cribl deployment with valid credentials

The server is designed to run from a source checkout. It reads `config.toml` and optional `.env` values from the checkout root, so keep the checkout in place and point your MCP client at that directory.

**Install from source:**

```bash
git clone https://github.com/atree1023/snc-cribl-mcp.git
cd snc-cribl-mcp

# Optional once the release tag exists:
# git checkout v0.3.0

uv sync
cp config.example.toml config.toml
```

Edit `config.toml` with your Cribl leaders, then verify the server starts:

```bash
uv run snc-cribl-mcp
```

For MCP clients, use the checkout path directly with `uv run --directory`; see [Example Integration with Claude](#example-integration-with-claude).

## Configuration

Create a `config.toml` file in the project root with your Cribl server definitions:

```toml
[defaults]
verify_ssl = true
timeout_ms = 10_000
oauth_token_url = "https://login.cribl.cloud/oauth/token"
oauth_audience = "https://api.cribl.cloud"
# Optional; defaults to the manifests/ directory in this checkout.
manifest_root = "manifests"
# Optional for on-prem; defaults to snc-cribl-mcp:<server-name>.
# keychain_name = "shared-cribl-login"

[golden.oak]
url = "http://localhost:19000"
# Optional for on-prem; defaults to your local macOS user.
# username = "admin"
# Optional for on-prem; overrides the default Keychain service name.
# keychain_name = "golden-oak-login"

[cribl.cloud]
url = "https://<workspace>-<org>.cribl.cloud"
client_id = "your-client-id"
client_secret = "${CRIBL_CLOUD_SECRET}"
```

For on-prem servers, omit `password` to use the local credential chain:

1. Use the configured `username`, or default to the locally logged-in macOS user.
2. Read the password from the macOS Keychain via Python `keyring`, using service
   `keychain_name` when configured in `[defaults]` or the server section. If omitted, the service defaults to
   `snc-cribl-mcp:<server-name>` and the resolved username. For `[golden.oak]`, the default service is
   `snc-cribl-mcp:golden.oak`. A server-level `keychain_name` overrides `[defaults]`.
3. Fall back to per-server environment variables loaded from `.env` or your shell. For `[golden.oak]`,
   the resolver checks `SNC_CRIBL_MCP_GOLDEN_OAK_PASSWORD`, `CRIBL_GOLDEN_OAK_PASSWORD`,
   `GOLDEN_OAK_PASSWORD`, then `GOLDEN_OAK_PASS`.

To store a local Keychain password:

```bash
uv run keyring set snc-cribl-mcp:golden.oak "$(whoami)"
```

If you use `${VAR}` placeholders, set the values in a `.env` file (or your shell environment). Explicit
placeholder values still take precedence over keychain lookup and must exist when referenced.

When a tool call omits a server name, the first non-`[defaults]` section in `config.toml` is used. The
`get_edge_info` tool is more specific: when `server` is omitted, it extracts the three-letter datacenter token from
`edge_host` and selects the one configured leader whose section name or URL hostname contains that token. For example,
`cribl01.fra0` selects a leader with a section or URL containing `fra` or `fra0`.

Logging is still controlled via the `LOG_LEVEL` environment variable (default: `INFO`).
Manifest job state defaults to `.snc-cribl-mcp/state.sqlite3`; set `SNC_CRIBL_STATE_DATABASE` to use another durable
SQLite path. Set `SNC_CRIBL_MANIFEST_ROOT` to override `[defaults].manifest_root`. Manifests never expand environment
variables and may only be loaded from the configured root.

**Configuration Options:**

| Section      | Key               | Description                                                | Required |
| :----------- | :---------------- | :--------------------------------------------------------- | :------- |
| `[defaults]` | `verify_ssl`      | Verify SSL certificates                                    | No       |
| `[defaults]` | `timeout_ms`      | API request timeout in milliseconds                        | No       |
| `[defaults]` | `oauth_token_url` | OAuth token URL for Cribl.Cloud                            | No       |
| `[defaults]` | `oauth_audience`  | OAuth audience for Cribl.Cloud                             | No       |
| `[defaults]` | `keychain_name`   | Shared macOS Keychain service name for on-prem passwords   | No       |
| `[defaults]` | `manifest_root`   | Safe root for YAML configuration manifests                 | No       |
| `[server]`   | `url`             | Base URL of your Cribl deployment (auto-appends `/api/v1`) | Yes      |
| `[server]`   | `username`        | On-prem username; defaults to local macOS user             | No\*     |
| `[server]`   | `password`        | On-prem password; defaults to Keychain/env lookup          | No\*     |
| `[server]`   | `keychain_name`   | Per-server macOS Keychain service name override            | No       |
| `[server]`   | `client_id`       | Cribl.Cloud client ID                                      | Yes\*    |
| `[server]`   | `client_secret`   | Cribl.Cloud client secret                                  | Yes\*    |

\*Cribl.Cloud URLs (ending in `.cribl.cloud`) require `client_id`/`client_secret`. On-prem URLs ultimately require a
resolved username/password pair, but the password can come from macOS Keychain or a per-server environment fallback.

## Usage

### Running the MCP Server

Start the server directly:

```bash
uv run snc-cribl-mcp
```

Or using the Python module:

```bash
uv run python -m snc_cribl_mcp.server
```

### Available MCP Tools

The server exposes thirty-seven MCP tools, and also mirrors the read-oriented data as MCP resources (e.g., `cribl://groups`, `cribl://sources`, `cribl://destinations`, `cribl://pipelines`, `cribl://routes`, `cribl://breakers`, `cribl://lookups`, `cribl://variables`, `cribl://packs`):

#### `get_leader_overview`

Returns a compact operational overview for a configured Cribl leader.

- **Returns:** JSON containing leader health, Cribl version, Stream/Edge aggregate node counts, active worker groups and Edge fleets with node counts, and source/destination runtime health summaries for groups or fleets with nodes. Transient per-group network failures are retried with bounded backoff; exhaustion returns `transient_error`, retry metadata, and a non-empty exception type instead of a permanent `error` with a blank message.

#### `get_edge_info`

Reads or searches a file on an Edge node through the leader-proxied teleport API. Pass `edge_host` as a short host plus
datacenter label, such as `cribl01.fra0`, or as a full `service-now.com` FQDN. Pass `file` as an absolute Edge node path.
When `query` is empty or omitted, the tool reads file events from `offset`; when `query` is provided, it searches the
file. Search values containing punctuation are sent quoted to match the Edge UI behavior. The tool sends `et` and
`rulesets` in the teleport payload. For searches, `et` defaults to one hour ago; pass `earliest_time`,
`search_window_seconds`, or `rulesets` only when you need a different search window or need to replay a captured UI
request.

- **Returns:** JSON containing the selected leader, normalized Edge host, resolved node GUID, request details, `next_offset`, and the raw teleport file response.

#### `list_groups`

Lists all Stream worker groups and Edge fleets from your Cribl deployment.

- **Returns:** JSON containing groups organized by product (Stream and Edge), with metadata including group IDs, names, descriptions, and configuration.

#### `list_sources`

Lists all configured sources across all groups and products, including both regular sources (from `/system/inputs`) and collector sources (from `/lib/jobs`).

- **Returns:** JSON containing sources organized by product and group, including source IDs, types, and configurations. Collector sources (S3, REST, database, etc.) are merged with regular sources per group.

#### `list_destinations`

Lists all configured destinations across all groups and products.

- **Returns:** JSON containing destinations organized by product and group, including destination IDs, types, and configurations.

#### `list_pipelines`

Lists all configured pipelines across all groups and products.

- **Returns:** JSON containing pipelines organized by product and group, including pipeline IDs, names, and configurations.

#### `list_routes`

Lists all configured routes across all groups and products.

- **Returns:** JSON containing routes organized by product and group, including route IDs, names, filters, destinations, and referenced pipelines.

#### `list_breakers`

Lists all configured event breakers across all groups and products.

- **Returns:** JSON containing event breakers organized by product and group, including ruleset IDs, rules, and configurations.

#### `list_lookups`

Lists all configured lookups across all groups and products.

- **Returns:** JSON containing lookups organized by product and group, including lookup IDs, file info, and configurations.

#### `list_variables`

Lists all configured variables across all groups and products.

- **Returns:** JSON containing variables organized by product and group, including variable IDs and configurations.

#### `list_packs`

Lists installed Packs. Optionally pass `with_="inputs"`, `with_="outputs"`, `with_="collectors"`, or a comma-separated combination to include those counts in the same SDK request. For distributed environments, pass `product="stream"` or `product="edge"` and `group="<group id, name, or description>"` to scope the request to `/m/{group}`.

- **Returns:** JSON containing Pack IDs, sources, versions, metadata, and any requested counts.

#### `get_pack`

Gets one installed Pack by Pack ID. By default, this returns the Pack metadata plus a bounded summary of the Pack's sources, destinations, pipelines, routes, knowledge categories, and settings categories. Pass `kind` to drill into one concrete section or category, `object_id` to fetch one object, `detail="full"` to include raw payloads from that selected section/category, and `cursor`/`limit` to page that selected section/category.

- **Supported `kind` values:** `sources`, `destinations`, `pipelines`, `routes`, `knowledge`, `knowledge.lookups`, `knowledge.breakers`, `knowledge.parsers`, `knowledge.variables`, `knowledge.samples`, `knowledge.regexes`, `knowledge.grok`, `knowledge.schemas`, `knowledge.functions`, `knowledge.hmac_functions`, `knowledge.appscope_configs`, `knowledge.database_connections`, `settings`, `settings.system`, `settings.cribl`, `settings.conf`, `settings.auth`, `settings.git`.
- **Returns:** JSON containing Pack metadata and either section summaries or the requested Pack object details.
- **Distributed scope:** Supports the same optional `product` and `group` arguments as `list_packs`.

#### `install_pack`

Installs a Pack using the SDK Pack request body. The request can create an empty Pack by ID, install from a URL, install from a `git+` repository URL, or install from an uploaded Pack source returned by `upload_pack`.

- **Returns:** JSON containing installed Pack metadata and any warnings returned by Cribl.
- **Distributed scope:** Supports the same optional `product` and `group` arguments as `list_packs`.

#### `upload_pack`

Uploads a local `.crbl` Pack file.

- **Returns:** JSON containing the uploaded `source` value to pass to `install_pack`.
- **Distributed scope:** Supports the same optional `product` and `group` arguments as `list_packs`.

#### `update_pack`

Upgrades an installed Pack from a source URL or uploaded source ID.

- **Returns:** JSON containing the upgraded Pack metadata.
- **Distributed scope:** Supports the same optional `product` and `group` arguments as `list_packs`.

#### `delete_pack`

Uninstalls an installed Pack by Pack ID.

- **Returns:** JSON containing uninstall metadata returned by Cribl.
- **Distributed scope:** Supports the same optional `product` and `group` arguments as `list_packs`.

#### `get_config_objects`

Queries supported config objects through one bounded read tool: groups, sources, destinations, pipelines, routes, breakers, lookups, and variables.

- **Returns:** Compact summaries by default, including product, group, ID, type, enabled state, optional dependency references, truncation state, and a cursor for follow-up calls. Use `detail="full"` with filters such as `selector`, `product`, and `group_id` to retrieve selected payloads without flooding the MCP response. `selector` is case-insensitive; values containing `*`, `?`, or character classes use shell-style wildcard matching, while other values use substring matching.

#### `validate_config_objects`

Semantically compares groups, sources, destinations, pipelines, routes, breakers, lookups, or variables between two configured leaders.

- **Returns:** Functional validation results that classify differences as blocking functional drift, non-blocking environment identity differences, or volatile metadata differences. Hostnames, endpoint server lists, generated IDs, credential references, and timestamps are reported but do not count as functional drift.
- **Subset matching:** Use `item_pattern`, `item_regex`, `exclude_item_pattern`, `exclude_item_regex`, and `case_sensitive` to validate selected config IDs without first listing every object.

#### `copy_resource_config`

Copies groups, sources, destinations, pipelines, routes, breakers, lookups, or variables from one configured leader to another.

- **Returns:** Dry-run plans describe would-create, would-update, would-append, skip, unsupported, and failed actions and include a content-addressed `plan_sha256`. Semantically identical targets are skipped without an API write; real updates include bounded added, changed, and removed config-path summaries so YAML key-order normalization cannot hide functional drift. Execution results report the matching `executed_plan_sha256` plus created, updated, appended, skipped, unsupported, and failed items. For group-scoped resources, both responses include the requested selectors and resolved group IDs.
- **Safe execution:** The tool defaults to `dry_run=true`. Review the plan, then pass its exact `plan_sha256` as `expected_plan_sha256` with `dry_run=false`. Source or target config drift causes execution to stop before any write.
- **Subset matching:** Use `item_pattern` for wildcard boolean selectors like `oodp-* but not oodp-source-*`, `item_regex` for regex selectors, and the explicit exclude filters to plan or copy only selected IDs.
- **Post-copy validation:** Batch copies re-list the target scope after all writes and compare the same list representation used by `validate_resource_sync` and `validate_config_objects`, avoiding false drift from list-versus-detail response differences.

#### `validate_resource_sync`

Compares groups, sources, destinations, pipelines, routes, breakers, lookups, or variables between two configured leaders.

- **Returns:** JSON describing whether the selected item or scope is in sync, along with per-item status and differing paths. For group-scoped resources, the response includes both the requested source and target group selectors and the resolved group IDs used on each leader.
- **Subset matching:** Use the same `item_pattern`, `item_regex`, exclude filters, and `case_sensitive` controls as `copy_resource_config`.

#### `sync_user`

Creates or replicates a local Cribl user on a target leader. When `source_server` is provided, profile fields and roles are copied from the source leader.

- **Password handling:** Cribl does not return user passwords from the API, so pass `password`, pass `password_env`, or provide one of the automatic `.env`/environment fallbacks such as `SNC_CRIBL_MCP_<TARGET_SERVER>_<USERNAME>_PASSWORD`, `CRIBL_USER_<USERNAME>_PASSWORD`, or `<USERNAME>_PASSWORD`.
- **Transport note:** For on-prem leaders configured with `http://` URLs, password create/update requests are sent over cleartext HTTP. Use HTTPS for production user sync.
- **Returns:** JSON describing whether the target user was created, updated, skipped, or validated. Password values are never returned.

#### `replicate_group_config`

Replicates a complete Stream worker group or Edge fleet between configured leaders.

- **Includes:** Group/fleet settings plus variables, event breakers, lookups, destinations, pipelines, sources, and routes by default.
- **Returns:** JSON describing each replicated section and optional post-copy validation.

#### `validate_group_config`

Validates a complete Stream worker group or Edge fleet between configured leaders.

- **Returns:** JSON with group/fleet setting status and per-section sync status for variables, event breakers, lookups, destinations, pipelines, sources, and routes.

#### `replicate_system_settings`

Replicates global Cribl system settings from one configured leader to another.

- **Returns:** JSON describing whether settings were updated, skipped, and optionally validated.

#### `validate_system_settings`

Validates global Cribl system settings between two configured leaders.

- **Returns:** JSON with an in-sync flag and differing setting paths. Use `include_payloads=true` when the raw source and target setting payloads are needed.

#### `write_manifest`

Validates agent-generated YAML against the strict schema and writes it beneath `manifest_root`, closing the workflow for
sandboxed MCP clients that cannot write files directly. The returned `manifest_path` feeds the other manifest tools.
Identical writes are idempotent; replacing different content requires `overwrite=true`. A name without an extension gets
`.yaml` automatically, while absolute/path-traversal escapes and non-YAML extensions are rejected.

#### `delete_manifest`

Deletes a validated manifest beneath `manifest_root` after rollout cleanup. Pass the prior `file_sha256` as
`expected_file_sha256` to refuse deletion when the file changed after inspection. Durable plans, receipts, and job history
are retained.

#### `replicate_config_manifest`

Plans or applies explicit group-scoped resources from one source leader to every target in a strict YAML manifest.

- **Safe input:** Manifests are limited to the configured manifest root, 1 MiB, schema version 1, configured server names, explicit item IDs, and known fields. Duplicate YAML keys, aliases, inline config payloads, environment expansion, duplicate targets, and duplicate group/kind sections are rejected.
- **Efficient fan-out:** Source objects are resolved and snapshotted once, then targets run concurrently (manifest `options.concurrency` by default, explicit tool override when supplied; maximum 10). Each target remains internally ordered as variables, breakers, lookups, destinations, pipelines, sources, then routes.
- **Safe execution:** Dry-run returns `intent_sha256`, aggregate `plan_sha256`, a `target_plan_sha256` for each leader, bounded item identities for every action bucket, and the dependency-aware `apply_order`. Execution requires the aggregate hash, revalidates each target independently with a visible `revalidated` counter, skips or aborts on drift, and never executes a target with preflight blockers.
- **Returns:** Execution immediately returns a durable `job_id`. Progress uses `unit: items`, counts item work across all targets, and reports active target slots plus the effective concurrency. Drift skips produce `partial_skip` and `skipped_targets`, distinct from real failures. The final bounded result includes an `apply_receipt_sha256`; target detail is retrieved with `get_config_deployment_job(job_id, target)`.

#### `validate_config_manifest`

Semantically validates every manifest item across all targets in parallel. Hostnames, endpoints, generated identities,
credential references, and volatile metadata are counted but non-blocking; functional differences and missing items fail
the affected target. Per-target summaries split `create`, `update`, `noop`, and `unsupported`. Difference detail is pageable
with `offset` and `limit`; use `target` to inspect one leader and `detail_scope="all"` to page every item, including noops.

#### `check_manifest_receipt_validity`

Checks whether an apply receipt still matches the current manifest and each guarded group/fleet pending diff without
committing or deploying. Provide exactly one of `apply_job_id` or `apply_receipt_sha256`; use `target` for one leader.

#### `commit_and_deploy_manifest`

Commits and deploys a prior manifest application across its successful target leaders.

- **Receipt gate:** Requires either the replication `apply_job_id` or `apply_receipt_sha256`. Every group diff must still match the durable post-apply receipt before planning and again before execution.
- **Scope:** Commits only manifest groups. For Edge, affected descendants are included and processed parent-first so inherited changes are committed and deployed safely.
- **Review contract:** Dry-run and execution use a separate commit/deploy `plan_sha256`, keeping replication approval distinct from deployment approval. Plans expose ordered per-fleet actions, `push_action`, and Leader blocker paths. Targets run concurrently, while each leader's hierarchy remains serialized.
- **Progress and outcomes:** Progress uses `unit: fleets` and reports the current leader, product, fleet, and phase while preserving parent-before-child order. `on_drift="skip"` applies to receipt, group/fleet, and Leader `groups.yml` blockers; skipped leaders produce `partial_skip`, not `partial_failure`. `push=false` is carried through both plan and execution and is guarded against an unexpected inner push request.

#### `get_group_git_status`

Reports Git and deployment state for one or all Stream worker groups and Edge fleets/subfleets.

- **Returns:** Branch and ahead/behind state, conflicts, committed and deployed versions, and current rollout node counts. Changed paths are capped at 25 entries and include `changed_count`, `changed_paths_truncated`, and a digest of the complete path set.

#### `get_group_git_diff`

Shows the configuration diff for one Stream worker group or Edge fleet/subfleet.

- **Baselines:** `compare_to="deployed"` validates the complete pending deployment against the active `configVersion`; `compare_to="head"` shows only uncommitted changes.
- **Returns:** A bounded diff plus a digest of the complete pending diff. Use `filename` to inspect one file or `diff_line_limit=0` for the full diff.

#### `get_leader_git_diff`

Shows the Leader-scoped `local/cribl/groups.yml` diff that records deployed group/fleet versions. Use it when a plan is
blocked by pre-existing Leader deployment metadata; group-scoped diff tools intentionally cannot expose this file.

#### `get_config_deployment_job`

Polls an asynchronous manifest replication, commit, deploy, or Git push execution.

- **With `job_id`:** Returns queued/running/completed/failed/interrupted state, aggregate progress, and the bounded final result when available. Generic pollers must inspect `progress.unit`: replication uses `items`, while manifest commit/deploy uses `fleets`. Add `target` for durable per-target detail; a known target that has not started returns `status: pending` rather than an error.
- **Without `job_id`:** Lists recent jobs without embedding every final result.
- **Lifetime:** Jobs and resumable request metadata are retained in SQLite across MCP process restarts. A previously running job is restored as `interrupted`; pass it as `resume_job_id` with the exact original parameters to retry unfinished targets.

#### `commit_group_config`

Commits pending changes for one group/fleet without deploying. An optional `files` list restricts the commit, `effective=true` includes inherited Edge configuration, and `push=true` pushes after a successful commit.

#### `deploy_group_config`

Deploys an explicit existing commit to one group/fleet, enabling a controlled rollback as well as forward deployment. The workflow then commits the resulting Leader deployment metadata and can optionally push it.

#### `commit_and_deploy_group`

Commits and deploys one group/fleet. If its working tree is clean but its current commit is not deployed, the current commit is deployed without creating an empty commit. A targeted Edge subfleet is blocked while any ancestor has pending configuration, preserving parent-first deployment order.

#### `commit_and_deploy_all`

Commits all selected targets before deploying them. Edge parents are processed before descendants, each descendant is re-evaluated after its parent commit, and Leader deployment metadata is committed once after successful deployments. A clean descendant whose effective configuration will change because an ancestor is committed is planned as `deploy_inherited`, so the reviewed plan includes the full deployment blast radius. Use `product="stream"`, `product="edge"`, or `product="all"` to set the scope.

#### `push_config_git`

Pushes already committed Leader configuration to the configured remote. Preflight rejects a missing remote, unresolved conflicts, or a local branch behind its remote.

All version-control and manifest mutation tools default to `dry_run=true`. Review the plan and diff, then pass the returned `plan_sha256` as `expected_plan_sha256` with `dry_run=false`. The execution call returns an accepted `job_id` immediately; poll `get_config_deployment_job` for completion. Mutations are serialized per configured server while read-only tools remain responsive. `copy_resource_config` uses the same review-and-confirm contract but executes synchronously.

Plans contain a single 25-path preview plus digests over the complete path set and pending diff. Final results omit full plans, diffs, deployment objects, and changed-path arrays; they retain the executed plan digest, action/status, pre-commit-diff line counts, file counts, deployed versions, rollout aggregates, push status, and recovery details. Use `get_group_git_diff` for file-level drill-down. A successful deployment confirms the Leader's active `configVersion`; use the returned rollout counts or a later status call to confirm that every worker or Edge node has converged. The installed Cribl SDK does not expose a failed-node aggregate, so `rollout.failed` remains `null` unless a future API response provides it.

### Example Integration with Claude

Add this server to your Claude desktop app configuration. Use an absolute path to the source checkout that contains `config.toml`:

```json
{
  "mcpServers": {
    "snc-cribl-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/absolute/path/to/snc-cribl-mcp",
        "snc-cribl-mcp"
      ],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## Project Structure

```text
snc_cribl_mcp/
├── src/snc_cribl_mcp/     # Main package (src-layout)
│   ├── client/           # Cribl client and token management
│   │   ├── cribl_client.py   # Control plane client factory
│   │   └── token_manager.py  # Bearer token lifecycle management
│   ├── models/           # Pydantic models for Cribl data structures
│   │   ├── collectors.py     # Typed models for 9 collector source types
│   │   └── pipeline_functions.py  # Typed models for 41 pipeline function types
│   ├── operations/       # Core business logic
│   │   ├── common.py         # Shared utilities and generic collectors
│   │   ├── groups.py         # Group collection and serialization
│   │   ├── sources.py        # Source collection helpers
│   │   ├── destinations.py   # Destination collection helpers
│   │   ├── pipelines.py      # Pipeline collection helpers
│   │   ├── routes.py         # Route collection helpers
│   │   ├── breakers.py       # Event breaker collection helpers
│   │   ├── lookups.py        # Lookup collection helpers
│   │   ├── variables.py      # Variable collection helpers
│   │   ├── users.py          # Local user create/replicate helpers
│   │   ├── group_sync.py     # Whole group/fleet copy and validation helpers
│   │   ├── version_control.py # Group/fleet Git commit, deployment, and push workflows
│   │   ├── version_control_jobs.py # Non-blocking mutation execution and polling
│   │   ├── system_settings.py # Global system setting sync helpers
│   │   ├── packs.py          # Top-level Pack management helpers
│   │   ├── config_objects.py # Consolidated config object response shaping
│   │   ├── resource_actions.py  # Context-free CRUD helpers over the SDK
│   │   ├── semantic_diff.py  # Functional vs environment identity comparison
│   │   ├── sync.py           # Cross-leader copy and validation helpers
│   │   └── validation_errors.py  # SDK validation error handling
│   ├── tools/            # MCP tool registrations
│   │   ├── common.py         # Shared tool registration utilities
│   │   ├── copy_resource_config.py
│   │   ├── list_groups.py
│   │   ├── list_sources.py
│   │   ├── list_destinations.py
│   │   ├── list_pipelines.py
│   │   ├── list_routes.py
│   │   ├── list_breakers.py
│   │   ├── list_lookups.py
│   │   ├── list_variables.py
│   │   ├── users.py
│   │   ├── group_sync.py
│   │   ├── version_control.py
│   │   ├── system_settings.py
│   │   ├── packs.py
│   │   ├── get_config_objects.py
│   │   ├── validate_config_objects.py
│   │   ├── sync_common.py
│   │   └── validate_resource_sync.py
│   ├── config.py         # Configuration management
│   ├── prompts.py        # MCP prompt definitions
│   ├── resources.py      # MCP resource definitions
│   └── server.py         # FastMCP app entry point
├── tests/
│   └── unit/             # Unit tests with pytest
├── docs/                 # Additional documentation
├── pyproject.toml        # Project dependencies and tool config
└── .env                  # Local configuration (not committed)
```

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/snc_cribl_mcp

# Run specific test file
uv run pytest tests/unit/test_server.py
```

### Code Quality

```bash
# Type checking
uv run pyright

# Linting and formatting
uv run ruff check
uv run ruff format
```

### Adding a New Tool

1. Create the implementation logic in `src/snc_cribl_mcp/operations/`.
2. Create a new tool file in `src/snc_cribl_mcp/tools/` following the existing pattern.
3. Register the tool in `src/snc_cribl_mcp/server.py` in the `_register_capabilities()` function.
4. Add corresponding tests in `tests/unit/`.

## Authentication

The server retrieves bearer tokens automatically based on the configured server type:

- **Cribl.Cloud**: Uses OAuth client credentials (`client_id`/`client_secret`) and refreshes tokens automatically.
- **On-prem**: Uses a resolved `username`/`password` pair to fetch bearer tokens, defaulting to the local macOS user and
  macOS Keychain before falling back to per-server environment variables. It refreshes using the JWT `exp` claim when
  available.

Tokens expire based on your Cribl settings (default: 1 hour on-prem, 24 hours on Cribl.Cloud). For production use, configure TLS and use HTTPS.

## Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Make your changes and add tests.
4. Run the test suite (`uv run pytest`).
5. Run type checking and linting (`uv run pyright && uv run ruff check`).
6. Commit your changes with a descriptive message.
7. Push to your branch (`git push origin feature/amazing-feature`).
8. Open a Pull Request.

Please ensure all tests pass and maintain code coverage before submitting a PR.

## License

This project is licensed under the MIT No Attribution License (MIT-0). See the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or feature requests, please open an issue in the repository.
