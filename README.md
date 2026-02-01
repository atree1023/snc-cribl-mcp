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

This MCP server connects to Cribl Stream and Edge deployments to retrieve metadata about worker groups, fleets, sources, destinations, pipelines, and routes. It's designed to work with customer-managed (on-premise) Cribl deployments and exposes structured data through MCP tools that can be consumed by AI assistants like Claude.

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
- **Typed Pipeline Models**: 41 Pydantic models for pipeline function configurations (eval, mask, sampling, regex_extract, etc.) with full type safety.
- **Typed Collector Models**: 9 Pydantic models for collector source configurations (S3, REST, database, Splunk, Azure Blob, GCS, filesystem, script, health check) with full type safety.
- **Graceful Error Handling**: SDK validation errors return structured, user-friendly responses with actionable guidance instead of crashing.
- **Robust Authentication**: Automatic token management and refresh for customer-managed deployments.
- **FastMCP Integration**: Built with [FastMCP 2.0](https://gofastmcp.com) for easy integration with Claude and other AI assistants.
- **Quality Assurance**: Comprehensive unit test coverage with full typing support.

## Installation

**Prerequisites:**

- Python 3.14 or higher
- [uv](https://github.com/astral-sh/uv) package manager (required)
- Access to a Cribl deployment with valid credentials

**Steps:**

```bash
# Clone the repository
git clone <repository-url>
cd snc_cribl_mcp

# Install dependencies using uv
uv sync
```

## Configuration

Create a `config.toml` file in the project root with your Cribl server definitions:

```toml
[defaults]
verify_ssl = true
timeout_ms = 10_000
oauth_token_url = "https://login.cribl.cloud/oauth/token"
oauth_audience = "https://api.cribl.cloud"

[golden.oak]
url = "http://localhost:19000"
username = "admin"
password = "${GOLDEN_OAK_PASS}"

[cribl.cloud]
url = "https://<workspace>-<org>.cribl.cloud"
client_id = "your-client-id"
client_secret = "${CRIBL_CLOUD_SECRET}"
```

If you use `${VAR}` placeholders, set the values in a `.env` file (or your shell environment). Only placeholder
expansion uses environment variables; configuration values are otherwise read directly from `config.toml`.

When a tool call omits a server name, the first non-`[defaults]` section in `config.toml` is used.

Logging is still controlled via the `LOG_LEVEL` environment variable (default: `INFO`).

**Configuration Options:**

| Section      | Key               | Description                                                | Required |
| :----------- | :---------------- | :--------------------------------------------------------- | :------- |
| `[defaults]` | `verify_ssl`      | Verify SSL certificates                                    | No       |
| `[defaults]` | `timeout_ms`      | API request timeout in milliseconds                        | No       |
| `[defaults]` | `oauth_token_url` | OAuth token URL for Cribl.Cloud                            | No       |
| `[defaults]` | `oauth_audience`  | OAuth audience for Cribl.Cloud                             | No       |
| `[server]`   | `url`             | Base URL of your Cribl deployment (auto-appends `/api/v1`) | Yes      |
| `[server]`   | `username`        | On-prem username                                           | Yes\*    |
| `[server]`   | `password`        | On-prem password                                           | Yes\*    |
| `[server]`   | `client_id`       | Cribl.Cloud client ID                                      | Yes\*    |
| `[server]`   | `client_secret`   | Cribl.Cloud client secret                                  | Yes\*    |

\*Cribl.Cloud URLs (ending in `.cribl.cloud`) require `client_id`/`client_secret`. On-prem URLs require
`username`/`password`.

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

The server exposes seven MCP tools, and also mirrors the same data as MCP resources (e.g., `cribl://groups`, `cribl://sources`, `cribl://destinations`, `cribl://pipelines`, `cribl://routes`, `cribl://breakers`, `cribl://lookups`):

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

### Example Integration with Claude

Add this server to your Claude desktop app configuration:

```json
{
  "mcpServers": {
    "snc-cribl-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "path-to-project-directory",
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
│   │   └── validation_errors.py  # SDK validation error handling
│   ├── tools/            # MCP tool registrations
│   │   ├── common.py         # Shared tool registration utilities
│   │   ├── list_groups.py
│   │   ├── list_sources.py
│   │   ├── list_destinations.py
│   │   ├── list_pipelines.py
│   │   ├── list_routes.py
│   │   ├── list_breakers.py
│   │   └── list_lookups.py
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
- **On-prem**: Uses `username`/`password` to fetch bearer tokens and refreshes using the JWT `exp` claim when available.

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
