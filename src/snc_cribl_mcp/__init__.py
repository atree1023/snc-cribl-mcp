"""SNC Cribl MCP Server package.

This package contains the FastMCP server and tools for interacting with
customer-managed Cribl deployments.
"""

# Intentionally do not re-export symbols from submodules to avoid importing
# heavy dependencies and triggering environment validation at package import
# time. Individual modules (e.g., ``server``) should be imported directly by
# consumers as needed.

__all__: list[str] = []
