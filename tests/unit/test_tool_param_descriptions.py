"""Tool parameter documentation reaches MCP clients."""

from fastmcp import Client

from snc_cribl_mcp.server import app


async def test_every_tool_parameter_has_a_description() -> None:
    """The JSON schema is the only parameter documentation a client model sees."""
    async with Client(app) as client:
        tools = await client.list_tools()

    undescribed = [
        f"{tool.name}.{name}"
        for tool in tools
        for name, schema in tool.input_schema.get("properties", {}).items()
        if not schema.get("description")
    ]
    assert undescribed == []
