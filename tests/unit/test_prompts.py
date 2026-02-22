"""Unit tests for MCP prompts."""

import pytest
from fastmcp import FastMCP
from fastmcp.prompts import Message

from snc_cribl_mcp import prompts


def _message_text(message: Message) -> str:
    """Extract normalized text content from a prompt message."""
    text = getattr(message.content, "text", None)
    return text if isinstance(text, str) else str(message.content)


@pytest.mark.asyncio
async def test_register_prompts() -> None:
    """Test that prompts are registered with the app."""
    app = FastMCP("test")
    prompts.register(app)

    registered_prompts = [prompt.name for prompt in await app.list_prompts()]

    assert "Summarize Cribl Configuration" in registered_prompts
    assert "Find Broken Sources" in registered_prompts
    assert "Analyze Pipeline" in registered_prompts
    assert "Troubleshoot Destination" in registered_prompts


@pytest.mark.asyncio
async def test_summarize_config_prompt() -> None:
    """Test the summarize config prompt returns expected content."""
    app = FastMCP("test")
    prompts.register(app)

    result = await app.render_prompt("Summarize Cribl Configuration", {})

    assert len(result.messages) == 1
    assert isinstance(result.messages[0], Message)
    content = _message_text(result.messages[0])
    assert "summarize" in content.lower()
    assert "worker groups" in content.lower()


@pytest.mark.asyncio
async def test_find_broken_sources_prompt() -> None:
    """Test the find broken sources prompt returns expected content."""
    app = FastMCP("test")
    prompts.register(app)

    result = await app.render_prompt("Find Broken Sources", {})

    assert len(result.messages) == 1
    assert isinstance(result.messages[0], Message)
    content = _message_text(result.messages[0])
    assert "sources" in content.lower()
    assert "list_sources" in content


@pytest.mark.asyncio
async def test_analyze_pipeline_prompt() -> None:
    """Test the analyze pipeline prompt returns expected content."""
    app = FastMCP("test")
    prompts.register(app)

    result = await app.render_prompt("Analyze Pipeline", {"pipeline_id": "main", "group_id": "default"})

    assert len(result.messages) == 1
    assert isinstance(result.messages[0], Message)
    content = _message_text(result.messages[0])
    assert "main" in content
    assert "default" in content
    assert "list_pipelines" in content


@pytest.mark.asyncio
async def test_analyze_pipeline_prompt_custom_group() -> None:
    """Test the analyze pipeline prompt with a custom group."""
    app = FastMCP("test")
    prompts.register(app)

    result = await app.render_prompt("Analyze Pipeline", {"pipeline_id": "custom_pipe", "group_id": "custom_group"})

    assert len(result.messages) == 1
    assert isinstance(result.messages[0], Message)
    content = _message_text(result.messages[0])
    assert "custom_pipe" in content
    assert "custom_group" in content


@pytest.mark.asyncio
async def test_troubleshoot_destination_prompt_without_error() -> None:
    """Test the troubleshoot destination prompt without error message."""
    app = FastMCP("test")
    prompts.register(app)

    result = await app.render_prompt("Troubleshoot Destination", {"destination_id": "splunk_hec", "error_message": ""})

    assert len(result.messages) == 1
    assert isinstance(result.messages[0], Message)
    content = _message_text(result.messages[0])
    assert "splunk_hec" in content
    assert "list_destinations" in content


@pytest.mark.asyncio
async def test_troubleshoot_destination_prompt_with_error() -> None:
    """Test the troubleshoot destination prompt with error message."""
    app = FastMCP("test")
    prompts.register(app)

    result = await app.render_prompt(
        "Troubleshoot Destination",
        {"destination_id": "s3_bucket", "error_message": "Connection timed out"},
    )

    assert len(result.messages) == 1
    assert isinstance(result.messages[0], Message)
    content = _message_text(result.messages[0])
    assert "s3_bucket" in content
    assert "Connection timed out" in content
    assert "list_destinations" in content
