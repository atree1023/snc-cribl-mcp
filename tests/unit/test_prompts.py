"""Unit tests for MCP prompts."""

# pyright: reportPrivateUsage=false

from fastmcp import FastMCP

from snc_cribl_mcp import prompts


def test_register_prompts() -> None:
    """Test that prompts are registered with the app."""
    app = FastMCP("test")
    prompts.register(app)

    # Verify prompts are registered via the internal manager
    registered_prompts = list(app._prompt_manager._prompts.keys())

    assert "Summarize Cribl Configuration" in registered_prompts
    assert "Find Broken Sources" in registered_prompts
    assert "Analyze Pipeline" in registered_prompts
    assert "Troubleshoot Destination" in registered_prompts


def test_summarize_config_prompt() -> None:
    """Test the summarize config prompt returns expected content."""
    app = FastMCP("test")
    prompts.register(app)

    prompt_fn = app._prompt_manager._prompts["Summarize Cribl Configuration"]
    result = prompt_fn.fn()  # type: ignore[reportUnknownMemberType]

    assert isinstance(result, str)
    assert "summarize" in result.lower()
    assert "worker groups" in result.lower()


def test_find_broken_sources_prompt() -> None:
    """Test the find broken sources prompt returns expected content."""
    app = FastMCP("test")
    prompts.register(app)

    prompt_fn = app._prompt_manager._prompts["Find Broken Sources"]
    result = prompt_fn.fn()  # type: ignore[reportUnknownMemberType]

    assert isinstance(result, str)
    assert "sources" in result.lower()
    assert "list_sources" in result


def test_analyze_pipeline_prompt() -> None:
    """Test the analyze pipeline prompt returns expected content."""
    app = FastMCP("test")
    prompts.register(app)

    prompt_fn = app._prompt_manager._prompts["Analyze Pipeline"]
    # Call with required and default arguments
    result = prompt_fn.fn(pipeline_id="main", group_id="default")  # type: ignore[reportUnknownMemberType]

    assert isinstance(result, str)
    assert "main" in result
    assert "default" in result
    assert "list_pipelines" in result


def test_analyze_pipeline_prompt_custom_group() -> None:
    """Test the analyze pipeline prompt with a custom group."""
    app = FastMCP("test")
    prompts.register(app)

    prompt_fn = app._prompt_manager._prompts["Analyze Pipeline"]
    result = prompt_fn.fn(pipeline_id="custom_pipe", group_id="custom_group")  # type: ignore[reportUnknownMemberType]

    assert isinstance(result, str)
    assert "custom_pipe" in result
    assert "custom_group" in result


def test_troubleshoot_destination_prompt_without_error() -> None:
    """Test the troubleshoot destination prompt without error message."""
    app = FastMCP("test")
    prompts.register(app)

    prompt_fn = app._prompt_manager._prompts["Troubleshoot Destination"]
    result = prompt_fn.fn(destination_id="splunk_hec", error_message="")  # type: ignore[reportUnknownMemberType]

    assert isinstance(result, str)
    assert "splunk_hec" in result
    assert "list_destinations" in result


def test_troubleshoot_destination_prompt_with_error() -> None:
    """Test the troubleshoot destination prompt with error message."""
    app = FastMCP("test")
    prompts.register(app)

    prompt_fn = app._prompt_manager._prompts["Troubleshoot Destination"]
    result = prompt_fn.fn(destination_id="s3_bucket", error_message="Connection timed out")  # type: ignore[reportUnknownMemberType]

    assert isinstance(result, str)
    assert "s3_bucket" in result
    assert "Connection timed out" in result
    assert "list_destinations" in result
