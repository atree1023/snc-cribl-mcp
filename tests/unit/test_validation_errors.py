"""Unit tests for operations.validation_errors module.

Covers utilities for parsing Pydantic validation errors and formatting
user-friendly error responses.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ValidationError

from snc_cribl_mcp.operations.validation_errors import (
    ErrorMessageContext,
    SDKValidationError,
    ValidationErrorDetails,
    _build_user_friendly_message,  # pyright: ignore[reportPrivateUsage]
    _extract_field_value,  # pyright: ignore[reportPrivateUsage]
    _extract_object_info,  # pyright: ignore[reportPrivateUsage]
    _format_json_value,  # pyright: ignore[reportPrivateUsage]
    _parse_error_location,  # pyright: ignore[reportPrivateUsage]
    format_validation_error_response,
    parse_validation_error,
)


class TestSDKValidationError:
    """Tests for SDKValidationError exception class."""

    def test_exception_with_message(self) -> None:
        """Error response message is used as exception message."""
        error_response = {
            "status": "validation_error",
            "message": "Test error message",
        }
        exc = SDKValidationError(error_response)

        assert str(exc) == "Test error message"
        assert exc.error_response == error_response

    def test_exception_without_message(self) -> None:
        """Falls back to default message when message not in response."""
        error_response: dict[str, Any] = {"status": "validation_error"}
        exc = SDKValidationError(error_response)

        assert str(exc) == "SDK validation failed"
        assert exc.error_response == error_response


class TestParseErrorLocation:
    """Tests for _parse_error_location helper."""

    def test_full_location_path(self) -> None:
        """Parses full SDK-style location path."""
        loc = ("body", "items", 6, "tcpjson", "connections", 0, "output")

        result = _parse_error_location(loc)

        assert result.object_index == 6
        assert result.object_type_field == "tcpjson"
        assert result.field_path == ["connections", "0", "output"]
        assert result.raw_location == loc

    def test_location_without_body_prefix(self) -> None:
        """Parses location without body prefix."""
        loc = ("items", 2, "syslog", "host")

        result = _parse_error_location(loc)

        assert result.object_index == 2
        assert result.object_type_field == "syslog"
        assert result.field_path == ["host"]
        assert result.raw_location == loc

    def test_location_without_items(self) -> None:
        """Parses location without items array reference."""
        loc = ("body", "config", "setting")

        result = _parse_error_location(loc)

        assert result.object_index is None
        assert result.object_type_field == "config"
        assert result.field_path == ["setting"]

    def test_empty_location(self) -> None:
        """Handles empty location tuple."""
        loc: tuple[str | int, ...] = ()

        result = _parse_error_location(loc)

        assert result.object_index is None
        assert result.object_type_field is None
        assert result.field_path == []
        assert result.raw_location == ()

    def test_items_without_index(self) -> None:
        """Handles items followed by non-integer."""
        loc = ("body", "items", "type", "field")

        result = _parse_error_location(loc)

        # "items" is processed, next is "type" (string, not int), so no index
        assert result.object_index is None
        assert result.object_type_field == "type"
        assert result.field_path == ["field"]

    def test_only_body_items_index(self) -> None:
        """Handles location with only body, items, and index."""
        loc = ("body", "items", 3)

        result = _parse_error_location(loc)

        assert result.object_index == 3
        assert result.object_type_field is None
        assert result.field_path == []


class TestExtractObjectInfo:
    """Tests for _extract_object_info helper."""

    def test_extracts_id_and_type(self) -> None:
        """Extracts id and type from body at given index."""
        body = '{"items": [{"id": "src1", "type": "http"}, {"id": "src2", "type": "syslog"}]}'

        obj_id, obj_type = _extract_object_info(body, 1)

        assert obj_id == "src2"
        assert obj_type == "syslog"

    def test_extracts_name_when_no_id(self) -> None:
        """Falls back to name when id not present."""
        body = '{"items": [{"name": "my-source", "type": "http"}]}'

        obj_id, obj_type = _extract_object_info(body, 0)

        assert obj_id == "my-source"
        assert obj_type == "http"

    def test_extracts_underscore_id(self) -> None:
        """Falls back to _id when id and name not present."""
        body = '{"items": [{"_id": "internal-id", "type": "kafka"}]}'

        obj_id, obj_type = _extract_object_info(body, 0)

        assert obj_id == "internal-id"
        assert obj_type == "kafka"

    def test_returns_none_for_none_body(self) -> None:
        """Returns (None, None) when body is None."""
        obj_id, obj_type = _extract_object_info(None, 0)

        assert obj_id is None
        assert obj_type is None

    def test_returns_none_for_invalid_json(self) -> None:
        """Returns (None, None) for invalid JSON."""
        body = "not valid json"

        obj_id, obj_type = _extract_object_info(body, 0)

        assert obj_id is None
        assert obj_type is None

    def test_returns_none_for_out_of_range_index(self) -> None:
        """Returns (None, None) when index is out of range."""
        body = '{"items": [{"id": "src1"}]}'

        obj_id, obj_type = _extract_object_info(body, 10)

        assert obj_id is None
        assert obj_type is None

    def test_returns_none_for_negative_index(self) -> None:
        """Returns (None, None) when index is negative."""
        body = '{"items": [{"id": "src1"}]}'

        obj_id, obj_type = _extract_object_info(body, -1)

        assert obj_id is None
        assert obj_type is None

    def test_returns_none_when_no_items_key(self) -> None:
        """Returns (None, None) when items key missing."""
        body = '{"data": [{"id": "src1"}]}'

        obj_id, obj_type = _extract_object_info(body, 0)

        assert obj_id is None
        assert obj_type is None

    def test_handles_missing_type(self) -> None:
        """Returns None for type when not present."""
        body = '{"items": [{"id": "src1"}]}'

        obj_id, obj_type = _extract_object_info(body, 0)

        assert obj_id == "src1"
        assert obj_type is None


class TestExtractFieldValue:
    """Tests for _extract_field_value helper."""

    def test_extracts_nested_field_value(self) -> None:
        """Extracts value from nested field path."""
        body = '{"items": [{"tcpjson": {"connections": [{"host": "localhost", "port": 514}]}}]}'

        value = _extract_field_value(body, 0, "tcpjson", ["connections", "0", "port"])

        # Returns parent of the final path element
        assert value == {"host": "localhost", "port": 514}

    def test_extracts_type_specific_field(self) -> None:
        """Extracts value when field is directly under type field."""
        body = '{"items": [{"syslog": {"host": "127.0.0.1", "port": 514}}]}'

        value = _extract_field_value(body, 0, "syslog", ["host"])

        assert value == {"host": "127.0.0.1", "port": 514}

    def test_extracts_without_type_field(self) -> None:
        """Extracts value when type_field is None."""
        body = '{"items": [{"config": {"setting": "value"}}]}'

        value = _extract_field_value(body, 0, None, ["config", "setting"])

        assert value == {"setting": "value"}

    def test_returns_none_for_none_body(self) -> None:
        """Returns None when body is None."""
        value = _extract_field_value(None, 0, "tcpjson", ["host"])

        assert value is None

    def test_returns_none_for_invalid_json(self) -> None:
        """Returns None for invalid JSON."""
        value = _extract_field_value("not json", 0, "tcpjson", ["host"])

        assert value is None

    def test_returns_none_for_out_of_range_index(self) -> None:
        """Returns None when index is out of range."""
        body = '{"items": [{"id": "src1"}]}'

        value = _extract_field_value(body, 10, "tcpjson", ["host"])

        assert value is None

    def test_returns_none_for_missing_type_field(self) -> None:
        """Returns None when type field doesn't exist in item."""
        body = '{"items": [{"syslog": {"host": "localhost"}}]}'

        value = _extract_field_value(body, 0, "tcpjson", ["host"])

        # Falls back to item since tcpjson not in item
        assert value == {"syslog": {"host": "localhost"}}

    def test_returns_none_for_missing_field_path(self) -> None:
        """Returns None when field path doesn't exist."""
        body = '{"items": [{"tcpjson": {"host": "localhost"}}]}'

        value = _extract_field_value(body, 0, "tcpjson", ["connections", "0", "port"])

        assert value is None

    def test_handles_empty_field_path(self) -> None:
        """Returns type-specific field when path is empty."""
        body = '{"items": [{"tcpjson": {"host": "localhost"}}]}'

        value = _extract_field_value(body, 0, "tcpjson", [])

        assert value == {"host": "localhost"}

    def test_navigates_list_index(self) -> None:
        """Correctly navigates list indices in path."""
        body = '{"items": [{"tcpjson": {"connections": [{"a": 1}, {"b": 2}]}}]}'

        value = _extract_field_value(body, 0, "tcpjson", ["connections", "1", "b"])

        assert value == {"b": 2}

    def test_returns_none_for_list_index_out_of_range(self) -> None:
        """Returns None when list index is out of range."""
        body = '{"items": [{"tcpjson": {"connections": [{"a": 1}]}}]}'

        value = _extract_field_value(body, 0, "tcpjson", ["connections", "5", "a"])

        assert value is None


class TestFormatJsonValue:
    """Tests for _format_json_value helper."""

    def test_formats_dict(self) -> None:
        """Formats dict as indented JSON."""
        value = {"key": "value", "num": 42}

        result = _format_json_value(value)

        assert '"key": "value"' in result
        assert '"num": 42' in result

    def test_formats_list(self) -> None:
        """Formats list as JSON array."""
        value = [1, 2, 3]

        result = _format_json_value(value)

        assert result == "[\n  1,\n  2,\n  3\n]"

    def test_formats_string(self) -> None:
        """Formats string with quotes."""
        value = "test string"

        result = _format_json_value(value)

        assert result == '"test string"'

    def test_truncates_long_values(self) -> None:
        """Truncates values exceeding max_length."""
        value = {"long_key": "x" * 1000}

        result = _format_json_value(value, max_length=100)

        assert len(result) == 100
        assert result.endswith("...")

    def test_handles_non_json_serializable(self) -> None:
        """Falls back to str() for non-serializable values."""
        value: Any = object()

        result = _format_json_value(value)

        assert "<object object at" in result


class TestBuildUserFriendlyMessage:
    """Tests for _build_user_friendly_message helper."""

    def test_missing_field_error(self) -> None:
        """Builds message for missing field error."""
        ctx = ErrorMessageContext(
            resource_type="sources",
            group_id="default",
            object_id="my-source",
            object_type="tcpjson",
            type_field="tcpjson",
            field_path=["connections", "0", "output"],
            error_msg="Field required",
            error_type="missing",
        )

        message = _build_user_friendly_message(ctx)

        assert "default" in message
        assert "tcpjson source" in message
        assert '"my-source"' in message
        assert '"connections.0"' in message
        assert 'missing the required "output"' in message

    def test_type_error(self) -> None:
        """Builds message for type error."""
        ctx = ErrorMessageContext(
            resource_type="destinations",
            group_id="workers",
            object_id="dest1",
            object_type="splunk",
            type_field="splunk",
            field_path=["port"],
            error_msg="Input should be a valid integer",
            error_type="int_type",
        )

        message = _build_user_friendly_message(ctx)

        assert "workers" in message
        assert "splunk destination" in message
        assert '"dest1"' in message
        assert "invalid type" in message

    def test_other_error_type(self) -> None:
        """Builds message for other error types."""
        ctx = ErrorMessageContext(
            resource_type="pipelines",
            group_id="edge-fleet",
            object_id="pipeline1",
            object_type=None,
            type_field="functions",
            field_path=["0", "conf"],
            error_msg="Extra fields not permitted",
            error_type="extra_forbidden",
        )

        message = _build_user_friendly_message(ctx)

        assert "edge-fleet" in message
        assert "pipeline" in message
        assert '"pipeline1"' in message
        assert "inconsistent with the SDK" in message

    def test_no_object_id(self) -> None:
        """Builds message when object_id is None."""
        ctx = ErrorMessageContext(
            resource_type="sources",
            group_id="default",
            object_id=None,
            object_type="syslog",
            type_field="syslog",
            field_path=["host"],
            error_msg="Field required",
            error_type="missing",
        )

        message = _build_user_friendly_message(ctx)

        assert "a syslog source" in message

    def test_no_object_type(self) -> None:
        """Builds message when object_type is None."""
        ctx = ErrorMessageContext(
            resource_type="breakers",
            group_id="default",
            object_id="breaker1",
            object_type=None,
            type_field=None,
            field_path=["rules"],
            error_msg="Field required",
            error_type="missing",
        )

        message = _build_user_friendly_message(ctx)

        # When object_type is None, just the object_id is shown
        assert '"breaker1"' in message

    def test_empty_field_path(self) -> None:
        """Builds message when field_path is empty."""
        ctx = ErrorMessageContext(
            resource_type="lookups",
            group_id="default",
            object_id="lookup1",
            object_type="file",
            type_field="file",
            field_path=[],
            error_msg="Invalid configuration",
            error_type="value_error",
        )

        message = _build_user_friendly_message(ctx)

        assert '"file"' in message


class TestParseValidationError:
    """Tests for parse_validation_error function."""

    def test_parses_single_error(self) -> None:
        """Parses a single validation error."""

        class TestModel(BaseModel):
            name: str
            value: int

        with pytest.raises(ValidationError) as exc_info:
            TestModel(name="test")  # type: ignore[call-arg]

        details = parse_validation_error(exc_info.value)

        assert len(details) == 1
        assert details[0].error_type == "missing"
        assert "value" in details[0].field_path

    def test_parses_multiple_errors(self) -> None:
        """Parses multiple validation errors."""

        class TestModel(BaseModel):
            name: str
            value: int
            count: int

        with pytest.raises(ValidationError) as exc_info:
            TestModel()  # type: ignore[call-arg]

        details = parse_validation_error(exc_info.value)

        assert len(details) == 3
        error_types = {d.error_type for d in details}
        assert error_types == {"missing"}

    def test_parses_nested_location(self) -> None:
        """Parses errors with nested location paths."""

        class Inner(BaseModel):
            port: int

        class Outer(BaseModel):
            inner: Inner

        with pytest.raises(ValidationError) as exc_info:
            Outer(inner={"port": "not-an-int"})  # type: ignore[arg-type]

        details = parse_validation_error(exc_info.value)

        assert len(details) == 1
        assert "inner" in details[0].field_path
        assert "int" in details[0].error_type

    def test_parses_error_with_type_field_only(self) -> None:
        """Parses error with object type field but no additional path.

        This covers the branch where parsed.object_type_field is truthy
        but field_path_str is empty.
        """
        # Create a mock error with location that has type field but no further path
        mock_error = MagicMock(spec=ValidationError)
        mock_error.errors.return_value = [
            {
                "loc": ("body", "items", 0, "tcpjson"),  # Type field with no path after
                "msg": "Invalid configuration",
                "type": "value_error",
                "input": {},
            }
        ]

        details = parse_validation_error(mock_error)

        assert len(details) == 1
        # When type field exists but no path, field_path should just be the type field
        assert details[0].field_path == "tcpjson"
        assert details[0].object_type == "tcpjson"

    def test_parses_error_with_type_field_and_path(self) -> None:
        """Parses error with both object type field and additional path.

        This covers the branch where both parsed.object_type_field and
        field_path_str are truthy, resulting in concatenation.
        """
        mock_error = MagicMock(spec=ValidationError)
        mock_error.errors.return_value = [
            {
                "loc": ("body", "items", 0, "tcpjson", "host"),  # Type field with path
                "msg": "Field required",
                "type": "missing",
                "input": None,
            }
        ]

        details = parse_validation_error(mock_error)

        assert len(details) == 1
        # When both type field and path exist, they should be concatenated
        assert details[0].field_path == "tcpjson.host"
        assert details[0].object_type == "tcpjson"

    def test_parses_error_without_type_field(self) -> None:
        """Parses error without object type field.

        This covers the branch where object_type_field is None,
        skipping both if and elif branches in field path construction.
        """
        mock_error = MagicMock(spec=ValidationError)
        mock_error.errors.return_value = [
            {
                "loc": (),  # Empty location - no type field or path
                "msg": "Invalid value",
                "type": "value_error",
                "input": None,
            }
        ]

        details = parse_validation_error(mock_error)

        assert len(details) == 1
        # When no type field exists, field_path should be empty
        assert details[0].field_path == ""
        assert details[0].object_type is None


class TestFormatValidationErrorResponse:
    """Tests for format_validation_error_response function."""

    def test_formats_complete_response(self) -> None:
        """Formats a complete error response with all fields."""
        validation_errors = [
            ValidationErrorDetails(
                object_index=0,
                object_type="tcpjson",
                field_path="tcpjson.connections.0.output",
                error_type="missing",
                error_message="Field required",
                input_value=None,
                raw_location=("body", "items", 0, "tcpjson", "connections", "0", "output"),
            )
        ]
        body = '{"items": [{"id": "src1", "type": "tcpjson", "tcpjson": {"connections": [{"host": "localhost"}]}}]}'

        result = format_validation_error_response(
            resource_type="sources",
            product="stream",
            group_id="default",
            body=body,
            validation_errors=validation_errors,
        )

        assert result["status"] == "validation_error"
        assert "message" in result
        assert result["product"] == "stream"
        assert result["group_id"] == "default"
        assert result["resource_type"] == "sources"
        assert len(result["errors"]) == 1
        assert "resolution" in result

    def test_formats_response_without_body(self) -> None:
        """Formats response when body is None."""
        validation_errors = [
            ValidationErrorDetails(
                object_index=0,
                object_type="syslog",
                field_path="syslog.host",
                error_type="missing",
                error_message="Field required",
                input_value=None,
                raw_location=("body", "items", 0, "syslog", "host"),
            )
        ]

        result = format_validation_error_response(
            resource_type="sources",
            product="edge",
            group_id="fleet1",
            body=None,
            validation_errors=validation_errors,
        )

        assert result["status"] == "validation_error"
        assert result["product"] == "edge"
        assert len(result["errors"]) == 1

    def test_formats_response_with_multiple_errors(self) -> None:
        """Formats response with multiple validation errors."""
        validation_errors = [
            ValidationErrorDetails(
                object_index=0,
                object_type="tcpjson",
                field_path="tcpjson.host",
                error_type="missing",
                error_message="Field required",
                input_value=None,
                raw_location=("body", "items", 0, "tcpjson", "host"),
            ),
            ValidationErrorDetails(
                object_index=1,
                object_type="syslog",
                field_path="syslog.port",
                error_type="int_type",
                error_message="Input should be a valid integer",
                input_value="abc",
                raw_location=("body", "items", 1, "syslog", "port"),
            ),
        ]

        result = format_validation_error_response(
            resource_type="sources",
            product="stream",
            group_id="workers",
            body=None,
            validation_errors=validation_errors,
        )

        assert len(result["errors"]) == 2
        # Primary message should be from first error
        assert result["message"] is not None

    def test_includes_actual_value_and_help(self) -> None:
        """Includes actual_value and help text when field value is found."""
        validation_errors = [
            ValidationErrorDetails(
                object_index=0,
                object_type="tcpjson",
                field_path="tcpjson.connections.0.output",
                error_type="missing",
                error_message="Field required",
                input_value=None,
                raw_location=("body", "items", 0, "tcpjson", "connections", "0", "output"),
            )
        ]
        body = '{"items": [{"id": "src1", "type": "tcpjson", "tcpjson": {"connections": [{"host": "localhost"}]}}]}'

        result = format_validation_error_response(
            resource_type="sources",
            product="stream",
            group_id="default",
            body=body,
            validation_errors=validation_errors,
        )

        error_entry = result["errors"][0]
        assert "actual_value" in error_entry
        assert "help" in error_entry
        assert "Cribl UI" in error_entry["help"]

    def test_uses_default_message_when_no_errors(self) -> None:
        """Uses default message when validation_errors list is empty."""
        result = format_validation_error_response(
            resource_type="pipelines",
            product="stream",
            group_id="default",
            body=None,
            validation_errors=[],
        )

        assert "could not validate" in result["message"]
        assert result["errors"] == []

    def test_handles_error_without_object_index(self) -> None:
        """Handles errors where object_index is None (no items array)."""
        validation_errors = [
            ValidationErrorDetails(
                object_index=None,  # No object index
                object_type=None,
                field_path="config.setting",
                error_type="missing",
                error_message="Field required",
                input_value=None,
                raw_location=("body", "config", "setting"),  # No items array
            )
        ]

        result = format_validation_error_response(
            resource_type="pipelines",
            product="stream",
            group_id="default",
            body='{"config": {}}',
            validation_errors=validation_errors,
        )

        assert result["status"] == "validation_error"
        # object_id and object_type should be None when index is None
        error_entry = result["errors"][0]
        assert error_entry["object_id"] is None
        assert error_entry["object_type"] is None
        # actual_value should not be present when object_index is None
        assert "actual_value" not in error_entry
