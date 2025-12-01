"""Unit tests for pipeline function Pydantic models.

Validates that the models correctly parse and serialize function configurations
from the Cribl API, preserving all fields and handling aliases properly.
"""

from snc_cribl_mcp.models.pipeline_functions import (
    FUNCTION_CONF_MAP,
    AggregateMetricItem,
    AggregateMetricsConf,
    DropConf,
    EvalConf,
    EvalField,
    FunctionConf,
    GrokConf,
    LookupConf,
    MaskConf,
    MaskRule,
    PipelineConf,
    PipelineFunctionConf,
    PipelineItem,
    RedisCommand,
    RedisConf,
    RegexExtractConf,
    SamplingConf,
    SamplingRule,
    SerdeConf,
    get_function_conf_class,
    parse_function_conf,
    parse_pipeline_item,
    serialize_pipeline_item,
)


class TestEvalField:
    """Tests for EvalField model."""

    def test_basic_field(self) -> None:
        """Should create an EvalField with name and value."""
        field = EvalField(name="test_field", value="'hello'")
        assert field.name == "test_field"
        assert field.value == "'hello'"

    def test_value_only(self) -> None:
        """Should allow None for name."""
        field = EvalField(value="123")
        assert field.name is None
        assert field.value == "123"

    def test_serialization(self) -> None:
        """Should serialize correctly."""
        field = EvalField(name="x", value="1+1")
        data = field.model_dump()
        assert data["name"] == "x"
        assert data["value"] == "1+1"


class TestSamplingRule:
    """Tests for SamplingRule model."""

    def test_basic_rule(self) -> None:
        """Should create a sampling rule with filter and rate."""
        rule = SamplingRule(filter="__action=='permitted'", rate=10)
        assert rule.filter == "__action=='permitted'"
        assert rule.rate == 10

    def test_default_values(self) -> None:
        """Should use default values for filter and rate."""
        rule = SamplingRule()
        assert rule.filter == "true"
        assert rule.rate == 1


class TestMaskRule:
    """Tests for MaskRule model."""

    def test_basic_rule_with_alias(self) -> None:
        """Should parse matchRegex alias correctly."""
        rule = MaskRule(matchRegex="/password=[^&]+/", replaceExpr="'password=***'")
        assert rule.match_regex == "/password=[^&]+/"
        assert rule.replace_expr == "'password=***'"

    def test_serialization_with_alias(self) -> None:
        """Should serialize with alias names."""
        rule = MaskRule(matchRegex="/secret/", replaceExpr="'***'")
        data = rule.model_dump(by_alias=True)
        assert data["matchRegex"] == "/secret/"
        assert data["replaceExpr"] == "'***'"


class TestRedisCommand:
    """Tests for RedisCommand model."""

    def test_basic_command(self) -> None:
        """Should parse a basic Redis command."""
        cmd = RedisCommand(command="GET", keyExpr="`user:${id}`")
        assert cmd.command == "GET"
        assert cmd.key_expr == "`user:${id}`"


class TestAggregateMetricItem:
    """Tests for AggregateMetricItem model."""

    def test_basic_metric(self) -> None:
        """Should parse an aggregate metric item."""
        item = AggregateMetricItem(agg="sum", metricType="counter")
        assert item.agg == "sum"
        assert item.metric_type == "counter"


class TestEvalConf:
    """Tests for EvalConf model."""

    def test_add_fields(self) -> None:
        """Should parse add fields correctly."""
        field1 = EvalField(name="status", value="'OK'")
        field2 = EvalField(name="count", value="1")
        conf = EvalConf(add=[field1, field2])
        assert conf.add is not None
        assert len(conf.add) == 2
        assert conf.add[0].name == "status"
        assert conf.add[1].value == "1"

    def test_remove_fields(self) -> None:
        """Should parse remove fields."""
        conf = EvalConf(remove=["field1", "field2"])
        assert conf.remove == ["field1", "field2"]

    def test_keep_fields(self) -> None:
        """Should parse keep fields."""
        conf = EvalConf(keep=["_time", "_raw", "host"])
        assert conf.keep == ["_time", "_raw", "host"]


class TestRegexExtractConf:
    """Tests for RegexExtractConf model."""

    def test_basic_regex(self) -> None:
        """Should parse regex and source fields."""
        conf = RegexExtractConf(regex="/(?<code>\\d+)/", source="_raw")
        assert conf.regex == "/(?<code>\\d+)/"
        assert conf.source == "_raw"

    def test_iteration_options(self) -> None:
        """Should handle iteration limit."""
        conf = RegexExtractConf(regex="/test/", iterations=5)
        assert conf.iterations == 5


class TestSamplingConf:
    """Tests for SamplingConf model."""

    def test_with_rules(self) -> None:
        """Should parse sampling rules correctly."""
        rule1 = SamplingRule(filter="severity=='debug'", rate=100)
        rule2 = SamplingRule(filter="severity=='info'", rate=10)
        conf = SamplingConf(rules=[rule1, rule2])
        assert conf.rules is not None
        assert len(conf.rules) == 2
        assert conf.rules[0].filter == "severity=='debug'"
        assert conf.rules[0].rate == 100


class TestMaskConf:
    """Tests for MaskConf model."""

    def test_with_rules_and_fields(self) -> None:
        """Should parse mask rules and target fields."""
        rule = MaskRule(matchRegex="/ssn:\\d+/", replaceExpr="'ssn:XXX'")
        conf = MaskConf(rules=[rule], fields=["_raw", "message"])
        assert len(conf.rules) == 1
        assert conf.rules[0].match_regex == "/ssn:\\d+/"
        assert conf.fields == ["_raw", "message"]


class TestSerdeConf:
    """Tests for SerdeConf model."""

    def test_type_selection(self) -> None:
        """Should parse serde type."""
        conf = SerdeConf(type="json")
        assert conf.type == "json"

    def test_src_field_alias(self) -> None:
        """Should handle srcField alias."""
        conf = SerdeConf(srcField="_raw", type="json")
        assert conf.src_field == "_raw"


class TestGrokConf:
    """Tests for GrokConf model."""

    def test_with_pattern(self) -> None:
        """Should parse grok pattern."""
        conf = GrokConf(pattern="%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level}")
        assert conf.pattern == "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level}"


class TestLookupConf:
    """Tests for LookupConf model."""

    def test_basic_lookup(self) -> None:
        """Should parse lookup file and match mode."""
        conf = LookupConf(file="geo.csv", matchMode="regex")
        assert conf.file == "geo.csv"
        assert conf.match_mode == "regex"


class TestRedisConf:
    """Tests for RedisConf model."""

    def test_with_commands(self) -> None:
        """Should parse redis commands."""
        cmd = RedisCommand(command="GET", keyExpr="`user:${_raw.userId}`")
        conf = RedisConf(commands=[cmd], url="redis://localhost:6379")
        assert len(conf.commands) == 1
        assert conf.commands[0].command == "GET"
        assert conf.url == "redis://localhost:6379"


class TestAggregateMetricsConf:
    """Tests for AggregateMetricsConf model."""

    def test_time_window(self) -> None:
        """Should parse timeWindow alias."""
        conf = AggregateMetricsConf(timeWindow="30s", aggregations=[])
        assert conf.time_window == "30s"

    def test_aggregations(self) -> None:
        """Should parse aggregations list."""
        metric = AggregateMetricItem(agg="sum", metricType="counter")
        conf = AggregateMetricsConf(aggregations=[metric])
        assert len(conf.aggregations) == 1
        assert conf.aggregations[0].agg == "sum"


class TestPipelineFunctionConf:
    """Tests for PipelineFunctionConf model."""

    def test_basic_function(self) -> None:
        """Should parse a basic pipeline function."""
        func = PipelineFunctionConf(
            id="eval",
            conf={"add": [{"name": "test", "value": "'x'"}]},
        )
        assert func.id == "eval"
        assert func.conf == {"add": [{"name": "test", "value": "'x'"}]}

    def test_disabled_function(self) -> None:
        """Should handle disabled flag."""
        func = PipelineFunctionConf(id="drop", disabled=True)
        assert func.disabled is True

    def test_function_with_description(self) -> None:
        """Should handle description field."""
        func = PipelineFunctionConf(
            id="mask",
            description="Mask sensitive data",
            conf={},
        )
        assert func.description == "Mask sensitive data"


class TestPipelineConf:
    """Tests for PipelineConf model."""

    def test_with_functions(self) -> None:
        """Should parse pipeline conf with functions."""
        func1 = PipelineFunctionConf(id="eval", conf={})
        func2 = PipelineFunctionConf(id="drop", conf={})
        conf = PipelineConf(output="default", functions=[func1, func2])
        assert conf.output == "default"
        assert conf.functions is not None
        assert len(conf.functions) == 2


class TestPipelineItem:
    """Tests for PipelineItem model."""

    def test_complete_pipeline(self) -> None:
        """Should parse a complete pipeline item."""
        func = PipelineFunctionConf(
            id="regex_extract",
            conf={"regex": "/test/", "source": "_raw"},
        )
        conf = PipelineConf(output="default", functions=[func])
        pipeline = PipelineItem(id="test_pipeline", conf=conf)
        assert pipeline.id == "test_pipeline"
        assert pipeline.conf.output == "default"
        assert pipeline.conf.functions is not None
        assert len(pipeline.conf.functions) == 1


class TestFunctionConfMap:
    """Tests for the FUNCTION_CONF_MAP registry."""

    def test_all_expected_functions_present(self) -> None:
        """Should have entries for common function types."""
        expected_functions = [
            "eval",
            "mask",
            "sampling",
            "regex_extract",
            "serde",
            "lookup",
            "grok",
            "drop",
            "clone",
            "chain",
            "redis",
        ]
        for func_id in expected_functions:
            assert func_id in FUNCTION_CONF_MAP, f"Missing function: {func_id}"

    def test_map_returns_correct_types(self) -> None:
        """Should return the correct model class for each function."""
        assert FUNCTION_CONF_MAP["eval"] is EvalConf
        assert FUNCTION_CONF_MAP["mask"] is MaskConf
        assert FUNCTION_CONF_MAP["sampling"] is SamplingConf
        assert FUNCTION_CONF_MAP["regex_extract"] is RegexExtractConf


class TestFunctionConfUnion:
    """Tests for the FunctionConf union type."""

    def test_eval_conf_in_union(self) -> None:
        """EvalConf should be a valid FunctionConf."""
        field = EvalField(name="x", value="1")
        conf: FunctionConf = EvalConf(add=[field])
        assert isinstance(conf, EvalConf)

    def test_mask_conf_in_union(self) -> None:
        """MaskConf should be a valid FunctionConf."""
        conf: FunctionConf = MaskConf(rules=[])
        assert isinstance(conf, MaskConf)


class TestExtraFieldsAllowed:
    """Tests that models allow extra fields for forward compatibility."""

    def test_pipeline_function_extra_fields(self) -> None:
        """PipelineFunctionConf should preserve unknown fields via model_validate."""
        data: dict[str, object] = {
            "id": "eval",
            "conf": {},
            "future_feature": True,
        }
        func = PipelineFunctionConf.model_validate(data)
        dumped = func.model_dump()
        assert dumped.get("future_feature") is True

    def test_eval_conf_extra_fields(self) -> None:
        """EvalConf should preserve unknown fields via model_validate."""
        data: dict[str, object] = {
            "add": [],
            "unknown_future_field": "value",
        }
        conf = EvalConf.model_validate(data)
        dumped = conf.model_dump()
        assert dumped.get("unknown_future_field") == "value"


class TestGetFunctionConfClass:
    """Tests for get_function_conf_class utility function."""

    def test_returns_correct_class_for_known_function(self) -> None:
        """Should return the correct model class for known function types."""
        assert get_function_conf_class("eval") is EvalConf
        assert get_function_conf_class("mask") is MaskConf
        assert get_function_conf_class("sampling") is SamplingConf

    def test_returns_drop_conf_for_unknown_function(self) -> None:
        """Should return DropConf as fallback for unknown function types."""
        result = get_function_conf_class("unknown_future_function")
        assert result is DropConf


class TestParseFunctionConf:
    """Tests for parse_function_conf utility function."""

    def test_parses_eval_conf(self) -> None:
        """Should parse an eval configuration into EvalConf."""
        data: dict[str, object] = {
            "add": [{"name": "test", "value": "'x'"}],
            "remove": ["old_field"],
        }
        result = parse_function_conf("eval", data)
        assert isinstance(result, EvalConf)
        assert result.remove == ["old_field"]

    def test_parses_unknown_function_as_drop_conf(self) -> None:
        """Should parse unknown functions using DropConf."""
        data: dict[str, object] = {"custom_field": "value"}
        result = parse_function_conf("unknown_type", data)
        assert isinstance(result, DropConf)


class TestSerializePipelineItem:
    """Tests for serialize_pipeline_item utility function."""

    def test_serializes_pipeline_item(self) -> None:
        """Should serialize a PipelineItem to a dictionary."""
        func = PipelineFunctionConf(id="eval", conf={})
        conf = PipelineConf(output="default", functions=[func])
        item = PipelineItem(id="test_pipeline", conf=conf)

        result = serialize_pipeline_item(item)

        assert result["id"] == "test_pipeline"
        assert result["conf"]["output"] == "default"
        assert len(result["conf"]["functions"]) == 1


class TestParsePipelineItem:
    """Tests for parse_pipeline_item utility function."""

    def test_parses_pipeline_item(self) -> None:
        """Should parse a dictionary into a PipelineItem."""
        data: dict[str, object] = {
            "id": "my_pipeline",
            "conf": {
                "output": "default",
                "functions": [
                    {"id": "drop", "conf": {}},
                ],
            },
        }
        result = parse_pipeline_item(data)

        assert isinstance(result, PipelineItem)
        assert result.id == "my_pipeline"
        assert result.conf.output == "default"
        assert result.conf.functions is not None
        assert len(result.conf.functions) == 1
