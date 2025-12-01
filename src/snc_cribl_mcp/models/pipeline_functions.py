"""Pydantic models for Cribl pipeline functions and their configurations.

This module defines typed models for all Cribl pipeline function types. Each function
has a specific configuration schema defined in docs/pipeline_functions/<id>.json.

The models preserve all configuration data during serialization, solving the issue
where the SDK's empty FunctionSpecificConfigs class would serialize conf as {}.
"""

from typing import Annotated, Any

import pydantic
from pydantic import BaseModel, ConfigDict, Field

# =============================================================================
# Common Helper Models
# =============================================================================


class EvalField(BaseModel):
    """A key-value pair for eval operations."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str | None = None
    value: str
    disabled: bool | None = None


class SamplingRule(BaseModel):
    """A sampling rule with filter and rate."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    filter: str = Field(default="true", alias="filter")
    rate: int = 1


class MaskRule(BaseModel):
    """A masking rule with regex match and replace expression."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    match_regex: str = Field(..., alias="matchRegex")
    replace_expr: str = Field(default="''", alias="replaceExpr")
    disabled: bool | None = None


class RegexListItem(BaseModel):
    """An item in a regex list."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    regex: str


class PatternListItem(BaseModel):
    """An item in a pattern list for Grok."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    pattern: str


class TimestampItem(BaseModel):
    """A timestamp extraction item."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    regex: str
    strptime: str


class LookupInField(BaseModel):
    """A lookup input field mapping."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    event_field: str = Field(..., alias="eventField")
    lookup_field: str | None = Field(default=None, alias="lookupField")


class LookupOutField(BaseModel):
    """A lookup output field mapping."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    lookup_field: str = Field(..., alias="lookupField")
    event_field: str | None = Field(default=None, alias="eventField")
    default_value: str | None = Field(default=None, alias="defaultValue")


class DnsLookupField(BaseModel):
    """A DNS lookup field configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    in_field_name: str | None = Field(default=None, alias="inFieldName")
    resource_record_type: str | None = Field(default="A", alias="resourceRecordType")
    out_field_name: str | None = Field(default=None, alias="outFieldName")


class ReverseLookupField(BaseModel):
    """A reverse DNS lookup field configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    in_field_name: str | None = Field(default=None, alias="inFieldName")
    out_field_name: str | None = Field(default=None, alias="outFieldName")


class GeoipAdditionalField(BaseModel):
    """Additional GeoIP field configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    extra_in_field: str = Field(..., alias="extraInField")
    extra_out_field: str = Field(..., alias="extraOutField")


class RenameField(BaseModel):
    """A rename field pair."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    current_name: str = Field(..., alias="currentName")
    new_name: str = Field(..., alias="newName")


class RedisCommand(BaseModel):
    """A Redis command configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    command: str
    key_expr: str = Field(..., alias="keyExpr")
    out_field: str | None = Field(default=None, alias="outField")
    args_expr: str | None = Field(default=None, alias="argsExpr")


class RootNode(BaseModel):
    """A Redis cluster root node."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    host: str
    port: int


class PublishMetricField(BaseModel):
    """A publish metrics field configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    in_field_name: str = Field(..., alias="inFieldName")
    out_field_expr: str | None = Field(default=None, alias="outFieldExpr")
    metric_type: str = Field(default="gauge", alias="metricType")


class AggregateMetricItem(BaseModel):
    """An aggregate metric configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    agg: str
    metric_type: str = Field(default="automatic", alias="metricType")


class HeaderField(BaseModel):
    """A CEF header field."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str | None = None
    value: str


class ExtensionField(BaseModel):
    """A CEF extension field."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    value: str


class SidLookupField(BaseModel):
    """A SID lookup field."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str | None = None
    expr: str
    disabled: bool | None = None


class TlsOptions(BaseModel):
    """TLS connection options."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    reject_unauthorized: bool | None = Field(default=True, alias="rejectUnauthorized")
    servername: str | None = None
    certificate_name: str | None = Field(default=None, alias="certificateName")
    ca_path: str | None = Field(default=None, alias="caPath")
    priv_key_path: str | None = Field(default=None, alias="privKeyPath")
    cert_path: str | None = Field(default=None, alias="certPath")
    passphrase: str | None = None
    min_version: str | None = Field(default=None, alias="minVersion")
    max_version: str | None = Field(default=None, alias="maxVersion")


class TimestampFormat(BaseModel):
    """Timestamp format configuration for event breaker."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: str = "auto"
    length: int | None = None
    format: str | None = None


class V3User(BaseModel):
    """SNMPv3 user configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str | None = None
    auth_protocol: str | None = Field(default="none", alias="authProtocol")
    auth_key: str | None = Field(default=None, alias="authKey")
    priv_protocol: str | None = Field(default="none", alias="privProtocol")
    priv_key: str | None = Field(default=None, alias="privKey")


# =============================================================================
# Function-Specific Configuration Models
# =============================================================================


class AggregateMetricsConf(BaseModel):
    """Configuration for the aggregate_metrics function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    time_window: str = Field(default="10s", alias="timeWindow")
    aggregations: Annotated[list[AggregateMetricItem], Field(default_factory=list)]
    groupbys: list[str] | None = None
    passthrough: bool | None = None
    preserve_group_bys: bool | None = Field(default=None, alias="preserveGroupBys")
    sufficient_stats_only: bool | None = Field(default=None, alias="sufficientStatsOnly")
    prefix: str | None = None
    flush_event_limit: int | None = Field(default=None, alias="flushEventLimit")
    flush_mem_limit: str | None = Field(default=None, alias="flushMemLimit")
    cumulative: bool | None = None
    should_treat_dots_as_literals: bool | None = Field(default=None, alias="shouldTreatDotsAsLiterals")
    add: list[EvalField] | None = None
    flush_on_input_close: bool | None = Field(default=None, alias="flushOnInputClose")
    lag_tolerance: str | None = Field(default=None, alias="lagTolerance")
    idle_time_limit: str | None = Field(default=None, alias="idleTimeLimit")


class AggregationConf(BaseModel):
    """Configuration for the aggregation function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    time_window: str = Field(default="10s", alias="timeWindow")
    aggregations: list[str] = Field(default_factory=list)
    groupbys: list[str] | None = None
    passthrough: bool | None = None
    preserve_group_bys: bool | None = Field(default=None, alias="preserveGroupBys")
    sufficient_stats_only: bool | None = Field(default=None, alias="sufficientStatsOnly")
    metrics_mode: bool | None = Field(default=None, alias="metricsMode")
    prefix: str | None = None
    flush_event_limit: int | None = Field(default=None, alias="flushEventLimit")
    flush_mem_limit: str | None = Field(default=None, alias="flushMemLimit")
    cumulative: bool | None = None
    search_agg_mode: str | None = Field(default=None, alias="searchAggMode")
    add: list[EvalField] | None = None
    should_treat_dots_as_literals: bool | None = Field(default=None, alias="shouldTreatDotsAsLiterals")
    flush_on_input_close: bool | None = Field(default=None, alias="flushOnInputClose")
    lag_tolerance: str | None = Field(default=None, alias="lagTolerance")
    idle_time_limit: str | None = Field(default=None, alias="idleTimeLimit")


class AutoTimestampConf(BaseModel):
    """Configuration for the auto_timestamp function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    src_field: str | None = Field(default="_raw", alias="srcField")
    dst_field: str | None = Field(default="_time", alias="dstField")
    default_timezone: str | None = Field(default="local", alias="defaultTimezone")
    time_expression: str | None = Field(default=None, alias="timeExpression")
    offset: int | None = None
    max_len: int | None = Field(default=None, alias="maxLen")
    default_time: str | None = Field(default="now", alias="defaultTime")
    latest_date_allowed: str | None = Field(default=None, alias="latestDateAllowed")
    earliest_date_allowed: str | None = Field(default=None, alias="earliestDateAllowed")
    spacer: str | None = None
    timestamps: list[TimestampItem] | None = None


class CefConf(BaseModel):
    """Configuration for the cef function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    output_field: str | None = Field(default="_raw", alias="outputField")
    header: list[HeaderField] | None = None
    extension: list[ExtensionField] | None = None


class ChainConf(BaseModel):
    """Configuration for the chain function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    processor: str


class CloneConf(BaseModel):
    """Configuration for the clone function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    clones: list[dict[str, Any]] | None = None


class CodeConf(BaseModel):
    """Configuration for the code function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    code: str | None = None
    max_num_of_iterations: int | None = Field(default=None, alias="maxNumOfIterations")
    active_log_sample_rate: int | None = Field(default=None, alias="activeLogSampleRate")
    use_unique_log_channel: bool | None = Field(default=None, alias="useUniqueLogChannel")


class CommentConf(BaseModel):
    """Configuration for the comment function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    comment: str | None = None


class DnsLookupConf(BaseModel):
    """Configuration for the dns_lookup function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    dns_lookup_fields: list[DnsLookupField] | None = Field(default=None, alias="dnsLookupFields")
    reverse_lookup_fields: list[ReverseLookupField] | None = Field(default=None, alias="reverseLookupFields")
    dns_servers: list[str] | None = Field(default=None, alias="dnsServers")
    cache_ttl: int | None = Field(default=None, alias="cacheTTL")
    max_cache_size: int | None = Field(default=None, alias="maxCacheSize")
    use_resolv_conf: bool | None = Field(default=None, alias="useResolvConf")
    lookup_fallback: bool | None = Field(default=None, alias="lookupFallback")
    domain_overrides: list[str] | None = Field(default=None, alias="domainOverrides")
    lookup_fail_log_level: str | None = Field(default=None, alias="lookupFailLogLevel")


class DropConf(BaseModel):
    """Configuration for the drop function (empty schema)."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class DropDimensionsConf(BaseModel):
    """Configuration for the drop_dimensions function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    time_window: str = Field(default="10s", alias="timeWindow")
    drop_dimensions: list[str] = Field(default_factory=list, alias="dropDimensions")
    flush_on_input_close: bool | None = Field(default=None, alias="flushOnInputClose")


class DynamicSamplingConf(BaseModel):
    """Configuration for the dynamic_sampling function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    mode: str = "log"
    key_expr: str = Field(default="`${host}`", alias="keyExpr")
    sample_period: int | None = Field(default=None, alias="samplePeriod")
    min_events: int | None = Field(default=None, alias="minEvents")
    max_sample_rate: int | None = Field(default=None, alias="maxSampleRate")


class EvalConf(BaseModel):
    """Configuration for the eval function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    add: list[EvalField] | None = None
    keep: list[str] | None = None
    remove: list[str] | None = None


class EventBreakerConf(BaseModel):
    """Configuration for the event_breaker function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    existing_or_new: str = Field(default="existing", alias="existingOrNew")
    should_mark_cribl_breaker: bool | None = Field(default=None, alias="shouldMarkCriblBreaker")
    existing_rule: str | None = Field(default=None, alias="existingRule")
    rule_type: str | None = Field(default=None, alias="ruleType")
    max_event_bytes: int | None = Field(default=None, alias="maxEventBytes")
    timestamp_anchor_regex: str | None = Field(default=None, alias="timestampAnchorRegex")
    timestamp: TimestampFormat | None = None
    timestamp_timezone: str | None = Field(default=None, alias="timestampTimezone")
    timestamp_earliest: str | None = Field(default=None, alias="timestampEarliest")
    timestamp_latest: str | None = Field(default=None, alias="timestampLatest")
    event_breaker_regex: str | None = Field(default=None, alias="eventBreakerRegex")
    json_array_field: str | None = Field(default=None, alias="jsonArrayField")
    parent_fields_to_copy: list[str] | None = Field(default=None, alias="parentFieldsToCopy")
    json_extract_all: bool | None = Field(default=None, alias="jsonExtractAll")
    json_time_field: str | None = Field(default=None, alias="jsonTimeField")
    delimiter_regex: str | None = Field(default=None, alias="delimiterRegex")
    fields_line_regex: str | None = Field(default=None, alias="fieldsLineRegex")
    header_line_regex: str | None = Field(default=None, alias="headerLineRegex")
    null_field_val: str | None = Field(default=None, alias="nullFieldVal")
    clean_fields: bool | None = Field(default=None, alias="cleanFields")
    delimiter: str | None = None
    quote_char: str | None = Field(default=None, alias="quoteChar")
    escape_char: str | None = Field(default=None, alias="escapeChar")
    time_field: str | None = Field(default=None, alias="timeField")


class FlattenConf(BaseModel):
    """Configuration for the flatten function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    fields: list[str] | None = None
    prefix: str | None = None
    depth: int | None = None
    delimiter: str | None = None


class FoldkeysConf(BaseModel):
    """Configuration for the foldkeys function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    delete_original: bool | None = Field(default=None, alias="deleteOriginal")
    separator: str | None = None
    selection_reg_exp: str | None = Field(default=None, alias="selectionRegExp")


class GeoipConf(BaseModel):
    """Configuration for the geoip function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    file: str
    in_field: str | None = Field(default="ip", alias="inField")
    out_field: str | None = Field(default="geoip", alias="outField")
    additional_fields: list[GeoipAdditionalField] | None = Field(default=None, alias="additionalFields")
    out_field_mappings: dict[str, Any] | None = Field(default=None, alias="outFieldMappings")


class GrokConf(BaseModel):
    """Configuration for the grok function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    pattern: str
    pattern_list: list[PatternListItem] | None = Field(default=None, alias="patternList")
    source: str | None = None


class JsonUnrollConf(BaseModel):
    """Configuration for the json_unroll function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    path: str
    name: str | None = None


class LookupConf(BaseModel):
    """Configuration for the lookup function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    file: str
    db_lookup: bool | None = Field(default=None, alias="dbLookup")
    match_mode: str | None = Field(default=None, alias="matchMode")
    match_type: str | None = Field(default=None, alias="matchType")
    reload_period_sec: int | None = Field(default=None, alias="reloadPeriodSec")
    in_fields: list[LookupInField] | None = Field(default=None, alias="inFields")
    out_fields: list[LookupOutField] | None = Field(default=None, alias="outFields")
    add_to_event: bool | None = Field(default=None, alias="addToEvent")
    ignore_case: bool | None = Field(default=None, alias="ignoreCase")


class MaskConf(BaseModel):
    """Configuration for the mask function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    rules: Annotated[list[MaskRule], Field(default_factory=list)]
    fields: list[str] | None = None
    depth: int | None = None
    flags: list[EvalField] | None = None


class NumerifyConf(BaseModel):
    """Configuration for the numerify function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    depth: int | None = None
    ignore_fields: list[str] | None = Field(default=None, alias="ignoreFields")
    filter_expr: str | None = Field(default=None, alias="filterExpr")
    format: str | None = None
    digits: int | None = None


class OtlpLogsConf(BaseModel):
    """Configuration for the otlp_logs function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    drop_non_log_events: bool | None = Field(default=None, alias="dropNonLogEvents")
    batch_otlp_logs: bool | None = Field(default=None, alias="batchOTLPLogs")
    send_batch_size: int | None = Field(default=None, alias="sendBatchSize")
    timeout: int | None = None
    send_batch_max_size: int | None = Field(default=None, alias="sendBatchMaxSize")
    metadata_keys: list[str] | None = Field(default=None, alias="metadataKeys")
    metadata_cardinality_limit: int | None = Field(default=None, alias="metadataCardinalityLimit")


class OtlpMetricsConf(BaseModel):
    """Configuration for the otlp_metrics function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    resource_attribute_prefixes: list[str] | None = Field(default=None, alias="resourceAttributePrefixes")
    drop_non_metric_events: bool | None = Field(default=None, alias="dropNonMetricEvents")
    otlp_version: str | None = Field(default=None, alias="otlpVersion")
    batch_otlp_metrics: bool | None = Field(default=None, alias="batchOTLPMetrics")
    send_batch_size: int | None = Field(default=None, alias="sendBatchSize")
    timeout: int | None = None
    send_batch_max_size: int | None = Field(default=None, alias="sendBatchMaxSize")
    metadata_keys: list[str] | None = Field(default=None, alias="metadataKeys")
    metadata_cardinality_limit: int | None = Field(default=None, alias="metadataCardinalityLimit")


class OtlpTracesConf(BaseModel):
    """Configuration for the otlp_traces function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    drop_non_trace_events: bool | None = Field(default=None, alias="dropNonTraceEvents")
    otlp_version: str | None = Field(default=None, alias="otlpVersion")
    batch_otlp_traces: bool | None = Field(default=None, alias="batchOTLPTraces")
    send_batch_size: int | None = Field(default=None, alias="sendBatchSize")
    timeout: int | None = None
    send_batch_max_size: int | None = Field(default=None, alias="sendBatchMaxSize")
    metadata_keys: list[str] | None = Field(default=None, alias="metadataKeys")
    metadata_cardinality_limit: int | None = Field(default=None, alias="metadataCardinalityLimit")


class PublishMetricsConf(BaseModel):
    """Configuration for the publish_metrics function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    fields: list[PublishMetricField] | None = None
    overwrite: bool | None = None
    dimensions: list[str] | None = None
    remove_metrics: list[str] | None = Field(default=None, alias="removeMetrics")
    remove_dimensions: list[str] | None = Field(default=None, alias="removeDimensions")


class RedisConf(BaseModel):
    """Configuration for the redis function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    commands: Annotated[list[RedisCommand], Field(default_factory=list)]
    deployment_type: str | None = Field(default="standalone", alias="deploymentType")
    auth_type: str | None = Field(default="none", alias="authType")
    max_block_secs: int | None = Field(default=None, alias="maxBlockSecs")
    enable_client_side_caching: bool | None = Field(default=None, alias="enableClientSideCaching")
    url: str | None = None
    tls_options: TlsOptions | None = Field(default=None, alias="tlsOptions")
    root_nodes: list[RootNode] | None = Field(default=None, alias="rootNodes")
    tls: bool | None = None
    scale_reads: str | None = Field(default=None, alias="scaleReads")
    master_name: str | None = Field(default=None, alias="masterName")
    username: str | None = None
    password: str | None = None
    credentials_secret: str | None = Field(default=None, alias="credentialsSecret")
    text_secret: str | None = Field(default=None, alias="textSecret")


class RegexExtractConf(BaseModel):
    """Configuration for the regex_extract function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    regex: str
    regex_list: list[RegexListItem] | None = Field(default=None, alias="regexList")
    source: str | None = None
    iterations: int | None = None
    field_name_expression: str | None = Field(default=None, alias="fieldNameExpression")
    overwrite: bool | None = None


class RegexFilterConf(BaseModel):
    """Configuration for the regex_filter function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    regex: str | None = None
    regex_list: list[RegexListItem] | None = Field(default=None, alias="regexList")
    field: str | None = None


class RenameConf(BaseModel):
    """Configuration for the rename function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    base_fields: list[str] | None = Field(default=None, alias="baseFields")
    rename: list[RenameField] | None = None
    rename_expr: str | None = Field(default=None, alias="renameExpr")
    wildcard_depth: int | None = Field(default=None, alias="wildcardDepth")


class RollupMetricsConf(BaseModel):
    """Configuration for the rollup_metrics function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    dimensions: list[str] | None = None
    time_window: str | None = Field(default=None, alias="timeWindow")
    gauge_rollup: str | None = Field(default=None, alias="gaugeRollup")


class SamplingConf(BaseModel):
    """Configuration for the sampling function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    rules: list[SamplingRule] | None = None


class SerdeConf(BaseModel):
    """Configuration for the serde (parser) function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    mode: str = "extract"
    type: str = "csv"
    src_field: str | None = Field(default="_raw", alias="srcField")
    dst_field: str | None = Field(default=None, alias="dstField")
    fields: list[str] | None = None
    keep: list[str] | None = None
    remove: list[str] | None = None
    field_filter_expr: str | None = Field(default=None, alias="fieldFilterExpr")
    clean_fields: bool | None = Field(default=None, alias="cleanFields")
    allowed_key_chars: list[str] | None = Field(default=None, alias="allowedKeyChars")
    allowed_value_chars: list[str] | None = Field(default=None, alias="allowedValueChars")
    delim_char: str | None = Field(default=None, alias="delimChar")
    quote_char: str | None = Field(default=None, alias="quoteChar")
    escape_char: str | None = Field(default=None, alias="escapeChar")
    null_value: str | None = Field(default=None, alias="nullValue")
    regex: str | None = None
    regex_list: list[RegexListItem] | None = Field(default=None, alias="regexList")
    iterations: int | None = None
    field_name_expression: str | None = Field(default=None, alias="fieldNameExpression")
    overwrite: bool | None = None
    pattern: str | None = None
    pattern_list: list[PatternListItem] | None = Field(default=None, alias="patternList")


class SerializeConf(BaseModel):
    """Configuration for the serialize function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: str = "csv"
    fields: list[str] | None = None
    src_field: str | None = Field(default=None, alias="srcField")
    dst_field: str | None = Field(default="_raw", alias="dstField")
    delim_char: str | None = Field(default=None, alias="delimChar")
    quote_char: str | None = Field(default=None, alias="quoteChar")
    escape_char: str | None = Field(default=None, alias="escapeChar")
    null_value: str | None = Field(default=None, alias="nullValue")
    clean_fields: bool | None = Field(default=None, alias="cleanFields")
    pair_delimiter: str | None = Field(default=None, alias="pairDelimiter")
    key_value_delimiter: str | None = Field(default=None, alias="keyValueDelimiter")


class SidlookupConf(BaseModel):
    """Configuration for the sidlookup function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    fields: list[SidLookupField] | None = None


class SnmpTrapSerializeConf(BaseModel):
    """Configuration for the snmp_trap_serialize function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    strict: bool | None = None
    drop_failed_events: bool | None = Field(default=None, alias="dropFailedEvents")
    v3_user: V3User | None = Field(default=None, alias="v3User")


class SuppressConf(BaseModel):
    """Configuration for the suppress function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    key_expr: str = Field(..., alias="keyExpr")
    allow: int = 1
    suppress_period_sec: int = Field(default=30, alias="suppressPeriodSec")
    drop_events_mode: bool | None = Field(default=None, alias="dropEventsMode")
    max_cache_size: int | None = Field(default=None, alias="maxCacheSize")
    cache_idle_timeout_periods: int | None = Field(default=None, alias="cacheIdleTimeoutPeriods")
    num_events_idle_timeout_trigger: int | None = Field(default=None, alias="numEventsIdleTimeoutTrigger")


class TeeConf(BaseModel):
    """Configuration for the tee function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    command: str
    args: list[str] | None = None
    restart_on_exit: bool | None = Field(default=None, alias="restartOnExit")
    env: dict[str, str] | None = None


class TrimTimestampConf(BaseModel):
    """Configuration for the trim_timestamp function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    field: str | None = None


class UnrollConf(BaseModel):
    """Configuration for the unroll function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    src_expr: str = Field(default="_raw", alias="srcExpr")
    dst_field: str = Field(default="_raw", alias="dstField")


class XmlUnrollConf(BaseModel):
    """Configuration for the xml_unroll function."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    unroll: str
    inherit: str | None = None
    unroll_idx_field: str | None = Field(default=None, alias="unrollIdxField")
    pretty: bool | None = None


# =============================================================================
# Union type for all function configurations
# =============================================================================

# Type alias for all possible function configurations
FunctionConf = (
    AggregateMetricsConf
    | AggregationConf
    | AutoTimestampConf
    | CefConf
    | ChainConf
    | CloneConf
    | CodeConf
    | CommentConf
    | DnsLookupConf
    | DropConf
    | DropDimensionsConf
    | DynamicSamplingConf
    | EvalConf
    | EventBreakerConf
    | FlattenConf
    | FoldkeysConf
    | GeoipConf
    | GrokConf
    | JsonUnrollConf
    | LookupConf
    | MaskConf
    | NumerifyConf
    | OtlpLogsConf
    | OtlpMetricsConf
    | OtlpTracesConf
    | PublishMetricsConf
    | RedisConf
    | RegexExtractConf
    | RegexFilterConf
    | RenameConf
    | RollupMetricsConf
    | SamplingConf
    | SerdeConf
    | SerializeConf
    | SidlookupConf
    | SnmpTrapSerializeConf
    | SuppressConf
    | TeeConf
    | TrimTimestampConf
    | UnrollConf
    | XmlUnrollConf
    | dict[str, Any]  # Fallback for unknown function types
)

# Mapping from function ID to configuration class
FUNCTION_CONF_MAP: dict[str, type[BaseModel]] = {
    "aggregate_metrics": AggregateMetricsConf,
    "aggregation": AggregationConf,
    "auto_timestamp": AutoTimestampConf,
    "cef": CefConf,
    "chain": ChainConf,
    "clone": CloneConf,
    "code": CodeConf,
    "comment": CommentConf,
    "dns_lookup": DnsLookupConf,
    "drop": DropConf,
    "drop_dimensions": DropDimensionsConf,
    "dynamic_sampling": DynamicSamplingConf,
    "eval": EvalConf,
    "event_breaker": EventBreakerConf,
    "flatten": FlattenConf,
    "foldkeys": FoldkeysConf,
    "geoip": GeoipConf,
    "grok": GrokConf,
    "json_unroll": JsonUnrollConf,
    "lookup": LookupConf,
    "mask": MaskConf,
    "numerify": NumerifyConf,
    "otlp_logs": OtlpLogsConf,
    "otlp_metrics": OtlpMetricsConf,
    "otlp_traces": OtlpTracesConf,
    "publish_metrics": PublishMetricsConf,
    "redis": RedisConf,
    "regex_extract": RegexExtractConf,
    "regex_filter": RegexFilterConf,
    "rename": RenameConf,
    "rollup_metrics": RollupMetricsConf,
    "sampling": SamplingConf,
    "serde": SerdeConf,
    "serialize": SerializeConf,
    "sidlookup": SidlookupConf,
    "snmp_trap_serialize": SnmpTrapSerializeConf,
    "suppress": SuppressConf,
    "tee": TeeConf,
    "trim_timestamp": TrimTimestampConf,
    "unroll": UnrollConf,
    "xml_unroll": XmlUnrollConf,
}


def get_function_conf_class(function_id: str) -> type[BaseModel]:
    """Get the configuration class for a function ID.

    Args:
        function_id: The function type identifier (e.g., "eval", "mask").

    Returns:
        The Pydantic model class for the function's configuration.
        Returns a generic BaseModel for unknown function types.

    """
    return FUNCTION_CONF_MAP.get(function_id, DropConf)


def parse_function_conf(function_id: str, conf_data: dict[str, Any]) -> BaseModel:
    """Parse a function configuration dict into the appropriate typed model.

    Args:
        function_id: The function type identifier.
        conf_data: The raw configuration dictionary from the API.

    Returns:
        A typed Pydantic model instance with the configuration data.

    """
    conf_class = get_function_conf_class(function_id)
    return conf_class.model_validate(conf_data)


# =============================================================================
# Pipeline Function Model
# =============================================================================


class PipelineFunctionConf(BaseModel):
    """A pipeline function with its configuration.

    This model captures all fields of a pipeline function, preserving the
    function-specific configuration in a typed manner.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    """Function type identifier (e.g., 'eval', 'mask', 'drop')."""

    conf: dict[str, Any] = Field(default_factory=dict)
    """Function-specific configuration. Uses dict to preserve all data."""

    filter_: Annotated[str | None, pydantic.Field(alias="filter")] = "true"
    """Filter expression that selects events to process."""

    description: str | None = None
    """Optional description of this function step."""

    disabled: bool | None = None
    """If True, events will not pass through this function."""

    final: bool | None = None
    """If True, stops results from passing to downstream functions."""

    group_id: str | None = Field(default=None, alias="groupId")
    """Optional group ID for organizing functions."""


# =============================================================================
# Pipeline Configuration Model
# =============================================================================


class PipelineGroups(BaseModel):
    """A pipeline function group."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    description: str | None = None
    disabled: bool | None = None


class PipelineConf(BaseModel):
    """Configuration for a pipeline."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    async_func_timeout: int | None = Field(default=None, alias="asyncFuncTimeout")
    """Time (ms) to wait for async function completion."""

    output: str | None = "default"
    """Output destination for processed events."""

    description: str | None = None
    """Pipeline description."""

    streamtags: list[str] | None = None
    """Tags for filtering and grouping."""

    functions: list[PipelineFunctionConf] | None = None
    """List of functions in this pipeline."""

    groups: dict[str, PipelineGroups] | None = None
    """Function groups within the pipeline."""


class PipelineItem(BaseModel):
    """A complete pipeline item as returned by the API."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    """Pipeline identifier."""

    conf: PipelineConf
    """Pipeline configuration including functions."""


# =============================================================================
# Utility Functions
# =============================================================================


def serialize_pipeline_item(item: PipelineItem) -> dict[str, Any]:
    """Serialize a pipeline item to a JSON-compatible dictionary.

    Args:
        item: The pipeline item to serialize.

    Returns:
        A dictionary representation preserving all data including function configs.

    """
    return item.model_dump(mode="json", exclude_none=True, by_alias=True)


def parse_pipeline_item(data: dict[str, Any]) -> PipelineItem:
    """Parse a raw pipeline dictionary into a typed PipelineItem.

    Args:
        data: Raw pipeline data from the API.

    Returns:
        A typed PipelineItem instance.

    """
    return PipelineItem.model_validate(data)


__all__ = [
    "FUNCTION_CONF_MAP",
    "AggregateMetricsConf",
    "AggregationConf",
    "AutoTimestampConf",
    "CefConf",
    "ChainConf",
    "CloneConf",
    "CodeConf",
    "CommentConf",
    "DnsLookupConf",
    "DropConf",
    "DropDimensionsConf",
    "DynamicSamplingConf",
    "EvalConf",
    "EventBreakerConf",
    "FlattenConf",
    "FoldkeysConf",
    "FunctionConf",
    "GeoipConf",
    "GrokConf",
    "JsonUnrollConf",
    "LookupConf",
    "MaskConf",
    "NumerifyConf",
    "OtlpLogsConf",
    "OtlpMetricsConf",
    "OtlpTracesConf",
    "PipelineConf",
    "PipelineFunctionConf",
    "PipelineGroups",
    "PipelineItem",
    "PublishMetricsConf",
    "RedisConf",
    "RegexExtractConf",
    "RegexFilterConf",
    "RenameConf",
    "RollupMetricsConf",
    "SamplingConf",
    "SerdeConf",
    "SerializeConf",
    "SidlookupConf",
    "SnmpTrapSerializeConf",
    "SuppressConf",
    "TeeConf",
    "TrimTimestampConf",
    "UnrollConf",
    "XmlUnrollConf",
    "get_function_conf_class",
    "parse_function_conf",
    "parse_pipeline_item",
    "serialize_pipeline_item",
]
