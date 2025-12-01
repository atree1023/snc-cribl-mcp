"""Pydantic models for Cribl collector sources (SavedJobs).

This module defines typed models for all Cribl collector source types. Each collector
has a specific configuration schema defined in docs/collectors/<id>.json.

Collectors are "Saved Jobs" in Cribl terminology and are fetched from the
/api/v1/m/{group_id}/lib/jobs endpoint rather than the /system/inputs endpoint
used by regular sources.

The SDK does not have native support for collectors, so we define these models
for type validation and consistent serialization.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# =============================================================================
# Generic Fallback Model for Unknown Collector Types
# =============================================================================


class GenericCollectorConf(BaseModel):
    """Generic collector configuration for unknown or unsupported collector types.

    This model accepts any extra fields and is used as a fallback when the collector
    type is not recognized or not yet implemented.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)


# =============================================================================
# Common Helper Models
# =============================================================================


class PathExtractor(BaseModel):
    """A path extractor for template token enrichment."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    key: str
    """Token name from the template path."""

    expression: str
    """JavaScript expression to evaluate the token."""


class RequestHeader(BaseModel):
    """HTTP request header for REST collectors."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    value: str


class RequestParam(BaseModel):
    """HTTP request parameter for REST collectors."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str
    value: str


class RetryRules(BaseModel):
    """HTTP retry rules configuration."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: str = "backoff"
    """Retry algorithm: none, backoff, or static."""

    interval: int | None = None
    """Time interval between retries in ms."""

    limit: int | None = None
    """Maximum retry attempts."""

    multiplier: int | None = None
    """Backoff multiplier for exponential backoff."""

    max_interval_ms: int | None = Field(default=None, alias="maxIntervalMs")
    """Maximum interval between retries."""

    codes: list[int] | None = None
    """HTTP status codes that trigger retries."""

    enable_header: bool | None = Field(default=None, alias="enableHeader")
    """Honor Retry-After header."""

    retry_header_name: str | None = Field(default=None, alias="retryHeaderName")
    """Name of the Retry-After header."""

    retry_connect_timeout: bool | None = Field(default=None, alias="retryConnectTimeout")
    """Retry on connection timeout."""

    retry_connect_reset: bool | None = Field(default=None, alias="retryConnectReset")
    """Retry on connection reset."""


class PaginationConfig(BaseModel):
    """Pagination configuration for REST collectors."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: str = "none"
    """Pagination type: none, response_body, response_header, response_header_link, request_offset, request_page."""

    attribute: str | list[str] | None = None
    """Response attributes containing next-page info."""

    max_pages: int | None = Field(default=None, alias="maxPages")
    """Maximum pages to retrieve."""

    last_page_expr: str | None = Field(default=None, alias="lastPageExpr")
    """JavaScript expression to detect last page."""

    next_relation_attribute: str | None = Field(default=None, alias="nextRelationAttribute")
    """Relation name for next page in link header."""

    cur_relation_attribute: str | None = Field(default=None, alias="curRelationAttribute")
    """Relation name for current page in link header."""

    offset_field: str | None = Field(default=None, alias="offsetField")
    """Query parameter for offset."""

    offset: int | None = None
    """Starting offset."""

    limit_field: str | None = Field(default=None, alias="limitField")
    """Query parameter for limit."""

    limit: int | None = None
    """Records per request."""

    total_record_field: str | None = Field(default=None, alias="totalRecordField")
    """Field containing total record count."""

    page_field: str | None = Field(default=None, alias="pageField")
    """Query parameter for page number."""

    page: int | None = None
    """Starting page number."""

    size_field: str | None = Field(default=None, alias="sizeField")
    """Query parameter for page size."""

    size: int | None = None
    """Records per page."""

    total_page_field: str | None = Field(default=None, alias="totalPageField")
    """Field containing total page count."""

    zero_indexed: bool | None = Field(default=None, alias="zeroIndexed")
    """Whether pagination is zero-indexed."""


class DiscoveryConfig(BaseModel):
    """Discovery configuration for REST/health_check collectors."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    discover_type: str = Field(default="none", alias="discoverType")
    """Discovery type: none, http, json, or list."""

    discover_url: str | None = Field(default=None, alias="discoverUrl")
    """URL for HTTP discovery."""

    discover_method: str | None = Field(default=None, alias="discoverMethod")
    """HTTP method for discovery: get, post, post_with_body, other."""

    discover_verb: str | None = Field(default=None, alias="discoverVerb")
    """Custom HTTP verb for discovery."""

    discover_body: str | None = Field(default=None, alias="discoverBody")
    """POST body template for discovery."""

    discover_request_params: list[RequestParam] | None = Field(default=None, alias="discoverRequestParams")
    """Request parameters for discovery."""

    discover_request_headers: list[RequestHeader] | None = Field(default=None, alias="discoverRequestHeaders")
    """Request headers for discovery."""

    pagination: PaginationConfig | None = None
    """Pagination configuration for discovery."""

    discover_data_field: str | None = Field(default=None, alias="discoverDataField")
    """Path to discovery results in response."""

    enable_strict_discover_parsing: bool | None = Field(default=None, alias="enableStrictDiscoverParsing")
    """Enable strict response parsing."""

    discover_response_format: str | None = Field(default=None, alias="discoverResponseFormat")
    """Response format when strict parsing enabled."""

    enable_discover_code: bool | None = Field(default=None, alias="enableDiscoverCode")
    """Enable custom code for formatting results."""

    format_result_code: str | None = Field(default=None, alias="formatResultCode")
    """Custom JavaScript code for formatting results."""

    manual_discover_result: str | None = Field(default=None, alias="manualDiscoverResult")
    """Hard-coded discovery result JSON."""

    item_list: list[str] | None = Field(default=None, alias="itemList")
    """List of items for list discovery type."""


class ScheduleConfig(BaseModel):
    """Schedule configuration for collector jobs."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    enabled: bool | None = None
    """Whether scheduling is enabled."""

    skippable: bool | None = None
    """Whether job can be delayed if system is at capacity."""

    resume_missed: bool | None = Field(default=None, alias="resumeMissed")
    """Run missed jobs on restart."""

    cron_schedule: str | None = Field(default=None, alias="cronSchedule")
    """Cron expression for scheduling."""

    max_concurrent_runs: int | None = Field(default=None, alias="maxConcurrentRuns")
    """Maximum concurrent instances."""

    run: dict[str, Any] | None = None
    """Run settings including mode, time range, etc."""


class StateTrackingConfig(BaseModel):
    """State tracking configuration for scheduled collectors."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    enabled: bool | None = None
    """Whether state tracking is enabled."""

    state_update_expression: str | None = Field(default=None, alias="stateUpdateExpression")
    """JavaScript expression for state updates."""

    state_merge_expression: str | None = Field(default=None, alias="stateMergeExpression")
    """JavaScript expression for merging states."""

    tracking_column: str | None = Field(default=None, alias="trackingColumn")
    """Database column to track (for database collector)."""


class SchedulingConfig(BaseModel):
    """Scheduling-specific configuration nested under __scheduling."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    state_tracking: StateTrackingConfig | None = Field(default=None, alias="stateTracking")
    """State tracking configuration."""


# =============================================================================
# Collector-Specific Configuration Models
# =============================================================================


class S3CollectorConf(BaseModel):
    """Configuration for the S3 collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["s3"] = "s3"
    """Collector type identifier."""

    bucket: str
    """S3 bucket name."""

    output_name: str | None = Field(default=None, alias="outputName")
    """Auto-populate from destination."""

    region: str | None = None
    """AWS region."""

    path: str | None = None
    """Directory path with optional templating."""

    partitioning_scheme: str | None = Field(default=None, alias="partitioningScheme")
    """Partitioning scheme: none or ddss."""

    extractors: list[PathExtractor] | None = None
    """Path extractors for template tokens."""

    aws_authentication_method: str | None = Field(default="auto", alias="awsAuthenticationMethod")
    """Auth method: auto, manual, or secret."""

    aws_api_key: str | None = Field(default=None, alias="awsApiKey")
    """AWS access key (manual auth)."""

    aws_secret_key: str | None = Field(default=None, alias="awsSecretKey")
    """AWS secret key (manual auth)."""

    aws_secret: str | None = Field(default=None, alias="awsSecret")
    """Secret reference (secret auth)."""

    endpoint: str | None = None
    """S3-compatible endpoint override."""

    signature_version: str | None = Field(default="v4", alias="signatureVersion")
    """S3 signature version: v2 or v4."""

    enable_assume_role: bool | None = Field(default=None, alias="enableAssumeRole")
    """Use AssumeRole credentials."""

    assume_role_arn: str | None = Field(default=None, alias="assumeRoleArn")
    """ARN of role to assume."""

    assume_role_external_id: str | None = Field(default=None, alias="assumeRoleExternalId")
    """External ID for AssumeRole."""

    duration_seconds: int | None = Field(default=None, alias="durationSeconds")
    """AssumeRole session duration."""

    max_batch_size: int | None = Field(default=None, alias="maxBatchSize")
    """Maximum objects per batch."""

    recurse: bool | None = None
    """Recurse through subdirectories."""

    reuse_connections: bool | None = Field(default=None, alias="reuseConnections")
    """Reuse HTTP connections."""

    reject_unauthorized: bool | None = Field(default=None, alias="rejectUnauthorized")
    """Reject self-signed certificates."""

    verify_permissions: bool | None = Field(default=None, alias="verifyPermissions")
    """Verify bucket permissions."""

    disable_time_filter: bool | None = Field(default=None, alias="disableTimeFilter")
    """Disable event time filtering."""

    parquet_chunk_size_mb: int | None = Field(default=None, alias="parquetChunkSizeMB")
    """Parquet chunk size limit in MB."""

    parquet_chunk_download_timeout: int | None = Field(default=None, alias="parquetChunkDownloadTimeout")
    """Parquet chunk download timeout in seconds."""


class AzureBlobCollectorConf(BaseModel):
    """Configuration for the Azure Blob Storage collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["azure_blob"] = "azure_blob"
    """Collector type identifier."""

    container_name: str = Field(..., alias="containerName")
    """Azure container name."""

    output_name: str | None = Field(default=None, alias="outputName")
    """Auto-populate from destination."""

    auth_type: str | None = Field(default="manual", alias="authType")
    """Auth method: manual, secret, clientSecret, or clientCert."""

    connection_string: str | None = Field(default=None, alias="connectionString")
    """Azure connection string (manual auth)."""

    text_secret: str | None = Field(default=None, alias="textSecret")
    """Text secret reference (secret auth)."""

    storage_account_name: str | None = Field(default=None, alias="storageAccountName")
    """Storage account name (service principal auth)."""

    tenant_id: str | None = Field(default=None, alias="tenantId")
    """Azure tenant ID."""

    client_id: str | None = Field(default=None, alias="clientId")
    """Service principal client ID."""

    client_text_secret: str | None = Field(default=None, alias="clientTextSecret")
    """Client secret (service principal auth)."""

    endpoint_suffix: str | None = Field(default=None, alias="endpointSuffix")
    """Azure endpoint suffix."""

    azure_cloud: str | None = Field(default=None, alias="azureCloud")
    """Azure cloud environment."""

    path: str | None = None
    """Directory path with optional templating."""

    extractors: list[PathExtractor] | None = None
    """Path extractors for template tokens."""

    recurse: bool | None = None
    """Recurse through subdirectories."""

    include_metadata: bool | None = Field(default=None, alias="includeMetadata")
    """Include blob metadata in events."""

    include_tags: bool | None = Field(default=None, alias="includeTags")
    """Include blob tags in events."""

    max_batch_size: int | None = Field(default=None, alias="maxBatchSize")
    """Maximum objects per batch."""

    parquet_chunk_size_mb: int | None = Field(default=None, alias="parquetChunkSizeMB")
    """Parquet chunk size limit in MB."""

    parquet_chunk_download_timeout: int | None = Field(default=None, alias="parquetChunkDownloadTimeout")
    """Parquet chunk download timeout in seconds."""


class GoogleCloudStorageCollectorConf(BaseModel):
    """Configuration for the Google Cloud Storage collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["google_cloud_storage"] = "google_cloud_storage"
    """Collector type identifier."""

    bucket: str
    """GCS bucket name."""

    output_name: str | None = Field(default=None, alias="outputName")
    """Auto-populate from destination."""

    auth_type: str | None = Field(default="manual", alias="authType")
    """Auth method: auto, manual, or secret."""

    service_account_credentials: str | None = Field(default=None, alias="serviceAccountCredentials")
    """Service account JSON credentials (manual auth)."""

    text_secret: str | None = Field(default=None, alias="textSecret")
    """Text secret reference (secret auth)."""

    path: str | None = None
    """Directory path with optional templating."""

    extractors: list[PathExtractor] | None = None
    """Path extractors for template tokens."""

    endpoint: str | None = None
    """GCS endpoint override."""

    recurse: bool | None = None
    """Recurse through subdirectories."""

    max_batch_size: int | None = Field(default=None, alias="maxBatchSize")
    """Maximum objects per batch."""

    disable_time_filter: bool | None = Field(default=None, alias="disableTimeFilter")
    """Disable event time filtering."""

    parquet_chunk_size_mb: int | None = Field(default=None, alias="parquetChunkSizeMB")
    """Parquet chunk size limit in MB."""

    parquet_chunk_download_timeout: int | None = Field(default=None, alias="parquetChunkDownloadTimeout")
    """Parquet chunk download timeout in seconds."""


class FilesystemCollectorConf(BaseModel):
    """Configuration for the Filesystem collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["filesystem"] = "filesystem"
    """Collector type identifier."""

    path: str
    """Directory path with optional templating."""

    output_name: str | None = Field(default=None, alias="outputName")
    """Auto-populate from destination."""

    extractors: list[PathExtractor] | None = None
    """Path extractors for template tokens."""

    recurse: bool | None = None
    """Recurse through subdirectories."""

    max_batch_size: int | None = Field(default=None, alias="maxBatchSize")
    """Maximum files per batch."""


class DatabaseCollectorConf(BaseModel):
    """Configuration for the Database collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["database"] = "database"
    """Collector type identifier."""

    connection_id: str = Field(..., alias="connectionId")
    """Database connection reference."""

    query: str
    """SQL query expression."""

    query_validation_enabled: bool | None = Field(default=None, alias="queryValidationEnabled")
    """Enable basic query validation."""

    default_breakers: str | None = Field(default=None, alias="defaultBreakers")
    """Default event breakers."""

    scheduling: SchedulingConfig | None = Field(default=None, alias="__scheduling")
    """Scheduling configuration including state tracking."""


class RestCollectorConf(BaseModel):
    """Configuration for the REST API collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["rest"] = "rest"
    """Collector type identifier."""

    collect_url: str = Field(..., alias="collectUrl")
    """URL for collection requests."""

    collect_method: str = Field(..., alias="collectMethod")
    """HTTP method: get, post, post_with_body, or other."""

    authentication: str
    """Auth method: none, basic, basicSecret, login, loginSecret, oauth, oauthSecret, google_oauth, google_oauthSecret, hmac."""

    discovery: DiscoveryConfig | None = None
    """Discovery configuration."""

    collect_verb: str | None = Field(default=None, alias="collectVerb")
    """Custom HTTP verb for collection."""

    collect_body: str | None = Field(default=None, alias="collectBody")
    """POST body template for collection."""

    collect_request_params: list[RequestParam] | None = Field(default=None, alias="collectRequestParams")
    """Request parameters for collection."""

    collect_request_headers: list[RequestHeader] | None = Field(default=None, alias="collectRequestHeaders")
    """Request headers for collection."""

    pagination: PaginationConfig | None = None
    """Pagination configuration for collection."""

    # Authentication fields (varies by auth type)
    username: str | None = None
    """Username for basic/login auth."""

    password: str | None = None
    """Password for basic/login auth."""

    credentials_secret: str | None = Field(default=None, alias="credentialsSecret")
    """Credentials secret reference."""

    login_url: str | None = Field(default=None, alias="loginUrl")
    """Login URL for login/oauth auth."""

    login_body: str | None = Field(default=None, alias="loginBody")
    """POST body template for login."""

    token_resp_attribute: str | None = Field(default=None, alias="tokenRespAttribute")
    """Path to token in login response."""

    auth_header_key: str | None = Field(default=None, alias="authHeaderKey")
    """Authorization header name."""

    auth_header_expr: str | None = Field(default=None, alias="authHeaderExpr")
    """JavaScript expression for auth header value."""

    get_auth_token_from_header: bool | None = Field(default=None, alias="getAuthTokenFromHeader")
    """Extract token from response header."""

    auth_request_params: list[RequestParam] | None = Field(default=None, alias="authRequestParams")
    """Extra auth request parameters."""

    auth_request_headers: list[RequestHeader] | None = Field(default=None, alias="authRequestHeaders")
    """Auth request headers."""

    client_secret_param_name: str | None = Field(default=None, alias="clientSecretParamName")
    """OAuth client secret parameter name."""

    client_secret_param_value: str | None = Field(default=None, alias="clientSecretParamValue")
    """OAuth client secret value."""

    text_secret: str | None = Field(default=None, alias="textSecret")
    """Text secret reference."""

    scopes: list[str] | None = None
    """Google OAuth scopes."""

    service_account_credentials: str | None = Field(default=None, alias="serviceAccountCredentials")
    """Google service account credentials."""

    subject: str | None = None
    """Google OAuth impersonated email."""

    hmac_function_id: str | None = Field(default=None, alias="hmacFunctionId")
    """HMAC function reference."""

    timeout: int | None = None
    """Request timeout in seconds."""

    use_round_robin_dns: bool | None = Field(default=None, alias="useRoundRobinDns")
    """Use round-robin DNS."""

    disable_time_filter: bool | None = Field(default=None, alias="disableTimeFilter")
    """Disable event time filtering."""

    decode_url: bool | None = Field(default=None, alias="decodeUrl")
    """Decode URL before sending."""

    reject_unauthorized: bool | None = Field(default=None, alias="rejectUnauthorized")
    """Reject self-signed certificates."""

    capture_headers: bool | None = Field(default=None, alias="captureHeaders")
    """Capture response headers."""

    stop_on_empty_results: bool | None = Field(default=None, alias="stopOnEmptyResults")
    """Stop pagination on empty results."""

    safe_headers: list[str] | None = Field(default=None, alias="safeHeaders")
    """Headers safe to log in plain text."""

    retry_rules: RetryRules | None = Field(default=None, alias="retryRules")
    """HTTP retry configuration."""

    scheduling: SchedulingConfig | None = Field(default=None, alias="__scheduling")
    """Scheduling configuration."""


class SplunkCollectorConf(BaseModel):
    """Configuration for the Splunk collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["splunk"] = "splunk"
    """Collector type identifier."""

    search_head: str = Field(..., alias="searchHead")
    """Splunk search head URL."""

    search: str
    """Splunk search query."""

    endpoint: str
    """Search API endpoint."""

    output_mode: str = Field(..., alias="outputMode")
    """Output format: csv or json."""

    authentication: str
    """Auth method: none, basic, basicSecret, token, tokenSecret, login, loginSecret."""

    earliest: str | None = None
    """Earliest time boundary."""

    latest: str | None = None
    """Latest time boundary."""

    collect_request_params: list[RequestParam] | None = Field(default=None, alias="collectRequestParams")
    """Extra request parameters."""

    collect_request_headers: list[RequestHeader] | None = Field(default=None, alias="collectRequestHeaders")
    """Extra request headers."""

    # Authentication fields
    username: str | None = None
    """Username for basic/login auth."""

    password: str | None = None
    """Password for basic/login auth."""

    credentials_secret: str | None = Field(default=None, alias="credentialsSecret")
    """Credentials secret reference."""

    token: str | None = None
    """Bearer token."""

    token_secret: str | None = Field(default=None, alias="tokenSecret")
    """Token secret reference."""

    login_url: str | None = Field(default=None, alias="loginUrl")
    """Login URL for login auth."""

    login_body: str | None = Field(default=None, alias="loginBody")
    """POST body template for login."""

    token_resp_attribute: str | None = Field(default=None, alias="tokenRespAttribute")
    """Path to token in login response."""

    auth_header_expr: str | None = Field(default=None, alias="authHeaderExpr")
    """JavaScript expression for auth header value."""

    timeout: int | None = None
    """Request timeout in seconds."""

    use_round_robin_dns: bool | None = Field(default=None, alias="useRoundRobinDns")
    """Use round-robin DNS."""

    disable_time_filter: bool | None = Field(default=None, alias="disableTimeFilter")
    """Disable event time filtering."""

    reject_unauthorized: bool | None = Field(default=None, alias="rejectUnauthorized")
    """Reject self-signed certificates."""

    handle_escaped_chars: bool | None = Field(default=None, alias="handleEscapedChars")
    """Preserve escaped characters in search."""

    retry_rules: RetryRules | None = Field(default=None, alias="retryRules")
    """HTTP retry configuration."""


class ScriptCollectorConf(BaseModel):
    """Configuration for the Script collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["script"] = "script"
    """Collector type identifier."""

    discover_script: str = Field(..., alias="discoverScript")
    """Script for discovery."""

    collect_script: str = Field(..., alias="collectScript")
    """Script for collection."""

    shell: str | None = None
    """Shell to execute scripts."""

    env_vars: list[dict[str, str]] | None = Field(default=None, alias="envVars")
    """Environment variables for scripts."""


class HealthCheckCollectorConf(BaseModel):
    """Configuration for the Health Check collector."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["health_check"] = "health_check"
    """Collector type identifier."""

    collect_url: str = Field(..., alias="collectUrl")
    """Health check URL."""

    collect_method: str = Field(..., alias="collectMethod")
    """HTTP method: get, post, post_with_body."""

    authentication: str
    """Auth method: none, basic, basicSecret, login, loginSecret, oauth, oauthSecret."""

    discovery: DiscoveryConfig | None = None
    """Discovery configuration."""

    collect_verb: str | None = Field(default=None, alias="collectVerb")
    """Custom HTTP verb."""

    collect_body: str | None = Field(default=None, alias="collectBody")
    """POST body template."""

    collect_request_params: list[RequestParam] | None = Field(default=None, alias="collectRequestParams")
    """Request parameters."""

    collect_request_headers: list[RequestHeader] | None = Field(default=None, alias="collectRequestHeaders")
    """Request headers."""

    authenticate_collect: bool | None = Field(default=None, alias="authenticateCollect")
    """Authenticate health check call."""

    # Authentication fields (varies by auth type)
    username: str | None = None
    password: str | None = None
    credentials_secret: str | None = Field(default=None, alias="credentialsSecret")
    login_url: str | None = Field(default=None, alias="loginUrl")
    login_body: str | None = Field(default=None, alias="loginBody")
    token_resp_attribute: str | None = Field(default=None, alias="tokenRespAttribute")
    auth_header_expr: str | None = Field(default=None, alias="authHeaderExpr")
    auth_request_params: list[RequestParam] | None = Field(default=None, alias="authRequestParams")
    auth_request_headers: list[RequestHeader] | None = Field(default=None, alias="authRequestHeaders")
    client_secret_param_name: str | None = Field(default=None, alias="clientSecretParamName")
    client_secret_param_value: str | None = Field(default=None, alias="clientSecretParamValue")
    text_secret: str | None = Field(default=None, alias="textSecret")

    timeout: int | None = None
    """Request timeout in seconds."""

    reject_unauthorized: bool | None = Field(default=None, alias="rejectUnauthorized")
    """Reject self-signed certificates."""

    default_breakers: str | None = Field(default=None, alias="defaultBreakers")
    """Default event breakers."""

    safe_headers: list[str] | None = Field(default=None, alias="safeHeaders")
    """Headers safe to log in plain text."""

    retry_rules: RetryRules | None = Field(default=None, alias="retryRules")
    """HTTP retry configuration."""


# =============================================================================
# Union type for all collector configurations
# =============================================================================

# Type alias for all possible collector configurations
CollectorConf = (
    S3CollectorConf
    | AzureBlobCollectorConf
    | GoogleCloudStorageCollectorConf
    | FilesystemCollectorConf
    | DatabaseCollectorConf
    | RestCollectorConf
    | SplunkCollectorConf
    | ScriptCollectorConf
    | HealthCheckCollectorConf
    | GenericCollectorConf  # Fallback for unknown collector types
)

# Mapping from collector type ID to configuration class
COLLECTOR_CONF_MAP: dict[str, type[BaseModel]] = {
    "s3": S3CollectorConf,
    "azure_blob": AzureBlobCollectorConf,
    "google_cloud_storage": GoogleCloudStorageCollectorConf,
    "filesystem": FilesystemCollectorConf,
    "database": DatabaseCollectorConf,
    "rest": RestCollectorConf,
    "splunk": SplunkCollectorConf,
    "script": ScriptCollectorConf,
    "health_check": HealthCheckCollectorConf,
}


def get_collector_conf_class(collector_type: str) -> type[BaseModel]:
    """Get the configuration class for a collector type.

    Args:
        collector_type: The collector type identifier (e.g., "s3", "rest").

    Returns:
        The Pydantic model class for the collector's configuration.
        Returns GenericCollectorConf for unknown types.

    """
    return COLLECTOR_CONF_MAP.get(collector_type, GenericCollectorConf)


def parse_collector_conf(collector_type: str, conf_data: dict[str, Any]) -> BaseModel:
    """Parse a collector configuration dict into the appropriate typed model.

    Args:
        collector_type: The collector type identifier.
        conf_data: The raw configuration dictionary from the API.

    Returns:
        A typed Pydantic model instance with the configuration data.

    """
    conf_class = get_collector_conf_class(collector_type)
    return conf_class.model_validate(conf_data)


# =============================================================================
# SavedJob (Collector) Model
# =============================================================================


class SavedJobCollection(BaseModel):
    """A SavedJob of type 'collection' representing a collector source.

    This model captures the full structure of a collector job as returned
    by the /api/v1/m/{group_id}/lib/jobs endpoint.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    """Unique job identifier."""

    type: Literal["collection"] = "collection"
    """Job type, always 'collection' for collectors."""

    collector: dict[str, Any]
    """Collector-specific configuration. Contains 'type' field identifying the collector."""

    description: str | None = None
    """Job description."""

    ttl: str | None = None
    """Time to keep artifacts after completion."""

    ignore_group_jobs_limit: bool | None = Field(default=None, alias="ignoreGroupJobsLimit")
    """Ignore worker group job limits."""

    remove_fields: list[str] | None = Field(default=None, alias="removeFields")
    """Fields to remove from discover results."""

    resume_on_boot: bool | None = Field(default=None, alias="resumeOnBoot")
    """Resume job if system restarts during execution."""

    environment: str | None = None
    """Git branch restriction."""

    schedule: ScheduleConfig | None = None
    """Schedule configuration."""

    input: dict[str, Any] | None = None
    """Input configuration (event breaker, etc.)."""

    @property
    def collector_type(self) -> str:
        """Get the collector type from the collector configuration."""
        return str(self.collector.get("type", "unknown"))


class SavedJobItem(BaseModel):
    """A generic SavedJob item that can be any job type.

    The API returns jobs of different types (collection, executor, scheduledSearch).
    This model handles all types and provides a way to identify collectors.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    """Unique job identifier."""

    type: str
    """Job type: collection, executor, or scheduledSearch."""

    collector: dict[str, Any] | None = None
    """Collector configuration (only for type='collection')."""

    description: str | None = None
    """Job description."""

    ttl: str | None = None
    """Time to keep artifacts after completion."""

    schedule: ScheduleConfig | None = None
    """Schedule configuration."""

    # Additional fields that may be present on any job type
    input: dict[str, Any] | None = None
    executor: dict[str, Any] | None = None
    saved_query_id: str | None = Field(default=None, alias="savedQueryId")

    def is_collector(self) -> bool:
        """Check if this job is a collector source."""
        return self.type == "collection" and self.collector is not None

    @property
    def collector_type(self) -> str | None:
        """Get the collector type if this is a collector job."""
        if self.collector:
            return str(self.collector.get("type", "unknown"))
        return None


# =============================================================================
# Utility Functions
# =============================================================================


def serialize_saved_job(item: SavedJobItem) -> dict[str, Any]:
    """Serialize a SavedJob item to a JSON-compatible dictionary.

    Args:
        item: The SavedJob item to serialize.

    Returns:
        A dictionary representation preserving all data.

    """
    return item.model_dump(mode="json", exclude_none=True, by_alias=True)


def parse_saved_job(data: dict[str, Any]) -> SavedJobItem:
    """Parse a raw SavedJob dictionary into a typed model.

    Args:
        data: Raw job data from the API.

    Returns:
        A typed SavedJobItem instance.

    """
    return SavedJobItem.model_validate(data)


def filter_collector_jobs(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter a list of jobs to include only collector sources.

    Args:
        jobs: List of raw job dictionaries from the API.

    Returns:
        List of jobs where type is 'collection'.

    """
    return [job for job in jobs if job.get("type") == "collection"]


__all__ = [
    "COLLECTOR_CONF_MAP",
    "AzureBlobCollectorConf",
    "CollectorConf",
    "DatabaseCollectorConf",
    "DiscoveryConfig",
    "FilesystemCollectorConf",
    "GoogleCloudStorageCollectorConf",
    "HealthCheckCollectorConf",
    "PaginationConfig",
    "PathExtractor",
    "RequestHeader",
    "RequestParam",
    "RestCollectorConf",
    "RetryRules",
    "S3CollectorConf",
    "SavedJobCollection",
    "SavedJobItem",
    "ScheduleConfig",
    "SchedulingConfig",
    "ScriptCollectorConf",
    "SplunkCollectorConf",
    "StateTrackingConfig",
    "filter_collector_jobs",
    "get_collector_conf_class",
    "parse_collector_conf",
    "parse_saved_job",
    "serialize_saved_job",
]
