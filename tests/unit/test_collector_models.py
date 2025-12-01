"""Unit tests for collector source Pydantic models.

Validates that the models correctly parse and serialize collector configurations
from the Cribl API, preserving all fields and handling aliases properly.
"""

from snc_cribl_mcp.models.collectors import (
    COLLECTOR_CONF_MAP,
    AzureBlobCollectorConf,
    DatabaseCollectorConf,
    FilesystemCollectorConf,
    GenericCollectorConf,
    GoogleCloudStorageCollectorConf,
    HealthCheckCollectorConf,
    PaginationConfig,
    PathExtractor,
    RequestHeader,
    RestCollectorConf,
    RetryRules,
    S3CollectorConf,
    SavedJobCollection,
    SavedJobItem,
    ScriptCollectorConf,
    SplunkCollectorConf,
    filter_collector_jobs,
    get_collector_conf_class,
    parse_collector_conf,
    parse_saved_job,
    serialize_saved_job,
)


class TestPathExtractor:
    """Tests for PathExtractor model."""

    def test_basic_extractor(self) -> None:
        """Should create a PathExtractor with key and expression."""
        extractor = PathExtractor(key="epoch", expression="{date: new Date(+value*1000)}")
        assert extractor.key == "epoch"
        assert extractor.expression == "{date: new Date(+value*1000)}"


class TestRequestHeader:
    """Tests for RequestHeader model."""

    def test_basic_header(self) -> None:
        """Should create a RequestHeader with name and value."""
        header = RequestHeader(name="Content-Type", value="application/json")
        assert header.name == "Content-Type"
        assert header.value == "application/json"


class TestRetryRules:
    """Tests for RetryRules model."""

    def test_backoff_rules(self) -> None:
        """Should parse backoff retry rules with aliases."""
        rules = RetryRules(
            type="backoff",
            interval=1000,
            limit=5,
            multiplier=2,
            maxIntervalMs=20000,
            codes=[429, 503],
        )
        assert rules.type == "backoff"
        assert rules.interval == 1000
        assert rules.limit == 5
        assert rules.multiplier == 2
        assert rules.max_interval_ms == 20000
        assert rules.codes == [429, 503]

    def test_serialization_with_alias(self) -> None:
        """Should serialize with alias names."""
        rules = RetryRules(type="static", interval=2000, limit=3)
        data = rules.model_dump(by_alias=True)
        assert data["type"] == "static"
        assert data["interval"] == 2000


class TestPaginationConfig:
    """Tests for PaginationConfig model."""

    def test_offset_pagination(self) -> None:
        """Should parse offset-based pagination config."""
        config = PaginationConfig(
            type="request_offset",
            offsetField="offset",
            limitField="limit",
            limit=100,
            maxPages=50,
        )
        assert config.type == "request_offset"
        assert config.offset_field == "offset"
        assert config.limit_field == "limit"
        assert config.limit == 100
        assert config.max_pages == 50


class TestS3CollectorConf:
    """Tests for S3CollectorConf model."""

    def test_basic_s3_config(self) -> None:
        """Should parse a basic S3 collector configuration."""
        conf = S3CollectorConf(
            bucket="my-bucket",
            region="us-west-2",
            path="/logs/${_time:%Y/%m/%d}/",
        )
        assert conf.type == "s3"
        assert conf.bucket == "my-bucket"
        assert conf.region == "us-west-2"
        assert conf.path == "/logs/${_time:%Y/%m/%d}/"

    def test_s3_with_assume_role(self) -> None:
        """Should parse S3 config with AssumeRole settings."""
        conf = S3CollectorConf(
            bucket="test-bucket",
            enableAssumeRole=True,
            assumeRoleArn="arn:aws:iam::123456789012:role/MyRole",
            assumeRoleExternalId="ext-id-123",
            durationSeconds=3600,
        )
        assert conf.enable_assume_role is True
        assert conf.assume_role_arn == "arn:aws:iam::123456789012:role/MyRole"
        assert conf.assume_role_external_id == "ext-id-123"
        assert conf.duration_seconds == 3600

    def test_s3_serialization_preserves_aliases(self) -> None:
        """Should serialize S3 config with original alias names."""
        conf = S3CollectorConf(bucket="b", awsAuthenticationMethod="auto")
        data = conf.model_dump(by_alias=True, exclude_none=True)
        assert data["bucket"] == "b"
        assert data["awsAuthenticationMethod"] == "auto"


class TestAzureBlobCollectorConf:
    """Tests for AzureBlobCollectorConf model."""

    def test_basic_azure_config(self) -> None:
        """Should parse a basic Azure Blob collector configuration."""
        conf = AzureBlobCollectorConf(containerName="my-container", path="/logs/")
        assert conf.type == "azure_blob"
        assert conf.container_name == "my-container"
        assert conf.path == "/logs/"

    def test_azure_with_service_principal(self) -> None:
        """Should parse Azure config with service principal auth."""
        conf = AzureBlobCollectorConf(
            containerName="test",
            authType="clientSecret",
            storageAccountName="mystorageaccount",
            tenantId="tenant-123",
            clientId="client-456",
        )
        assert conf.auth_type == "clientSecret"
        assert conf.storage_account_name == "mystorageaccount"
        assert conf.tenant_id == "tenant-123"


class TestGoogleCloudStorageCollectorConf:
    """Tests for GoogleCloudStorageCollectorConf model."""

    def test_basic_gcs_config(self) -> None:
        """Should parse a basic GCS collector configuration."""
        conf = GoogleCloudStorageCollectorConf(bucket="my-gcs-bucket")
        assert conf.type == "google_cloud_storage"
        assert conf.bucket == "my-gcs-bucket"


class TestFilesystemCollectorConf:
    """Tests for FilesystemCollectorConf model."""

    def test_basic_filesystem_config(self) -> None:
        """Should parse a basic filesystem collector configuration."""
        conf = FilesystemCollectorConf(path="/var/log/app/")
        assert conf.type == "filesystem"
        assert conf.path == "/var/log/app/"


class TestDatabaseCollectorConf:
    """Tests for DatabaseCollectorConf model."""

    def test_basic_database_config(self) -> None:
        """Should parse a basic database collector configuration."""
        conf = DatabaseCollectorConf(
            connectionId="my-db-connection",
            query="SELECT * FROM events WHERE timestamp > ${earliest}",
        )
        assert conf.type == "database"
        assert conf.connection_id == "my-db-connection"
        assert "SELECT * FROM events" in conf.query


class TestRestCollectorConf:
    """Tests for RestCollectorConf model."""

    def test_basic_rest_config(self) -> None:
        """Should parse a basic REST collector configuration."""
        conf = RestCollectorConf(
            collectUrl="`https://api.example.com/events`",
            collectMethod="get",
            authentication="none",
        )
        assert conf.type == "rest"
        assert conf.collect_url == "`https://api.example.com/events`"
        assert conf.collect_method == "get"
        assert conf.authentication == "none"

    def test_rest_with_oauth(self) -> None:
        """Should parse REST config with OAuth authentication."""
        conf = RestCollectorConf(
            collectUrl="`https://api.example.com/data`",
            collectMethod="get",
            authentication="oauth",
            loginUrl="`https://auth.example.com/token`",
            clientSecretParamName="client_secret",
            authHeaderExpr="`Bearer ${token}`",
        )
        assert conf.authentication == "oauth"
        assert conf.login_url == "`https://auth.example.com/token`"
        assert conf.auth_header_expr == "`Bearer ${token}`"


class TestSplunkCollectorConf:
    """Tests for SplunkCollectorConf model."""

    def test_basic_splunk_config(self) -> None:
        """Should parse a basic Splunk collector configuration."""
        conf = SplunkCollectorConf(
            searchHead="https://splunk.example.com:8089",
            search="index=main | head 100",
            endpoint="/services/search/v2/jobs/export",
            outputMode="json",
            authentication="basic",
        )
        assert conf.type == "splunk"
        assert conf.search_head == "https://splunk.example.com:8089"
        assert conf.search == "index=main | head 100"
        assert conf.output_mode == "json"


class TestScriptCollectorConf:
    """Tests for ScriptCollectorConf model."""

    def test_basic_script_config(self) -> None:
        """Should parse a basic script collector configuration."""
        conf = ScriptCollectorConf(  # noqa: S604 - shell is a Pydantic field, not subprocess
            discoverScript="/opt/scripts/discover.sh",
            collectScript="/opt/scripts/collect.sh",
            shell="/bin/bash",
        )
        assert conf.type == "script"
        assert conf.discover_script == "/opt/scripts/discover.sh"
        assert conf.collect_script == "/opt/scripts/collect.sh"


class TestHealthCheckCollectorConf:
    """Tests for HealthCheckCollectorConf model."""

    def test_basic_health_check_config(self) -> None:
        """Should parse a basic health check collector configuration."""
        conf = HealthCheckCollectorConf(
            collectUrl="`https://api.example.com/health`",
            collectMethod="get",
            authentication="none",
        )
        assert conf.type == "health_check"
        assert conf.collect_url == "`https://api.example.com/health`"


class TestSavedJobItem:
    """Tests for SavedJobItem model."""

    def test_collector_job(self) -> None:
        """Should parse a collector job with type='collection'."""
        data = {
            "id": "s3_collector_job",
            "type": "collection",
            "description": "Collect logs from S3",
            "collector": {"type": "s3", "bucket": "my-bucket"},
        }
        job = SavedJobItem.model_validate(data)
        assert job.id == "s3_collector_job"
        assert job.type == "collection"
        assert job.is_collector() is True
        assert job.collector_type == "s3"

    def test_executor_job(self) -> None:
        """Should parse an executor job (non-collector)."""
        data = {
            "id": "custom_executor",
            "type": "executor",
            "executor": {"command": "/bin/process.sh"},
        }
        job = SavedJobItem.model_validate(data)
        assert job.id == "custom_executor"
        assert job.type == "executor"
        assert job.is_collector() is False
        assert job.collector_type is None

    def test_scheduled_search_job(self) -> None:
        """Should parse a scheduled search job (non-collector)."""
        data = {
            "id": "my_search",
            "type": "scheduledSearch",
            "savedQueryId": "query_123",
        }
        job = SavedJobItem.model_validate(data)
        assert job.id == "my_search"
        assert job.type == "scheduledSearch"
        assert job.is_collector() is False
        assert job.saved_query_id == "query_123"

    def test_job_with_schedule(self) -> None:
        """Should parse a job with schedule configuration."""
        data = {
            "id": "scheduled_collector",
            "type": "collection",
            "collector": {
                "type": "rest",
                "collectUrl": "https://api.example.com",
                "collectMethod": "get",
                "authentication": "none",
            },
            "schedule": {
                "enabled": True,
                "cronSchedule": "*/15 * * * *",
                "maxConcurrentRuns": 1,
            },
        }
        job = SavedJobItem.model_validate(data)
        assert job.schedule is not None
        assert job.schedule.enabled is True
        assert job.schedule.cron_schedule == "*/15 * * * *"


class TestSavedJobCollection:
    """Tests for SavedJobCollection model."""

    def test_full_collector_job(self) -> None:
        """Should parse a full collector job structure."""
        data = {
            "id": "full_s3_job",
            "type": "collection",
            "description": "Full S3 collector",
            "ttl": "4h",
            "collector": {
                "type": "s3",
                "bucket": "production-logs",
                "region": "us-east-1",
            },
        }
        job = SavedJobCollection.model_validate(data)
        assert job.id == "full_s3_job"
        assert job.type == "collection"
        assert job.ttl == "4h"
        assert job.collector_type == "s3"
        assert job.collector["bucket"] == "production-logs"


class TestCollectorConfMap:
    """Tests for the COLLECTOR_CONF_MAP registry."""

    def test_all_expected_collectors_present(self) -> None:
        """Should have entries for all collector types."""
        expected_collectors = [
            "s3",
            "azure_blob",
            "google_cloud_storage",
            "filesystem",
            "database",
            "rest",
            "splunk",
            "script",
            "health_check",
        ]
        for collector_id in expected_collectors:
            assert collector_id in COLLECTOR_CONF_MAP, f"Missing collector: {collector_id}"

    def test_map_returns_correct_types(self) -> None:
        """Should return the correct model class for each collector."""
        assert COLLECTOR_CONF_MAP["s3"] is S3CollectorConf
        assert COLLECTOR_CONF_MAP["azure_blob"] is AzureBlobCollectorConf
        assert COLLECTOR_CONF_MAP["rest"] is RestCollectorConf
        assert COLLECTOR_CONF_MAP["database"] is DatabaseCollectorConf


class TestGetCollectorConfClass:
    """Tests for get_collector_conf_class utility function."""

    def test_returns_correct_class_for_known_collector(self) -> None:
        """Should return the correct model class for known collector types."""
        assert get_collector_conf_class("s3") is S3CollectorConf
        assert get_collector_conf_class("rest") is RestCollectorConf
        assert get_collector_conf_class("splunk") is SplunkCollectorConf

    def test_returns_generic_model_for_unknown_collector(self) -> None:
        """Should return GenericCollectorConf as fallback for unknown collector types."""
        result = get_collector_conf_class("unknown_future_collector")
        assert result is GenericCollectorConf


class TestParseCollectorConf:
    """Tests for parse_collector_conf utility function."""

    def test_parses_s3_conf(self) -> None:
        """Should parse an S3 configuration into S3CollectorConf."""
        data = {
            "type": "s3",
            "bucket": "test-bucket",
            "region": "eu-west-1",
        }
        result = parse_collector_conf("s3", data)
        assert isinstance(result, S3CollectorConf)
        assert result.bucket == "test-bucket"

    def test_parses_unknown_collector_as_generic_model(self) -> None:
        """Should parse unknown collectors using GenericCollectorConf."""
        data = {"custom_field": "value"}
        result = parse_collector_conf("unknown_type", data)
        assert isinstance(result, GenericCollectorConf)


class TestSerializeSavedJob:
    """Tests for serialize_saved_job utility function."""

    def test_serializes_collector_job(self) -> None:
        """Should serialize a SavedJobItem to a dictionary."""
        job = SavedJobItem(
            id="test_job",
            type="collection",
            collector={"type": "s3", "bucket": "b"},
        )
        result = serialize_saved_job(job)
        assert result["id"] == "test_job"
        assert result["type"] == "collection"
        assert result["collector"]["bucket"] == "b"


class TestParseSavedJob:
    """Tests for parse_saved_job utility function."""

    def test_parses_saved_job(self) -> None:
        """Should parse a dictionary into a SavedJobItem."""
        data = {
            "id": "my_job",
            "type": "collection",
            "collector": {
                "type": "rest",
                "collectUrl": "https://example.com",
                "collectMethod": "get",
                "authentication": "none",
            },
        }
        result = parse_saved_job(data)
        assert isinstance(result, SavedJobItem)
        assert result.id == "my_job"
        assert result.is_collector() is True


class TestFilterCollectorJobs:
    """Tests for filter_collector_jobs utility function."""

    def test_filters_only_collection_type(self) -> None:
        """Should filter jobs to include only type='collection'."""
        rest_collector = {"type": "rest", "collectUrl": "u", "collectMethod": "get", "authentication": "none"}
        jobs = [
            {"id": "job1", "type": "collection", "collector": {"type": "s3", "bucket": "b"}},
            {"id": "job2", "type": "executor", "executor": {"command": "run"}},
            {"id": "job3", "type": "collection", "collector": rest_collector},
            {"id": "job4", "type": "scheduledSearch", "savedQueryId": "q"},
        ]
        result = filter_collector_jobs(jobs)
        assert len(result) == 2
        assert all(j["type"] == "collection" for j in result)
        assert result[0]["id"] == "job1"
        assert result[1]["id"] == "job3"

    def test_empty_list_returns_empty(self) -> None:
        """Should return empty list for empty input."""
        result = filter_collector_jobs([])
        assert result == []

    def test_no_collectors_returns_empty(self) -> None:
        """Should return empty list when no collectors present."""
        jobs = [
            {"id": "job1", "type": "executor"},
            {"id": "job2", "type": "scheduledSearch"},
        ]
        result = filter_collector_jobs(jobs)
        assert result == []


class TestExtraFieldsAllowed:
    """Tests that models allow extra fields for forward compatibility."""

    def test_saved_job_item_extra_fields(self) -> None:
        """SavedJobItem should preserve unknown fields via model_validate."""
        data = {
            "id": "job",
            "type": "collection",
            "collector": {"type": "s3", "bucket": "b"},
            "future_feature": True,
        }
        job = SavedJobItem.model_validate(data)
        dumped = job.model_dump()
        assert dumped.get("future_feature") is True

    def test_s3_conf_extra_fields(self) -> None:
        """S3CollectorConf should preserve unknown fields via model_validate."""
        data = {
            "type": "s3",
            "bucket": "b",
            "unknown_future_field": "value",
        }
        conf = S3CollectorConf.model_validate(data)
        dumped = conf.model_dump()
        assert dumped.get("unknown_future_field") == "value"
