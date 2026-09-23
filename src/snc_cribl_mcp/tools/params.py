"""Described parameter types for MCP tool signatures.

FastMCP copies each ``Field(description=...)`` below into the tool's JSON schema, which is the only
parameter documentation a client model sees. Keep every description a precise statement of what the
code does with the value; update it in the same change that alters the behavior.
"""

from typing import Annotated, Any, Literal

from pydantic import Field

from ..models.config_manifest import DriftPolicy
from ..operations.config_manifest import ValidationDetailScope
from ..operations.config_objects import ConfigObjectDetail, ConfigObjectKind
from ..operations.packs import PackObjectDetail, PackObjectKind
from ..operations.resource_actions import ResourceKind
from ..operations.version_control import CompareTo, ProductScope
from .sync_common import ProductName

# Leaders

type Server = Annotated[str | None, Field(description="Configured leader name; omit for the first configured leader.")]
type EdgeServer = Annotated[
    str | None,
    Field(
        description=(
            "Configured leader name. Omit to pick the leader whose name or URL matches the datacenter taken from "
            "datacenter or edge_host."
        ),
    ),
]
type TargetLeader = Annotated[
    str | None,
    Field(description="Configured leader name that receives the change. Omit to use the first configured leader."),
]
type SourceServer = Annotated[str, Field(description="Configured leader name to read from.")]
type TargetServer = Annotated[str, Field(description="Configured leader name to write to or compare against.")]
type UserSourceServer = Annotated[
    str | None,
    Field(
        description=(
            "Configured leader to copy the user's profile and roles from. Omit to start from the existing target "
            "user and the explicit fields."
        ),
    ),
]

# Products and group selectors

type GroupProduct = Annotated[
    ProductName,
    Field(description="Product of the group or fleet: 'stream' for a worker group, 'edge' for a fleet."),
]
type SyncProduct = Annotated[
    ProductName,
    Field(
        description=(
            "Product that group selectors (and resource_kind='groups') resolve against: 'stream' worker groups or "
            "'edge' fleets."
        ),
    ),
]
type PackProduct = Annotated[
    ProductName,
    Field(description="'stream' worker group or 'edge' fleet; only used together with group."),
]
type OptionalProduct = Annotated[
    ProductName | None,
    Field(description="Limit results to 'stream' or 'edge'; omit for both."),
]
type StatusProductScope = Annotated[
    ProductScope,
    Field(description="'stream', 'edge', or 'all'. Use 'stream' or 'edge' when group is set."),
]
type DeployProductScope = Annotated[
    ProductScope,
    Field(description="Targets to include: 'stream' worker groups, 'edge' fleets, or 'all'."),
]
type GroupSelector = Annotated[
    str,
    Field(
        description=(
            "Group or fleet selector, matched exactly against id, then name, then description (case-sensitive "
            "first, then case-insensitive). An ambiguous or unmatched selector returns an error."
        ),
    ),
]
type StatusGroupSelector = Annotated[
    str | None,
    Field(description="Group or fleet selector (exact id, name, or description). Omit to report every target."),
]
type PackGroup = Annotated[
    str | None,
    Field(description="Group or fleet selector (exact id, name, or description); omit for leader-level Packs."),
]
type SourceGroup = Annotated[
    str | None,
    Field(
        description=(
            "Source group or fleet selector (exact id, name, or description). Required for every resource_kind "
            "except 'groups', where it must be omitted."
        ),
    ),
]
type TargetGroup = Annotated[
    str | None,
    Field(
        description=(
            "Target group or fleet selector, resolved on the target leader; defaults to the source selector. "
            "Must be omitted for resource_kind='groups'."
        ),
    ),
]
type GroupSyncSource = Annotated[
    str,
    Field(
        description=(
            "Group or fleet to process, matched on the source leader by exact id, name, or description "
            "(case-sensitive first, then case-insensitive)."
        ),
    ),
]
type GroupSyncTarget = Annotated[
    str | None,
    Field(
        description=(
            "Target group or fleet selector; defaults to the resolved source group id. Group settings can only be "
            "copied or compared when the target id equals the source id."
        ),
    ),
]

# Review-then-execute protocol and Git

type DryRun = Annotated[
    bool,
    Field(description="true returns a review plan and changes nothing; false executes the reviewed plan."),
]
type ExpectedPlanSha256 = Annotated[
    str | None,
    Field(description="plan_sha256 from the reviewed dry run; required when dry_run=false."),
]
type Push = Annotated[
    bool,
    Field(description="After success, push the Leader Git repository, including all earlier unpushed commits, to its remote."),
]
type CommitMessage = Annotated[str, Field(description="Commit message; must not be blank.")]
type ManifestCommitMessage = Annotated[
    str,
    Field(description="Commit message; must not be blank and must be identical in the dry run and the execution."),
]

# Config object copy and validation filters

type CopyResourceKind = Annotated[
    ResourceKind,
    Field(
        description=(
            "Config object type. 'groups' copies or compares group and fleet definitions; every other kind lives "
            "inside a group and needs source_group."
        ),
    ),
]
type ItemId = Annotated[
    str | None,
    Field(
        description=("Exact, case-sensitive id of one item. Cannot be combined with the pattern, regex, or exclude filters."),
    ),
]
type ItemPattern = Annotated[
    str | None,
    Field(
        description=(
            "Whole-id shell wildcard expression with and, or, not, 'but not', and parentheses, for example "
            "'oodp-* and not oodp-source-*'. Terms cannot contain spaces."
        ),
    ),
]
type ItemRegex = Annotated[
    str | None,
    Field(
        description=(
            "Regular expression searched anywhere in the item id (unanchored). When item_pattern is also set, an "
            "item must match both."
        ),
    ),
]
type ExcludeItemPattern = Annotated[
    str | None,
    Field(description="Wildcard expression with item_pattern syntax; matching items are dropped even when included."),
]
type ExcludeItemRegex = Annotated[
    str | None,
    Field(description="Regular expression; items whose id matches are dropped even when included."),
]
type CaseSensitive = Annotated[
    bool,
    Field(description="Match item_pattern, item_regex, and the exclude filters case-sensitively. item_id is always exact."),
]
type CopyOverwrite = Annotated[
    bool,
    Field(description="When false, items that already exist on the target are skipped; missing items are still created."),
]
type CopyValidateAfter = Annotated[
    bool,
    Field(
        description=(
            "After execution, re-read the target and attach a validation result to each created, updated, or "
            "appended item. Does not change the result status."
        ),
    ),
]
type AppendRoutes = Annotated[
    bool,
    Field(
        description=(
            "For routes: append the source routes to the existing target route table instead of replacing it. No "
            "in-sync check is made, so running again appends again."
        ),
    ),
]
type ComparePayloads = Annotated[
    bool,
    Field(
        description=(
            "Include canonical source and target payloads for items present on both sides. Oversized responses drop "
            "payloads first."
        ),
    ),
]
type ContentKinds = Annotated[
    list[str] | None,
    Field(
        description=(
            "Content to process, in order: any of variables, breakers, lookups, destinations, pipelines, sources, "
            "routes. Omit for all seven in that order; an empty list processes none."
        ),
    ),
]
type IncludeGroupSettings = Annotated[
    bool,
    Field(
        description=(
            "Also copy or compare the group or fleet definition itself. Requires the target group id to equal the source id."
        ),
    ),
]

# System settings

type SettingsOverwrite = Annotated[
    bool,
    Field(description="When false and the settings differ, the target is left unchanged and reported as skipped."),
]
type SettingsValidateAfter = Annotated[
    bool,
    Field(description="Re-read the target settings afterwards and attach a validation result. Does not change the action."),
]
type SettingsPayloads = Annotated[bool, Field(description="Include the raw source and target settings in the response.")]

# Local users

type Username = Annotated[str, Field(description="Local Cribl username to create or update.")]
type UserPassword = Annotated[
    str | None,
    Field(
        description=(
            "Password for the user. Needed when the user does not exist on the target (or use password_env); for an "
            "existing user it resets the password. Never returned in responses."
        ),
    ),
]
type PasswordEnv = Annotated[
    str | None,
    Field(
        description=(
            "Name of an environment variable on the MCP server host that holds the password. When set, the automatic "
            "fallback variable names are not tried."
        ),
    ),
]
type UserFirst = Annotated[
    str | None,
    Field(description="First name; overrides the value copied from the source or existing user."),
]
type UserLast = Annotated[
    str | None,
    Field(description="Last name; overrides the value copied from the source or existing user."),
]
type UserEmail = Annotated[
    str | None,
    Field(description="Email address; overrides the value copied from the source or existing user."),
]
type UserRoles = Annotated[list[str] | None, Field(description="Role ids; replaces the user's whole role list.")]
type UserDisabled = Annotated[
    bool | None,
    Field(description="true disables the account and false enables it; omit to keep the copied or existing value."),
]
type UserOverwrite = Annotated[
    bool,
    Field(description="When false and the user already exists on the target, nothing is changed."),
]
type UserValidateAfter = Annotated[
    bool,
    Field(description="Re-read the user from the target afterwards and attach a comparison with what was written."),
]

# get_config_objects

type ConfigKind = Annotated[ConfigObjectKind, Field(description="Config object type to query.")]
type ConfigGroupId = Annotated[
    str | None,
    Field(
        description=(
            "Exact group or fleet id (case-insensitive); names and descriptions do not match here. Omit for all "
            "groups. Any value returns nothing for kind='groups'."
        ),
    ),
]
type ConfigSelector = Annotated[
    str | None,
    Field(
        description=(
            "Case-insensitive filter on id, name, type, and description: a substring match, or a whole-value shell "
            "wildcard when it contains *, ? or [."
        ),
    ),
]
type ConfigDetail = Annotated[
    ConfigObjectDetail,
    Field(
        description=(
            "'summary' returns compact rows, 'refs' also fills dependency refs, and 'full' adds each object's raw payload."
        ),
    ),
]
type IncludeDependencies = Annotated[
    bool,
    Field(
        description=(
            "Fill refs in summary or full rows: routes to pipelines and destinations, sources to pipelines, pipelines "
            "to lookups. Other kinds have no refs."
        ),
    ),
]
type ConfigCursor = Annotated[
    str | None,
    Field(description="next_cursor from the previous response, to fetch the next page."),
]
type ConfigLimit = Annotated[int | None, Field(description="Rows per page; default 50, maximum 250.")]

# Packs

type PackId = Annotated[str, Field(description="Installed Pack id.")]
type PackCounts = Annotated[
    str | None,
    Field(description="Comma-separated counts to include per Pack: inputs, outputs, collectors."),
]
type PackKind = Annotated[
    PackObjectKind | None,
    Field(description="Pack section or category to drill into. Omit for a bounded summary of every section."),
]
type PackObjectId = Annotated[
    str | None,
    Field(
        description=("Id of one object within a concrete kind (not 'knowledge' or 'settings'). Ignored when kind is omitted."),
    ),
]
type PackDetail = Annotated[
    PackObjectDetail,
    Field(
        description=(
            "'full' adds each object's raw payload and needs a concrete kind; 'summary' and 'refs' return the same rows."
        ),
    ),
]
type PackCursor = Annotated[
    str | None,
    Field(description="next_cursor from the previous response. Only with a concrete kind, not 'knowledge' or 'settings'."),
]
type PackLimit = Annotated[
    int | None,
    Field(description="Items per page with a concrete kind; default 50, maximum 250."),
]
type PackInstallRequest = Annotated[
    dict[str, Any],
    Field(
        description=(
            "Install body. Give id (creates an empty Pack) and/or source (a .crbl URL, git+<repo-url>, or the source "
            "returned by upload_pack). Optional: version, spec (semver range), force (replace a Pack with the same "
            "id), allowCustomFunctions, displayName, author, description, minLogStreamVersion, tags. Other keys are "
            "rejected."
        ),
    ),
]
type PackFilePath = Annotated[
    str,
    Field(
        description=(
            "Path to a .crbl file on the MCP server host; relative paths resolve against the server's working directory."
        ),
    ),
]
type PackSource = Annotated[
    str,
    Field(description="Upgrade source: the source value returned by upload_pack, a .crbl URL, or git+<repo-url>."),
]
type AllowCustomFunctions = Annotated[
    bool | None,
    Field(description="false rejects Packs that contain custom JavaScript functions; omit or true allows them."),
]
type PackMinor = Annotated[
    bool | None,
    Field(description="true allows the upgrade to install a minor (non-breaking) version."),
]
type PackSpec = Annotated[
    str | None,
    Field(description="Semver range constraint used to choose the Pack version to install."),
]

# Edge teleport

type EdgeHost = Annotated[
    str,
    Field(
        description=(
            "Edge node hostname such as 'cribl01.fra0' or its full service-now.com name ('.service-now.com' is "
            "appended to dotted names that lack it), matched exactly and case-insensitively against node hostnames."
        ),
    ),
]
type EdgeFile = Annotated[str, Field(description="Absolute path of the file on the Edge node.")]
type EdgeQuery = Annotated[
    str | None,
    Field(
        description=(
            "Search text. Omit or leave empty to read the file from offset instead of searching. Text containing "
            "punctuation is quoted automatically."
        ),
    ),
]
type EdgeOffset = Annotated[
    int,
    Field(description="Read position; pass next_offset from a previous response to continue."),
]
type EdgeLimit = Annotated[int, Field(description="Maximum results to return, 1-1000.")]
type EdgeEarliestTime = Annotated[
    int | None,
    Field(description="Search start as Unix epoch seconds; overrides search_window_seconds."),
]
type EdgeSearchWindow = Annotated[
    int,
    Field(description="When query is set and earliest_time is omitted, search this many seconds back from now."),
]
type EdgeRulesets = Annotated[
    list[str] | None,
    Field(
        description=(
            "Event-breaker ruleset ids sent with the file request. Leave unset unless replaying a request captured "
            "from the Edge UI."
        ),
    ),
]
type EdgeInfoType = Annotated[Literal["file"], Field(description="Kind of Edge information; 'file' is the only value.")]
type EdgeDatacenter = Annotated[
    str | None,
    Field(
        description=(
            "Datacenter label such as 'fra0'. Its first three letters select the leader when server is omitted, and "
            "a dotless edge_host becomes '<edge_host>.<datacenter>.service-now.com'."
        ),
    ),
]

# Edge fleet mappings

type RulesetId = Annotated[str, Field(description="Fleet mapping ruleset id on the source leader.")]
type RulesetOverwrite = Annotated[
    bool,
    Field(description="When false, a ruleset that already exists on the target is skipped."),
]

# Manifests

type ManifestName = Annotated[
    str,
    Field(
        description=(
            "File name or relative path under the manifest root. '.yaml' is appended when there is no extension; the "
            "result must end in .yaml or .yml."
        ),
    ),
]
type ManifestContent = Annotated[str, Field(description="Complete schema-1 manifest YAML text.")]
type ManifestOverwrite = Annotated[
    bool,
    Field(description="Replace an existing manifest whose content differs. Identical content is always accepted."),
]
type ManifestPath = Annotated[
    str,
    Field(
        description=(
            "Manifest path relative to the manifest root, as returned by write_manifest. Absolute paths must stay "
            "inside the root."
        ),
    ),
]
type ExpectedFileSha256 = Annotated[
    str | None,
    Field(
        description=(
            "file_sha256 returned by write_manifest; deletion is refused if the file has changed. Omit to delete "
            "without the check."
        ),
    ),
]
type ManifestConcurrency = Annotated[
    int | None,
    Field(
        description=("Target Leaders processed in parallel, 1-10. Omit to use the manifest's options.concurrency (default 5)."),
    ),
]
type ReplicateOnDrift = Annotated[
    DriftPolicy | None,
    Field(
        description=(
            "At execution, how to handle targets whose plan changed after review: 'abort' fails before writing "
            "anything, 'skip' applies the other targets. Omit to use the manifest's options.on_drift (default 'skip')."
        ),
    ),
]
type DeployOnDrift = Annotated[
    DriftPolicy,
    Field(
        description=(
            "'skip' skips blocked Leaders and continues with the rest; 'abort' preflights every Leader and changes "
            "nothing if any is blocked."
        ),
    ),
]
type ResumeJobId = Annotated[
    str | None,
    Field(
        description=(
            "A failed, interrupted, or completed job from this tool to resume with dry_run=false. All other "
            "parameters must match the original request."
        ),
    ),
]
type ManifestTarget = Annotated[
    str | None,
    Field(description="One Leader name from the manifest's targets to inspect; omit for all targets."),
]
type ReceiptTarget = Annotated[
    str | None,
    Field(description="One Leader name from the receipt's targets to check; omit for all targets."),
]
type ValidationOffset = Annotated[int, Field(description="Detail rows to skip, for paging.")]
type ValidationLimit = Annotated[int, Field(description="Detail rows to return, 1-100.")]
type DetailScope = Annotated[
    ValidationDetailScope,
    Field(description="'differences' returns only items that differ; 'all' also includes noop items."),
]
type ApplyJobId = Annotated[
    str | None,
    Field(
        description=(
            "Job id of the replicate_config_manifest execution whose apply receipt to use. Provide exactly one of "
            "apply_job_id or apply_receipt_sha256."
        ),
    ),
]
type ApplyReceiptSha256 = Annotated[
    str | None,
    Field(description="Digest of the apply receipt; alternative to apply_job_id."),
]
type DeployApplyJobId = Annotated[
    str | None,
    Field(
        description=(
            "Job id of the replicate_config_manifest execution whose apply receipt to deploy. For the dry run, "
            "provide exactly one of apply_job_id or apply_receipt_sha256; execution uses the receipt pinned in the "
            "reviewed plan."
        ),
    ),
]
type DeployApplyReceiptSha256 = Annotated[
    str | None,
    Field(description="Digest of the apply receipt; alternative to apply_job_id for the dry run."),
]

# Version control

type CompareToParam = Annotated[
    CompareTo,
    Field(
        description=(
            "'deployed' diffs the working configuration against the active deployed version; 'head' shows only "
            "uncommitted changes."
        ),
    ),
]
type DiffFilename = Annotated[
    str | None,
    Field(description="Return only this file's diff, using a path from the diff summary."),
]
type DiffLineLimit = Annotated[
    int,
    Field(description="Maximum hunk lines returned across all files. 0 removes the line cap; byte and file caps still apply."),
]
type DiffLineOffset = Annotated[
    int,
    Field(description="diff_page.next_line_offset from the previous response, to continue."),
]
type LeaderDiffFilename = Annotated[
    str,
    Field(description="Leader file to diff; the default, local/cribl/groups.yml, records deployments."),
]
type JobId = Annotated[
    str | None,
    Field(description="Job id returned by a mutation execution. Omit to list recent jobs."),
]
type JobListLimit = Annotated[int, Field(description="Recent jobs to list when job_id is omitted, 1-100.")]
type JobTarget = Annotated[
    str | None,
    Field(
        description=(
            "Requires job_id. A Leader name ('default' when the job was started without server), or "
            "'edge:<fleet-id>' / 'stream:<group-id>' for fleet detail."
        ),
    ),
]
type CommitFiles = Annotated[
    list[str] | None,
    Field(
        description=(
            "Only commit these files, as paths shown in get_group_git_diff (for example 'local/cribl/inputs.yml'). "
            "Omit to commit all pending changes."
        ),
    ),
]
type LeaderFiles = Annotated[
    list[str],
    Field(
        description=(
            "1-100 individual Leader file paths such as 'local/cribl/groups.yml'. Directories, wildcards, '..', "
            "'.git', and group paths are rejected."
        ),
    ),
]
type CommitEffective = Annotated[
    bool,
    Field(description="Cribl commit API 'effective' flag: commit the group's effective configuration."),
]
type GroupCommitEffective = Annotated[
    bool,
    Field(
        description=(
            "Cribl commit API 'effective' flag: commit the group's effective configuration. false also skips the "
            "Edge ancestor readiness preflight."
        ),
    ),
]
type DeployVersion = Annotated[
    str,
    Field(
        description=(
            "Commit hash to deploy, for example a previous version for rollback. A hash equal to the active "
            "configVersion plans as noop."
        ),
    ),
]
type StopOnError = Annotated[
    bool,
    Field(
        description=(
            "true stops at the first commit or deploy failure and reports remaining targets as not_started; false "
            "continues with the other targets. Descendants of a failed Edge parent are skipped either way."
        ),
    ),
]

# Listing

type PipelineId = Annotated[
    str | None,
    Field(description="Exact pipeline id to fetch from every group. Omit for all pipelines."),
]
