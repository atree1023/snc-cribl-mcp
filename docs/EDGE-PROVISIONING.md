# Edge provisioning API notes

Fleet creation uses the installed `cribl-control-plane` SDK's `groups.create_async` with
`product=ProductsCore.EDGE`, `type_="edge"`, and optional `inherits`. The public model intentionally
accepts only creation fields, preventing runtime fields such as `configVersion`, `git`, and node
counts from being written back. The real SDK request is exercised in the HTTP contract tests.

Fleet declarations also accept `isSearch` and `streamtags`; the installed SDK maps these to
`is_search` and `streamtags` in `groups.create_async`. False values and empty lists are sent explicitly.
`lookupDeployments` was considered for Issue #29 but excluded: the installed SDK's creation schema
does not accept it, and Cribl documents it as lookup deployment status containing deployed versions.
See [groups.yml configuration](https://docs.cribl.io/edge/4.13/groupsyml/) and
[lookup deployment](https://docs.cribl.io/cribl-as-code/create-update-lookups/).

Manifest receipts already captured `groups.yml`; a later group-copy pass could invalidate that
complete diff. Supplying the creation fields directly removes that pass. Receipts now also retain
created-fleet ownership, missing declarations after partial failure, and target-local versions, so
matching retries can finish provisioning without treating their own undeployed parents as foreign work.
Fresh plans reuse only receipts with the same manifest path and intent (including source snapshot);
execution pins the reviewed receipt rather than looking up a newer receipt.

Issue #29 regressions exercise a 22-Leader/12-fleet rollout, exact Leader-file commits, ordered
deployments, per-Leader push success/failure, cached-ahead readback, partial retries across a SQLite
restart, and rejection of unrelated drift. The cluster is simulated; these tests do not establish
Cribl 4.18.1 UI behavior or independently verify a real remote repository.

Read-only validation on 2026-09-18 also planned a new parent and child with `isSearch: false`,
populated parent tags, and empty child tags on each of `golden.oak` and `golden.oak.new`.
Both plans had zero blocked targets and two creates. Fleet/Git fingerprints were unchanged afterward;
temporary manifests were removed with their file digests. No live fleet creation, deployment, or push
was performed for this change.

The installed Python SDK has no fleet mapping component. Mapping operations use the SDK-owned HTTP
client, refreshed security, configured TLS policy, and timeout at Leader scope:

| Operation | Method and path |
| --- | --- |
| Read ruleset | `GET /api/v1/fleet-mappings/{id}` |
| Create ruleset | `POST /api/v1/fleet-mappings` |
| Update ruleset | `PATCH /api/v1/fleet-mappings/{id}` |

Bodies contain `id`, `conf.functions` in original order, and `active`. Replication preserves target
activation, with inactive creates. Returned unknown shapes are rejected; an empty counted result or
404 denotes absence. Authorization failures propagate without retrying another endpoint.

Sources checked during implementation:

- [Published Cribl Go SDK v1.2.1](https://pkg.go.dev/github.com/speakeasy-sdks/cribl-go@v1.2.1):
  its published module archive contains `fleetmappings.go` (the methods above) and
  `pkg/models/shared/mappingruleset.go` (request/response fields).
- [Cribl mapping configuration reference](https://docs.cribl.io/edge/4.13/mappingsyml/):
  the Edge Leader file is `local/cribl/fleet-mappings.yml`.
- [Cribl 4.18.2 API compatibility notes](https://docs.cribl.io/stream/release-notes/release-v4182/):
  `/fleet-mappings` remains a supported CRUD endpoint; Cloud GET-by-ID absence changed to 404.
- [Cribl's current Terraform mapping client](https://github.com/criblio/terraform-provider-criblio/blob/80a26d1574c880c0a0b5c5f944a42b1aa028ec90/internal/provider/mapping_ruleset_client.go):
  the separate `/admin/products/edge/mappings/{id}` endpoint uses PATCH for creation, but returned
  403 on both configured on-prem rollout Leaders. Do not use that Cloud admin contract for
  `/fleet-mappings` creation.

On 2026-09-18, read-only checks against `golden.oak` and `golden.oak.new` successfully read Edge fleet
inventory and the default ruleset through `/fleet-mappings`. Dry-run fleet-creation plans on both Leaders had no blockers; copying the default ruleset from
`golden.oak` to `golden.oak.new` planned as a no-op. No live create, update, commit, deploy, or push was performed. Write behavior and manifest dependency/receipt handling are covered by
stateful fake-Leader and real-SDK HTTP tests.
