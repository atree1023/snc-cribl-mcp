# Edge provisioning API notes

Fleet creation uses the installed `cribl-control-plane` SDK's `groups.create_async` with
`product=ProductsCore.EDGE`, `type_="edge"`, and optional `inherits`. The public model intentionally
accepts only creation fields, preventing runtime fields such as `configVersion`, `git`, and node
counts from being written back. The real SDK request is exercised in the HTTP contract tests.

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
