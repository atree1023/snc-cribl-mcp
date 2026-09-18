# Issue #28: parent readiness and remote Git status

Investigation date: 2026-09-18. Reference: [GitHub Issue #28](https://github.com/atree1023/snc-cribl-mcp/issues/28).

## Reproduced parent-guard defect

Fleet provisioning listed Edge fleets without `fields=git.commit,git.localChanges`.
Cribl omits the `git` object unless requested. The shared status helper therefore fell
back to commit history, which returns a full SHA-1 hash. The guard compared that string
with the abbreviated `configVersion` and incorrectly classified the parent as undeployed.

Read-only observations from the configured local leaders:

| Leader | History fallback | Deployed version | Old guard status | Explicit fleet Git status |
| --- | --- | --- | --- | --- |
| `golden.oak` | `d53dd908ff9e2f03353698358970e9c306140b36` | `d53dd90` | `deployment_pending=true` | `deployment_pending=false` |
| `golden.oak.new` | `d7c79ce1282ac659413de2537a3739fdfeda843f` | `d7c79ce` | `deployment_pending=true` | `deployment_pending=false` |

Both working trees were clean with `ahead=0`, `behind=0`, no conflicts, and no pending
Leader deployment metadata. The inspected local Leader version was `4.20.0-cee79842`.
This reproduces blocking on pristine leaders independently of any remote Git behavior.
The parent comparison is target-local; it does not compare source and target commit IDs.

The fix requests fleet Git metadata explicitly, matching the existing status workflow.
If the requested commit metadata is unavailable, readiness fails closed with an explicit
reason instead of guessing from history. Dirty, undeployed, conflicted, and remote-behind
states still block. Unpushed commits (`ahead > 0`) remain informational.

Block reasons now identify the signal and value. Bounded parent snapshots are available
in standalone `plan.guard` and each manifest target's `provisioning_guard`. Complete
digests still cover parents omitted from the preview. `fleet_count` includes proposed
creations; `existing_fleet_count` and `planned_create_count` make that distinction explicit.

After the fix, standalone child-fleet dry-runs succeeded on both local leaders. A temporary
manifest with source `golden.oak` and target `golden.oak.new` reported
`blocked_target_count=0`. Fleet inventory and Git status were unchanged across standalone
probes. The temporary manifest was removed using its file digest. No fleet was created,
and no live configuration commit, deployment, push, or service restart was performed.

Validation passed: 773 tests, 91.50% total coverage, Ruff format/lint, Pyright, and
`git diff --check`. The installed environment used `cribl-control-plane 0.12.0` and
FastMCP 4.0.5. No dependency versions were changed by this fix.

## Separate report: missing UI Push action and stale remote counts

Local deployment and remote push are distinct operations. Cribl's
[distributed commit/deploy documentation](https://docs.cribl.io/cribl-as-code/commit-deploy/)
describes committing the group, deploying its immutable version, and committing Leader
metadata. Its [remote repository documentation](https://docs.cribl.io/stream/remote-repositories/)
describes a separate Git Push action.

Tests exercise the installed SDK's actual HTTP serialization against a stateful mocked
Cribl API for both single-group and all-target workflows. With `push=false`, the mutation
sequence is:

1. `POST /m/<group>/version/commit`
2. `PATCH /products/<product>/groups/<group>/deploy`
3. `POST /version/commit`, selecting only `local/cribl/groups.yml`

No `/version/push` request is sent. With `push=true`, that request follows successful
commit/deploy finalization. A later, separately reviewed `push_config_git` request can
push previously committed changes when Cribl reports pending local commits.

The installed SDK commit body exposes `message`, `effective`, and `files`; it has no
push parameter. The MCP push flag controls the separate push request. Committing
`groups.yml` records deployment state locally and is not itself a remote push.

The user subsequently traced the symptom to Cribl API caching: after `push_config_git` pushes,
the Leader API can continue reporting ahead of origin. This is user-reported evidence from the
affected environment. It has **not** been independently reproduced or fixed here. Both local test leaders report
`remote_configured=false`. The affected deployment is **4.18.1**, as reported by the user;
the local guard reproduction used 4.20.0. Passing SDK request tests does not verify Cribl's internal
Git cache or UI behavior. No claim is made that the API refreshed its remote status.

The Issue #29 changes report successful manifest/all-target and standalone pushes separately from
one post-push API status read. Cached-ahead or failed reads do not trigger a duplicate push or turn
API push success into failure. Results explicitly retain `remote_sync_verified=false`; the available
SDK status endpoint has no cache-refresh control.

`ahead` counts local commits absent from the tracked remote; `behind` counts remote
commits absent locally. Current push planning trusts Cribl's API counts: a stale
`ahead=0` can produce a no-op, and a stale nonzero `behind` can block pushing. A clean
working tree alone does not establish remote synchronization.

To isolate the remaining symptom on an affected Leader, collect its Cribl version and
timestamped `/version/status` responses alongside read-only shell output from
`git rev-parse HEAD`, `git rev-parse '@{upstream}'`, and
`git rev-list --left-right --count 'HEAD...@{upstream}'`. These compare the local branch
with its locally stored upstream reference; an independent remote query is needed to
establish the remote's actual current tip. Record the exact commit/deploy request sequence
and whether any `/version/push` request occurred. Do not substitute a Git sync, force push,
or automatic service restart for that diagnosis.
