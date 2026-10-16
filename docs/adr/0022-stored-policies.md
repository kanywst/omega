# ADR 0022: Cedar policies stored in the control plane

## Status

Accepted.

## Context

Until now Cedar policies came only from `--policy-dir`, a directory of files each server reads at startup and on `SIGHUP`. That keeps policy in version control, but a change is invisible to the audit chain, has to be copied to every replica's disk and signalled to each, and cannot be made by an authenticated operator through the same API that manages domains, groups and admins. The threat model (T2) listed Cedar policy management over HTTP as partial for this reason.

## Decision

1. **Policies are stored in the database.** A `policies` table (SQLite and Postgres) holds each policy's id, Cedar text, version, and who created and last changed it, and when. Its SHA-256 digest is computed from the text on every read, so a text edited in the database shows a digest the audit chain never recorded. `/v1/policies` lists, reads, creates, updates and deletes them, and `/v1/policies/validate` runs the same checks without storing anything. `omega policy list|get|apply|delete` is the CLI.
2. **The engine evaluates the union.** `--policy-dir` files and stored policies form one Cedar policy set. Files stay read-only over the API and are listed as `source: file`. Every Cedar policy id a stored policy defines is prefixed with `api/<id>::`, its `@id` included, so a stored policy can never take over an id a file defines and a decision's `reasons` name the stored policy. An id that collides anyway (a file defining `api/...`) is refused on whichever side changes second.
3. **Only root admins write, only with authentication.** Writes need `--require-auth` and a caller listed with `--domain-root-admin`. A Cedar policy is not scoped to a domain, so a domain admin's grant does not extend to it. Writes are leader-only. Reads need an authenticated caller under `--require-auth` and are served by followers.
4. **Change and record commit together.** Each write and its audit row (`policy.create`, `policy.update`, `policy.delete`, with the old and new digests) are written in one transaction, as SCIM changes are (ADR 0017). Updates need `If-Match` with the policy's ETag, so concurrent edits fail with `412` instead of overwriting each other.
5. **Replicas and nodes follow the database.** Every replica reloads the stored set with the domain tree every five seconds, and the leader right after a write. The policy bundle carries stored policies, so node agents' local PDPs (ADR 0016) see them on their next sync.
6. **A set that does not load keeps the last one and fails closed.** The leader validates before it stores, so a set that fails to load on a replica means it disagrees with the database. The replica keeps the last set that loaded, logs, counts the failure in a metric, and lets the projected directory go stale, so evaluation fails closed after fifteen seconds as it does for an unreadable domain tree. Keeping the last set forever would silently ignore every later change, a new `forbid` included. A server whose first load fails still starts, so the API can fix the policy.

## Consequences

Easier:

- A policy change is attributed to an authenticated caller and recorded in the tamper-evident chain with digests that identify the exact text.
- One write reaches every replica and every node agent without touching disks or sending signals.
- Policies kept in version control can still be applied from CI with `omega policy apply`, which keeps an audit trail on both sides.

Harder:

- Policy text now lives in the database, so database write access reaches the policy set directly, bypassing the API and its audit row (T2). The residual risk is the same as for domains and groups.
- Delegating policy authorship to domain admins would need proof that a policy only governs the admin's subtree. That is not attempted; root admins write every stored policy.
- Validation is syntactic plus id collisions. There is no Cedar schema in Omega, so a policy that names an attribute no entity has is accepted and simply never matches.
- One stored policy that fails to load on a replica makes that replica fail closed until the policy is fixed or deleted.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Omega is the PDP that evaluates these policies (ADR 0001). Managing the policy set through the same authenticated, audited API as the domain tree and groups it refers to keeps who changed what Omega decides inside Omega's audit chain, rather than in whatever wrote the files.
