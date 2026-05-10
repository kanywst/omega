# ADR 0002: Postgres advisory-lock leader election over in-process Raft

## Status

Accepted (project inception).

## Context

The control plane has two stateful surfaces: the CA private key
material and the policy / audit / domain database. For a
single-replica deployment SQLite covers both. For HA deployments
the question is what replicates the database, *and* how a single
writer is elected so the audit log's hash chain stays consistent.

Two natural answers exist:

1. **Postgres + advisory-lock leader election.** Pick one
   replica as the writer using `pg_try_advisory_lock`. All other
   replicas serve reads and proxy writes back to the leader (or,
   in our case, return `503 Retry-After: 1`). Database
   replication happens at the Postgres layer, which has decades
   of operational tooling.
2. **Raft inside the omega binary.** Use a library like
   `hashicorp/raft` to replicate state. The store becomes a
   replicated state machine; no external database is required.

Vault chose option 2 because its data plane *is* secrets
storage, and the cost of running a replicated KV separately
from the application is high. Etcd, Consul, and Nomad chose the
same path.

Omega's stateful surface is small (CA private key + policy +
audit log) and is already trivially backed by Postgres - which
operators in our target environments already run. Building
Raft into the binary would re-implement features Postgres ships
(replication, point-in-time recovery, backups, monitoring,
TLS at the wire) inside an application we want to keep small
and reviewable.

## Decision

Run leader election with `pg_try_advisory_lock` at a fixed
key (`0x0e6a3a0001` by default; overridable per cluster). Mechanics
implemented in `internal/server/storage/leader.go`:

- Every replica runs the same election goroutine. On each tick of
  a ticker (`PollInterval`, default 1 second) a non-leader replica
  takes a fresh dedicated `*sql.Conn` from the pool and calls
  `pg_try_advisory_lock`. On `true`, it pins the conn (the lock is
  session-scoped) and flips its in-memory `isLeader` bit.
- The current leader holds the conn open and `Ping`s it every tick
  to detect silent connection drops. On Ping failure (process
  crash, Postgres restart, network partition) it explicitly calls
  `pg_advisory_unlock` to release the lock cleanly, closes the
  conn, and re-enters the contention loop.
- Followers therefore acquire leadership at most one
  `PollInterval` after the previous leader releases it.

`IsLeader()` is the cheap predicate every write path checks;
`ErrNotLeader` bubbles up to the HTTP layer as
`503 Service Unavailable` with `Retry-After: 1`. Clients are
expected to honour `Retry-After` and retry against
`GET /v1/leader`.

In-process Raft is deferred indefinitely. It is revisited only
if a deployment proves DB-side HA insufficient.

## Consequences

Easier:

- One writer at a time, by construction. The audit log's hash
  chain serialisation stays correct without a distributed-write
  protocol.
- Operators reuse their existing Postgres expertise and tooling
  - backup, point-in-time recovery, observability, TLS.
- The single-binary mental model is preserved: `omega server`
  with a `--db postgres://...` flag, no co-located cluster
  membership service.

Harder:

- HA deployments must run Postgres in a high-availability
  configuration themselves (managed Postgres, Patroni, Crunchy
  Data, etc.). Omega does not orchestrate Postgres.
- Failover latency is bounded by Postgres connection drops plus
  the next replica grabbing the advisory lock, not by a Raft
  election timeout. In practice this is comparable, but the
  failure modes are Postgres failure modes.

New obligations:

- The `examples/postgres-ha/` example must keep working as a
  smoke test for the leader-election path (it is part of the CI
  matrix).
- The `503 Retry-After: 1` contract is part of the public API
  surface and is documented in [`api/openapi.yaml`](../../api/openapi.yaml).

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes. Storage and replication are a Plugin-layer concern (SQLite
default, Postgres for HA). Raft would have moved this *into*
Core, which the four-rules guidance explicitly cautions against.
