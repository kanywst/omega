# Running Omega on Postgres

Omega ships a single-file SQLite store by default - perfect for a
laptop, a single VM, or a CI run, but a non-starter for HA. This example
runs the same omega binary against a Postgres database. Nothing about
the API, agents, or policies changes; only the storage URL.

## Topology

```text
                  +-----------------+   sql/database (lib/pq)   +--------------+
   curl --------> |  omega server   | ------------------------> |  Postgres    |
                  |  :18097         |  domains, audit_log,      |  16-alpine   |
                  +-----------------+  audit_forward_state      |  :55433      |
                                                                +--------------+
```

The `Store` API is unchanged from SQLite: the same `CreateDomain` /
`AppendAudit` / `ListAudit` / `AuditForwardSeq` calls run against
either driver. `storage.Open` inspects the spec and dispatches:

| spec                                   | driver                         |
| -------------------------------------- | ------------------------------ |
| `postgres://...` or `postgresql://...` | lib/pq (Postgres)              |
| anything else                          | modernc.org/sqlite (file path) |

## Run it

```bash
make demo
```

The script:

1. starts a Postgres container (`postgres:16-alpine` on `:55433`)
2. starts an omega server with `--db postgres://omega:omega@127.0.0.1:55433/omega?sslmode=disable`
3. drives one AuthZEN evaluation and one domain creation
4. restarts the server (proving the rows aren't in the process)
5. prints the `audit_log` rows directly from `psql` so you can see the
   canonical chain bytes in the database
6. calls `/v1/audit/verify` and asserts `{"valid":true}`

Expected tail:

```text
[demo] domains visible after restart:
  {"items":[{"name":"media","description":"media","created_at":"..."},{"name":"media.news","parent":"media","description":"news","created_at":"..."}]}
[demo] audit_log rows directly from Postgres:
   seq |      kind       |  subject   | decision |     hash16       |     prev16
  -----+-----------------+------------+----------+------------------+------------------
     1 | access.evaluate | alice      | deny     | 60351f7fc390c9bf | GENESIS
     2 | domain.create   | media      | ok       | 1b0e4c2d9a7f3e65 | 60351f7fc390c9bf
     3 | domain.create   | media.news | ok       | 4ffd561d32c473d6 | 1b0e4c2d9a7f3e65
[demo] /v1/audit/verify → {"first_bad_seq":0,"valid":true}
[demo] success - omega is durable on Postgres and the audit chain is intact
```

## Configuring the server

| flag         | default  | meaning                                                                         |
| ------------ | -------- | ------------------------------------------------------------------------------- |
| `--db`       | empty    | `postgres://...` DSN. Empty falls back to SQLite at `<data-dir>/omega.db`       |
| `--data-dir` | `.omega` | still used for the on-disk CA key + workdir, even when the database is Postgres |

A typical production-shaped invocation:

```bash
omega server \
  --http-addr 0.0.0.0:8080 \
  --trust-domain omega.example.com \
  --data-dir /var/lib/omega \
  --db "postgres://omega:$PASSWORD@db.internal:5432/omega?sslmode=verify-full&sslrootcert=/etc/ssl/certs/db-ca.pem"
```

The CA key still lives at `<data-dir>/ca/`. The follow-up `Authority`
interface (KMS / PKCS#11 / Vault Transit) will move that behind a
plugin so the data directory becomes optional.

## Schema

`storage.Open` runs the parallel DDL on every start; both `CREATE TABLE
IF NOT EXISTS` and the indexes are idempotent so existing databases
aren't re-initialised. The Postgres-flavored shape:

```sql
CREATE TABLE domains (
  name        TEXT    PRIMARY KEY,
  parent      TEXT    NOT NULL DEFAULT '',
  description TEXT    NOT NULL DEFAULT '',
  created_at  BIGINT  NOT NULL
);
CREATE INDEX idx_domains_parent ON domains(parent);

CREATE TABLE audit_log (
  seq        BIGSERIAL PRIMARY KEY,
  ts         BIGINT  NOT NULL,
  kind       TEXT    NOT NULL,
  actor      TEXT    NOT NULL DEFAULT '',
  subject    TEXT    NOT NULL DEFAULT '',
  decision   TEXT    NOT NULL DEFAULT '',
  payload    TEXT    NOT NULL DEFAULT '',
  prev_hash  TEXT    NOT NULL,
  hash       TEXT    NOT NULL UNIQUE
);
CREATE INDEX idx_audit_kind    ON audit_log(kind);
CREATE INDEX idx_audit_subject ON audit_log(subject);

CREATE TABLE audit_forward_state (
  name        TEXT   PRIMARY KEY,
  last_seq    BIGINT NOT NULL,
  updated_at  BIGINT NOT NULL
);
```

Timestamps are stored as `BIGINT` UNIX nanoseconds (rather than
`TIMESTAMPTZ`) so the same on-disk shape works for both backends and
serialisation through the audit chain hash is byte-stable.

## Running the test suite against Postgres

```bash
make test-pg
```

This runs the `Postgres*` tests under
`internal/server/storage` against a transient container and exits
non-zero on any failure. The same env-var contract works in CI:

```bash
OMEGA_TEST_POSTGRES_DSN="postgres://..." go test ./internal/server/storage/... -run Postgres
```

When `OMEGA_TEST_POSTGRES_DSN` is unset (the default), the Postgres
tests are skipped and `go test ./...` runs the SQLite-only path.

## Known limitations

| gap                      | what's missing                                                                                                                                                                | follow-up                                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Multi-writer correctness | `audit.AppendAudit` uses a process-local mutex to serialise the prev_hash lookup + INSERT. Two omega servers writing to the same Postgres can interleave and break the chain. | HA via advisory-lock leader election: a single writer holds a `pg_advisory_lock` and the others stay read-only / standby. |
| Migrations               | DDL is `CREATE TABLE IF NOT EXISTS`. Schema changes need a migration story.                                                                                                   | Bring in a thin migration runner (golang-migrate or hand-rolled) before the first column rename ships.                    |
| Connection tuning        | The store opens with `database/sql` defaults (no `SetMaxOpenConns`, etc).                                                                                                     | Surface pool tunables on the CLI / chart.                                                                                 |

## Files

| path          | purpose                                                         |
| ------------- | --------------------------------------------------------------- |
| `run-demo.sh` | spin Postgres + omega server, prove durability, dump audit rows |
| `Makefile`    | `make demo`, `make down`, `make test-pg` wrappers               |
