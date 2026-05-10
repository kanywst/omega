# Threat model

This page is the threat model for the Omega control plane and node
agent in the configuration shipped in the source tree. It is written
to give operators an honest read of what Omega defends against, what
it does *not* defend against, and which mitigations live where.

The model uses [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
as the categorisation: Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege.

It is updated when the architecture changes. The page is meant to be
read alongside [`docs/scope.md`](scope.md) and
[`docs/non-goals.md`](non-goals.md), which together state what the
project is *and* is not in the business of solving.

## Trust boundaries

```text
+--------------------+   1. HTTP/JSON       +-------------------+
| Operator / admin   | -------------------> | omega server      |
| (kubectl / curl)   |                      | (control plane)   |
+--------------------+                      | - SQLite/Postgres |
                                            | - CA + SVID issue |
+--------------------+                      | - AuthZEN PDP     |
| Workload (process) |                      | - audit log       |
| on a node          |                      | - federation peer |
+--------------------+                      +-------------------+
        |                                         ^
        | 2. SPIFFE Workload API                  | 3. HTTP/JSON
        |    gRPC over UDS                        |    (agent → server)
        |    (SO_PEERCRED auth)                   |
        v                                         |
+--------------------+   ----------------->-------+
| omega agent        |
| (per node)         |
+--------------------+

+-------------------+   4. SPIFFE federation     +-------------------+
| omega server      | <------------------------> | omega server      |
| (this domain)     |    bundle exchange         | (peer domain)     |
+-------------------+                            +-------------------+
```

Boundaries enforced today:

1. Operator / admin → server: HTTP/JSON. **Network-layer auth is
   delegated to the deployment** (ingress, service mesh, mTLS at
   the load balancer). The server itself does not authenticate or
   authorize the caller of `POST /v1/domains` or `POST /v1/svid`.
   The CLI subcommands (`omega domain`, `omega svid`) speak the same
   HTTP API and inherit the same property.
2. Workload → agent: SPIFFE Workload API gRPC over a Unix domain
   socket. Authentication is `SO_PEERCRED`-based (the agent reads
   the connecting process's UID and looks up the matching SPIFFE
   ID).
3. Agent → server: HTTP/JSON, same listener as the operator API.
4. Server → peer server: SPIFFE federation. Bundle exchange is a
   one-way `GET /v1/bundle` against the peer.

What lives outside the trust boundary:

- The host kernel. If the kernel is compromised, `peercred` lies and
  every workload identity is forgeable.
- The Postgres / SQLite filesystem. Anyone with read access to
  `omega.db` (SQLite) or the Postgres data directory holds the audit
  log and the CA private key.
- The TLS termination point. Omega does not terminate TLS itself in
  the default `omega server` listener.

## Assets

| ID | Asset | Where it lives | Why it matters |
| --- | --- | --- | --- |
| A1 | CA root private key | Memory + on-disk file under `--data-dir`, written at first boot | Forging this key means issuing arbitrary X.509-SVIDs |
| A2 | JWT-SVID signing key | Same `--data-dir` keyset | Forging this key means issuing arbitrary JWT-SVIDs |
| A3 | Cedar policy set | DB + `--policy-dir` | Determines every authorization decision |
| A4 | Audit log | DB table `audit_log` | Tamper-evident record of every decision and issuance |
| A5 | Federation peer bundles | DB table `federated_bundles` | Trust anchors for cross-trust-domain identity |
| A6 | Workload API UDS socket | `/tmp/omega-agent.sock` (default; see S1) | Path through which workloads request SVIDs |
| A7 | Postgres advisory lock state | Postgres lock table | Determines which replica accepts writes |

## Threats

The threats below are the ones we have explicit answers for. Threats
the project has *not* mitigated are listed under
[Out of scope](#out-of-scope) so operators can decide for themselves
whether their environment closes the gap.

### S1 — Spoofing a workload identity to the agent

A malicious process on a node connects to `/tmp/omega-agent.sock`
and asks for an SVID belonging to a different workload.

- Mitigation: peercred attestation reads the connecting process's
  UID via `SO_PEERCRED`. Issuance is keyed on `(uid → spiffe_id)`
  registrations. A process running under a different UID cannot
  receive another UID's SVID.
- Residual risk: a process that gains the target UID (e.g. via
  `setuid` after compromising a privileged binary) defeats the
  attestor. Attestation is only as strong as Linux UID isolation;
  containers or VMs sharing UIDs across workloads weaken this.
- Default socket path is `/tmp/omega-agent.sock`. The agent removes
  any pre-existing file before binding, but `/tmp` is still a shared
  filesystem - a hostile non-root user with write access to `/tmp`
  cannot impersonate the agent (the sticky bit prevents removing
  the existing socket and `bind` then fails) but *can* deny service
  by creating the file before the agent starts.
- Recommended hardening: pass `--socket /run/omega/agent.sock` (or
  `/var/run/omega/agent.sock` on systems without `/run`) and create
  the parent directory mode `0755` owned by the agent's UID at
  install time. The Helm chart in `charts/omega/` and the example
  systemd units should follow this pattern; revisit once we change
  the in-binary default (separate PR).
- Out-of-tree mitigation: deploy with one workload per UID and per
  network namespace, or use a stronger attestor (Kubernetes
  ServiceAccount projected token, EC2 IMDSv2 hash, etc., tracked in
  `ROADMAP.md`).

### S2 — Spoofing the control plane to a workload or peer

An attacker on the network impersonates `omega server` (or a
federation peer) and serves forged bundles.

- Mitigation today: federation bundle exchange runs over plain HTTP
  by default. **TLS termination is the deployment's responsibility.**
  Omega's `--http-addr` listener does not bring its own TLS; users
  who care about S2 must front the server with mTLS (mesh, ingress,
  or a TLS-terminating reverse proxy).
- Residual risk: deployments that expose `omega server` directly on
  the network without TLS allow this attack at the federation layer.
  The operator is expected to know.

### T1 — Tampering with the audit log

An attacker with database access edits or deletes audit rows to
hide an authorization decision or an SVID issuance.

- Mitigation: every audit row carries `prev_hash` and `hash` columns
  computed over `(seq, ts, kind, actor, subject, decision, payload,
  prev_hash)`. `GET /v1/audit/verify` walks the chain from genesis;
  the response includes `first_bad_seq`, the lowest sequence at which
  the chain breaks.
- The hash chain is *tamper-evident*, not tamper-resistant: an
  attacker with database write access can compute new hashes, but
  must rewrite every subsequent row to keep the chain valid, and
  any external verifier with a previously-published hash anchor will
  detect the rewrite.
- Out-of-tree mitigation: forward the audit log to a write-once
  store (S3 Object Lock, Splunk Indexer with frozen retention, etc.)
  via `audit.Pump`'s webhook forwarder. OTLP forwarder is on the
  roadmap.

### T2 — Tampering with policy in the database

An attacker with database write access modifies the Cedar policy
set to permit an action that should be denied.

- Mitigation today: policy mutation goes through the leaderOnly
  HTTP path (`POST /v1/domains` etc.; Cedar policy CRUD over HTTP
  is partial - see `gap-analysis.md`). Direct DB writes leave no
  audit row.
- Residual risk: an attacker who reaches the database directly
  bypasses the audit log. Mitigation is at the database access
  layer, not Omega.
- Recommended: run Postgres with row-level access control or a
  least-privileged role for the omega-server process; the
  `--policy-dir` flag also lets policies be sourced from a file
  tree under version control, which moves T2 from "DB attack" to
  "VCS attack".

### T3 — Tampering with the trust bundle exchanged with a peer

A federation peer (or someone impersonating one) advertises a
modified trust bundle so SVIDs from the attacker's domain are
trusted.

- Mitigation today: bundle exchange happens over `GET /v1/bundle`,
  with a one-way pull and an exponential backoff retry. There is no
  authentication of the peer at the application layer.
- Residual risk: as with S2, the deployment is responsible for
  authenticating the peer at the transport layer. Federation
  partners that trust each other should pin TLS or mutual TLS.

### R1 — Repudiating an authorization decision

A workload (or operator) denies that a given allow / deny decision
was theirs.

- Mitigation: every `POST /access/v1/evaluation` adds a row to the
  audit log keyed by `subject.id`, with the request and response
  payloads. The decision counter `omega_authzen_decisions_total` is
  also exposed at `/metrics`.
- Residual risk: the audit log records what the *server* received.
  If the request body was forged (for example, a bug or an attacker
  injecting `subject.id`), the audit log records the forged
  identity. Authentication of the caller is the deployment's
  responsibility (S2 above).

### I1 — Information disclosure of CA / JWT signing keys

An attacker reads `--data-dir` and exfiltrates the CA root key or
the JWT signing key.

- Mitigation today: keys are stored as plaintext files under
  `--data-dir`, owned by the omega-server process user. There is no
  envelope encryption at rest.
- Residual risk: anyone who can read the data directory holds the
  trust domain. Mitigation is at the filesystem / pod-security
  layer (host filesystem ACLs, Kubernetes `securityContext`,
  encrypted volumes).
- Out-of-tree mitigation: HSM / KMS upstream plugins (Vault PKI,
  step-ca, AWS Private CA, GCP CAS, Azure Key Vault) are tracked in
  `ROADMAP.md`. With those, the CA root never leaves the KMS.

### I2 — Information disclosure via audit log content

The audit log payload column carries decision context, which can
include resource identifiers and contextual attributes.

- Mitigation today: the audit log is read-only over `GET /v1/audit`
  and is gated by the same trust boundary as the rest of the HTTP
  API (the deployment authenticates the caller).
- Residual risk: a deployment that exposes `/v1/audit` without
  authentication leaks decision metadata to anyone who can reach
  the listener. Operators must front the API with auth.

### D1 — Denial of service via SVID issuance flood

An attacker (or a misbehaving workload) requests SVIDs at a high
rate, exhausting CA throughput or filling the audit log.

- Mitigation today: there are no per-caller rate limits in core. The
  agent's UDS socket is a serialisation point per node, but the HTTP
  API is not.
- Residual risk: real. Operators should rate-limit the API at the
  ingress layer.
- Tracked: in-process token-bucket per `subject.id` is a candidate
  Plugin-layer feature; not on the near-term roadmap because the
  deployment-time answer (ingress rate limit) is a known good
  pattern.

### D2 — Denial of service via Postgres leader thrash

Two replicas fight over the advisory lock and neither stays
leader long enough to accept writes.

- Mitigation today: `pg_try_advisory_lock` is non-blocking and the
  current leader holds the lock until disconnect. The server polls
  `IsLeader` cheaply on every write; failed writes return 503 with
  `Retry-After: 1`. Clients are expected to honour `Retry-After`
  and retry against `GET /v1/leader`.
- Residual risk: an attacker who can drop and reconnect a Postgres
  client repeatedly can force lock churn. Mitigation is database
  access control.

### E1 — Elevation of privilege via policy bug

A Cedar policy is written incorrectly and grants a workload more
than the operator intended.

- Mitigation today: Cedar's default-deny semantics (no permit ⇒
  deny) and the AuthZEN evaluation log make every decision
  observable. Cedar is also formally analysable with the
  `cedar-go` analysis tooling (out of tree).
- Residual risk: a buggy policy that *does* permit the action
  passes review. Mitigation is policy review and CI tests, not
  Omega itself. The `examples/envoy-ext-authz/` and
  `examples/mcp-a2a-delegation/` directories carry policy fixtures
  that can be used as starting points.

### E2 — Elevation of privilege via token-exchange chain forgery

A workload presents an `actor_token` that is *not* the workload's
own SVID and asks for a delegated token in someone else's name.

- Mitigation today: `tokenExchange` requires
  `requested_spiffe_id == actor_token.sub` regardless of policy
  configuration. The optional Cedar gate
  (`WithEnforceTokenExchangePolicy`) layers further restrictions.
- Residual risk: if the `actor_token` was issued by the same Omega
  server, this baseline holds. Cross-issuer delegation chains are
  not supported today.

## Out of scope

These are threats the project deliberately does not address. Each
has a recommended out-of-tree answer.

| Threat | Recommended mitigation |
| --- | --- |
| TLS termination of the HTTP API | Service mesh, ingress, or sidecar (e.g. Linkerd, Istio, Envoy front proxy, Kubernetes Ingress) |
| Caller authentication on `omega server` | OIDC IdP federation hub (tracked in `ROADMAP.md`); until that lands, terminate auth at the ingress |
| Application secrets leak | Vault / OpenBao / cloud secrets manager - Omega's DB holds policy and audit, not application secrets |
| Endpoint hardening of agent UDS | Pod / VM security context (own UID, no shared mount namespace) |
| At-rest encryption of CA keys | HSM / KMS plugins (tracked in `ROADMAP.md`); until then, encrypted volumes |
| Long-lived credential revocation (CRL / OCSP) | Short-lived rotation is the design, see [`docs/non-goals.md`](non-goals.md#omega-is-not-a-crl--ocsp-responder) |
| Compromised host kernel | Out of any application-layer control plane's reach |

## How this page is maintained

The threat model is updated whenever a change touches one of:

- A trust boundary (a new socket, a new authentication path, a new
  network listener).
- A new asset class (a new key kind, a new audit-log column, a new
  storage backend).
- A new attestor or PDP plugin that changes which threats Omega
  itself owns.

Reviewers will ask for an update to this page in the same PR. The
maintainers track it as part of release readiness in
[`RELEASING.md`](../RELEASING.md).
