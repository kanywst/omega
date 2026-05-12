# Omega

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/0-draft/omega/badge)](https://scorecard.dev/viewer/?uri=github.com/0-draft/omega)
[![CodeQL](https://github.com/0-draft/omega/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/0-draft/omega/actions/workflows/codeql.yml)

> SPIFFE-compatible Workload Identity + OpenID AuthZEN 1.0 Authorization in a single binary. Apache-2.0.

**Ω - the last letter, and the last identity platform you'll need to deploy.**

Running workload identity today means stitching four projects together: SPIRE for identity, OPA / Cedar / OpenFGA / SpiceDB for authorization, an OIDC provider for federation, and a separate audit pipeline. Each speaks its own wire format and ships its own operator. Omega closes those seams in one binary: SPIFFE-native identity, an AuthZEN 1.0 PDP, SPIFFE federation, and a tamper-evident audit log behind one HTTP API and one Workload API socket.

## Why

The standards landed. The integration didn't.

- **SPIFFE/SPIRE** is the de-facto workload identity standard but ends at issuance: authorization is explicitly out of scope.
- **OpenID AuthZEN Authorization API 1.0** was approved as a Final Specification on 2026-01-12 with 15+ PDP implementers (Aserto, AVP, Axiomatics, Cerbos, EmpowerID, OpenFGA, Permit.io, PingAuthorize, PlainID, SGNL, Topaz, WSO2, …). PDPs are abundant; what's missing is a workload identity provider that *natively* speaks AuthZEN as the subject side of every decision.
- **Cedar** joined CNCF Sandbox on 2025-10-08 and is in production at Cloudflare, MongoDB, StrongDM, AWS Bedrock AgentCore. Omega ships it as the default PDP.
- **Vault**'s 2023 BUSL relicensing and IBM's 2024 acquisition fragmented the OSS continuity (OpenBao 2.5 under LF, still maturing). Omega stays Apache-2.0, no CLA, no relicensing trapdoor.
- **OSS workload-identity admin UI is essentially absent**: SPIRE has no console, Vault and Keycloak ship 2010s-era admin panels. Omega's `ui/` dashboard is a first-class deliverable, not an afterthought.

What Omega ships today:

- **One binary**: `omega server`, `omega agent`, `omega <CRUD>`. One install, one upgrade path
- **SPIFFE-native**: X.509-SVID and JWT-SVID, Workload API over a Unix socket
- **AuthZEN 1.0 PDP**: Cedar embedded by default
- **SPIFFE federation**: trust-bundle exchange via `--federate-with`
- **K8s integration**: `OmegaDomain` CRD and a cert-manager `Issuer` / `ClusterIssuer`
- **AI agent delegation**: an `examples/mcp-a2a-delegation/` reference using JWT-SVID with RFC 8693 nested `act` claims
- **Tamper-evident audit log** with hash chain and webhook forwarding
- **Modular**: server / agent / CLI run independently
- **Apache-2.0**, no CLA, no BSL trap door

## Three subjects, one model

Omega's design treats Service, Human, and AI Agent identities under a single
authorization model (Cedar via AuthZEN). Implementation status per subject
today:

| Subject  | Identity format        | Authorization model      | Primary protocol                  | Status      |
| -------- | ---------------------- | ------------------------ | --------------------------------- | ----------- |
| Service  | X.509-SVID, JWT-SVID   | RBAC + ABAC + ReBAC      | mTLS, AuthZEN PDP                 | implemented |
| AI Agent | JWT-SVID + MCP / A2A   | Delegation chain, scoped | RFC 8693 token exchange + AuthZEN | example     |
| Human    | OIDC (SCIM-provisioned: tracked) | RBAC + ABAC + ReBAC | OIDC, AuthZEN PDP        | partial: OIDC IdP federation implemented; SCIM tracked |

Every authorization decision lands in a tamper-evident log, regardless of
subject type.

## Quickstart

```bash
git clone https://github.com/0-draft/omega
cd omega
make docker-up                    # full stack in containers, no toolchain
```

That brings up the full stack - control plane, two node agents (giving the same UID two distinct SPIFFE IDs over separate sockets), the [`examples/hello-svid`](examples/hello-svid/) server + client (which mTLS-handshakes and prints the verified peer SPIFFE ID), and the admin dashboard:

| URL                      | Surface                              |
| ------------------------ | ------------------------------------ |
| `http://127.0.0.1:3000`  | Admin dashboard (Next.js + Tailwind) |
| `http://127.0.0.1:8080`  | Control plane HTTP API + AuthZEN PDP |
| `https://127.0.0.1:9443` | hello-svid demo service (mTLS)       |

Tear it down with `make docker-down` (which removes volumes too, so the next `up` starts from a clean SQLite).

Authorization is exposed at the OpenID AuthZEN 1.0 PDP API endpoint:

```bash
curl -sS -X POST http://127.0.0.1:8080/access/v1/evaluation \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"Spiffe","id":"spiffe://omega.local/example/web"},
       "action":{"name":"GET"},
       "resource":{"type":"HttpPath","id":"/api/foo"}}'
# -> {"decision":true,"reasons":["policy0"]}   (or {"decision":false} when no policy permits)
```

Pass `--policy-dir DIR` to `omega server` to load `*.cedar` files at startup.

### Other entry points

- `make demo` - local Go build of the same hello-svid loop. Faster iteration when working on `internal/` code, no Docker needed
- `make docker-demo` - the compose stack but exits as soon as the hello-svid client succeeds. Used by CI to smoke-test the wiring
- `cd ui && npm run dev` - Next dev server with hot reload, proxies to whatever `OMEGA_API` points at (defaults to `http://127.0.0.1:8080`). Use this when iterating on the dashboard itself

## Architecture

```text
+----------------------+        +------------------+
|  omega server        |  HTTP  |  omega agent     |    workload
|  (control plane)     |<------>|  (Workload API)  |<--- (uds, X509-SVID)
|  - SQLite / Postgres |        |  - peercred      |
|  - CA + SVID issuer  |        |  - cache         |
|  - AuthZEN PDP       |        +------------------+
|  - SPIFFE federation |
|  - Audit log         |
+----------------------+
```

Components are independently runnable (`omega server identity`, `omega server policy`, `omega agent`) so deployments can scale or replace each piece without forklift upgrades.

## Endpoints

| Method | Path                              | Purpose                                                                |
| ------ | --------------------------------- | ---------------------------------------------------------------------- |
| GET    | `/healthz`                        | Liveness                                                               |
| POST   | `/v1/domains`                     | Create a SPIFFE namespace (`{name, description}`)                      |
| GET    | `/v1/domains`                     | List domains                                                           |
| GET    | `/v1/domains/{name}`              | Fetch a domain                                                         |
| POST   | `/v1/svid`                        | Issue an X.509-SVID from a CSR (`{spiffe_id, csr}`)                    |
| POST   | `/v1/attest/k8s`                  | Attest a Kubernetes ServiceAccount projected token + CSR → X.509-SVID  |
| GET    | `/v1/bundle`                      | Trust bundle PEM (CA cert)                                             |
| POST   | `/v1/oidc/exchange`               | Swap an external OIDC IdP ID token for an omega JWT-SVID (Human flow)  |
| POST   | `/access/v1/evaluation`           | OpenID AuthZEN 1.0 PDP evaluation (single decision)                    |
| POST   | `/access/v1/evaluations`          | OpenID AuthZEN 1.0 PDP evaluation (batch, with top-level defaults)     |
| GET    | `/.well-known/openid-configuration` | OIDC discovery (when `--issuer-url` is set; for AWS IAM, GCP WIF, K8s) |

The full HTTP surface (request/response shapes, status codes, leader-only endpoints, federation and audit routes) is described in the OpenAPI 3.1 specification at [`api/openapi.yaml`](api/openapi.yaml).

Workload API gRPC (SPIFFE) is served by `omega agent` over a Unix socket and speaks the standard `SpiffeWorkloadAPI` service: `FetchX509SVID` and `FetchX509Bundles`.

## Standards alignment

Section-by-section audits live at [docs/conformance-spiffe.md](docs/conformance-spiffe.md) (SPIFFE Workload API + X.509-SVID + JWT-SVID + Bundle Format + Federation) and [docs/conformance-authzen.md](docs/conformance-authzen.md) (AuthZEN 1.0 Final Specification).

| Layer                 | Standard                                                       | Status      |
| --------------------- | -------------------------------------------------------------- | ----------- |
| Workload identity     | SPIFFE / SPIRE compatible (X.509-SVID, JWT-SVID, Workload API) | implemented |
| CA backend (Plugin)   | disk default + Vault PKI + step-ca; AWS PCA / GCP CAS / Azure KV via the same `identity.Authority` seam | partial: disk + vault-pki + step-ca shipped |
| Authorization         | OpenID AuthZEN 1.0                                             | implemented |
| Federation            | SPIFFE federation (trust bundle exchange)                      | implemented |
| Token binding         | RFC 8705 (mTLS-bound)                                          | implemented |
| OIDC discovery        | OpenID Connect Discovery 1.0 (for JWT-SVID consumers)          | implemented |
| Token exchange        | RFC 8693 (nested `act`)                                        | example     |
| AI agent identity     | MCP (Anthropic), A2A (Google)                                  | example     |
| Multi-domain identity | IETF WIMSE                                                     | tracked     |
| OIDC IdP federation   | OIDC ID-token-in, omega JWT-SVID-out (`POST /v1/oidc/exchange`)| implemented |
| Provisioning          | SCIM 2.0                                                       | tracked     |
| Cryptography          | NIST FIPS 203 / 204 / 205 (ML-KEM / ML-DSA / SLH-DSA)          | tracked     |

## Scope

Omega is a deliberately bounded project. The charter is **workload and agent identity plus authorization control plane**: issuance, AuthZEN evaluation, federation, audit.

The minimum demo path that ships in the source tree today is enumerated in [docs/scope.md](docs/scope.md). The rule for whether a new feature lands in Core, Plugin, or Out-of-tree lives in [docs/design-philosophy.md](docs/design-philosophy.md). Things Omega does *not* try to be (secrets storage, end-user login UX, service-mesh data plane, SIEM, agent runtime) are catalogued with their recommended alternatives in [docs/non-goals.md](docs/non-goals.md). The forward-looking work is tracked in [ROADMAP.md](ROADMAP.md). The threat model the project mitigates today, with assets and STRIDE-categorised threats, lives in [docs/threat-model.md](docs/threat-model.md); the *why* behind the major design choices is recorded in [docs/adr/](docs/adr/).

## Observability

`omega-server` exposes Prometheus metrics on the same listener as the admin API
(`/metrics`): HTTP rate / latency by route, AuthZEN decision allow/deny counts and
evaluation latency, SVID issuance by kind, audit append counts, plus the standard
Go runtime collectors. A self-contained Prometheus + Grafana stack with the
auto-provisioned "Omega control plane" dashboard ships in
[`examples/observability/`](examples/observability/):

```bash
make observability-up
# Grafana    http://localhost:13001
# Prometheus http://localhost:19090
# /metrics   http://localhost:18080/metrics
make observability-down
```

Full metric reference, cardinality notes, and starter alerting rules:
[docs/observability.md](docs/observability.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
