# Omega

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kanywst/omega/badge)](https://scorecard.dev/viewer/?uri=github.com/kanywst/omega)
[![CodeQL](https://github.com/kanywst/omega/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/kanywst/omega/actions/workflows/codeql.yml)

> SPIFFE-compatible workload identity and OpenID AuthZEN 1.0 authorization in a single binary. Apache-2.0.

Omega issues or consumes SPIFFE identities, decides what each one may do with an AuthZEN 1.0 PDP backed by Cedar, and records every decision in a tamper-evident audit log. Services, people and AI agents go through the same policy engine and the same log.

## Why

SPIFFE and SPIRE are the standard for workload identity, but they stop at issuance; authorization is out of their scope. AuthZEN 1.0 became a Final Specification on 2026-01-12 and there are many PDPs (Aserto, AVP, Axiomatics, Cerbos, EmpowerID, OpenFGA, Permit.io, PingAuthorize, PlainID, SGNL, Topaz, WSO2 and others), but none of them is also the identity provider for the subjects it decides about. Omega puts the two together: the SPIFFE ID is the AuthZEN subject.

Cedar joined the CNCF Sandbox on 2025-10-08 and runs in production at Cloudflare, MongoDB, StrongDM and AWS Bedrock AgentCore; Omega uses it as the default PDP. Omega stays Apache-2.0 with no CLA, and ships an admin dashboard (`ui/`), which open-source workload identity tools have mostly lacked.

## What it does

| Area | What you get | Docs |
| --- | --- | --- |
| Identity | X.509-SVID and JWT-SVID over the SPIFFE Workload API, from the built-in CA, Vault PKI or step-ca, or consumed from an upstream SPIRE / Istio trust domain (`--identity-source=spire-upstream`) | [conformance-spiffe.md](docs/conformance-spiffe.md) |
| Authorization | AuthZEN 1.0 PDP with Cedar policies | [conformance-authzen.md](docs/conformance-authzen.md) |
| Domains | A tree of namespaces (`media` → `media.news`) whose admins run their own subtree; policies use `principal in Domain::"media"` | [domains.md](docs/domains.md) |
| Groups | Groups owned by a domain, with memberships that can expire; policies use `principal in Group::"media:oncall"` | [groups.md](docs/groups.md) |
| People | OIDC IdP federation, and users and groups pushed from an identity provider over SCIM 2.0 | [scim.md](docs/scim.md) |
| AI agents | RFC 8693 token exchange with nested `act`, and the ID-JAG grant on `POST /oauth2/token`, optionally DPoP-bound | [id-jag.md](docs/id-jag.md) |
| Local decisions | The node agent decides from a synced copy of the policy, keeps working through a control-plane outage for a bounded time, and records every decision centrally | [local-pdp.md](docs/local-pdp.md) |
| Federation | SPIFFE trust bundle exchange (`--federate-with`) | [conformance-spiffe.md](docs/conformance-spiffe.md) |
| Audit | Hash-chained log with webhook and OTLP forwarding | [observability.md](docs/observability.md) |
| Kubernetes | Helm chart, `OmegaDomain` CRD, and a cert-manager `Issuer` / `ClusterIssuer` | [charts/omega](charts/omega/README.md) |

Already running SPIRE? [examples/spire-authz](examples/spire-authz/) keeps SPIRE as the issuer and adds Omega's authorization, SCIM-provisioned people, node-local decisions and audit on top, end to end in one `make demo`.

One binary runs every role: `omega server`, `omega agent`, `omega operator`, and the CLI (`omega domain`, `omega group`, `omega policy`, `omega svid`).

## Three subjects, one model

| Subject | Identity | Protocol | Status |
| --- | --- | --- | --- |
| Service | X.509-SVID, JWT-SVID | mTLS, AuthZEN PDP | implemented |
| Person | OIDC, SCIM-provisioned groups | OIDC federation, AuthZEN PDP | implemented |
| AI agent | JWT-SVID with a delegation chain | RFC 8693 token exchange, ID-JAG grant, AuthZEN PDP | implemented; MCP / A2A as an example |

All three are evaluated by the same Cedar policies and recorded in the same log.

## Quickstart

```bash
git clone https://github.com/kanywst/omega
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
+----------------------+        +----------------------+
|  omega server        |  HTTP  |  omega agent         |    workload
|  (control plane)     |<------>|  - Workload API      |<--- (uds, SVIDs)
|  - SQLite / Postgres |        |  - local PDP         |<--- PEP (AuthZEN)
|  - CA + SVID issuer  |        |    (optional)        |
|  - AuthZEN PDP       |        +----------------------+
|  - domains, groups,  |
|    SCIM              |
|  - federation        |
|  - audit log         |
+----------------------+
```

The server, agent and operator run independently, so each can be scaled or replaced on its own.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | Liveness |
| GET, POST, DELETE | `/v1/domains`, `/v1/domains/{name}` | Domain tree |
| POST, DELETE | `/v1/domains/{name}/admins` | Domain admins |
| GET, POST, DELETE, PUT | `/v1/domains/{name}/groups/...` | Groups and members |
| POST | `/v1/svid`, `/v1/svid/jwt` | Issue an X.509-SVID from a CSR, or a JWT-SVID |
| POST | `/v1/attest/k8s` | Kubernetes ServiceAccount token + CSR to X.509-SVID |
| GET | `/v1/bundle`, `/v1/spiffe-bundle` | Trust bundle |
| POST | `/v1/oidc/exchange` | External OIDC ID token to JWT-SVID |
| POST | `/v1/token/exchange` | RFC 8693 token exchange |
| POST | `/oauth2/token` | ID-JAG grant |
| POST | `/access/v1/evaluation`, `/access/v1/evaluations` | AuthZEN evaluation, single and batch |
| GET | `/v1/policy/bundle` | Policy bundle for node agents |
| GET, POST | `/v1/audit`, `/v1/audit/decisions` | Read the audit log; record local decisions |
| various | `/scim/v2/{idp}/...` | SCIM 2.0 Users and Groups |
| GET | `/.well-known/openid-configuration` | OIDC discovery (with `--issuer-url`) |

The full HTTP surface (request/response shapes, status codes, leader-only endpoints, federation and audit routes) is described in the OpenAPI 3.1 specification at [`api/openapi.yaml`](api/openapi.yaml).

Workload API gRPC (SPIFFE) is served by `omega agent` over a Unix socket and speaks the standard `SpiffeWorkloadAPI` service: `FetchX509SVID`, `FetchX509Bundles`, `FetchJWTSVID` and `FetchJWTBundles`.

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
| Token exchange        | RFC 8693 (nested `act`)                                        | implemented |
| Agent authorization   | ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant), RFC 9449 DPoP | implemented |
| AI agent identity     | MCP (Anthropic), A2A (Google)                                  | example     |
| Multi-domain identity | IETF WIMSE                                                     | tracked     |
| OIDC IdP federation   | OIDC ID-token-in, omega JWT-SVID-out (`POST /v1/oidc/exchange`)| implemented |
| Provisioning          | SCIM 2.0                                                       | implemented |
| Cryptography          | NIST FIPS 203 / 204 / 205 (ML-KEM / ML-DSA / SLH-DSA)          | tracked     |

## Scope

Omega is the identity and authorization control plane for workloads, people and agents: issuance, AuthZEN evaluation, federation and audit. What ships today is listed in [docs/scope.md](docs/scope.md), where a new feature belongs (core, plugin or out of tree) in [docs/design-philosophy.md](docs/design-philosophy.md), and what Omega deliberately does not do, with alternatives, in [docs/non-goals.md](docs/non-goals.md). Planned work is in [ROADMAP.md](ROADMAP.md), the threat model in [docs/threat-model.md](docs/threat-model.md), and the reasons behind major design choices in [docs/adr/](docs/adr/).

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
