# OpenID AuthZEN 1.0 conformance

omega is positioned as an **AuthZEN 1.0 PDP**. This page is the
honest section-by-section conformance audit against the
[OpenID AuthZEN Authorization API 1.0 Final Specification](https://openid.net/specs/authorization-api-1_0.html)
(approved 2026-01-12), so reviewers and integrators can answer
"exactly which parts of AuthZEN does omega implement today"
without reading the source.

Status legend:

- **implemented** — omega ships the surface and the existing tests
  exercise it.
- **partial** — omega ships some of the surface; gaps are listed in
  the notes column.
- **deferred** — the spec section is in scope eventually but
  is not yet implemented.
- **not applicable** — the section governs callers, not PDPs, or
  is out of scope for the current charter.

Spec version audited:

| Spec | Version | Source |
| --- | --- | --- |
| AuthZEN Authorization API | 1.0 Final (2026-01-12) | <https://openid.net/specs/authorization-api-1_0.html> |

## §3 — Subject / Action / Resource / Context

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 3.1 | Subject is `{type, id, properties?}` | implemented | `policy.EvalRequest.Subject` is the same shape |
| 3.2 | Action is `{name, properties?}` | implemented | `policy.EvalRequest.Action` |
| 3.3 | Resource is `{type, id, properties?}` | implemented | `policy.EvalRequest.Resource` |
| 3.4 | Context is a free-form JSON object | implemented | `policy.EvalRequest.Context map[string]any` |

## §4 — Evaluation Request

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 4.1 | A request carries exactly one subject, one action, one resource | implemented | enforced by the JSON schema in `api/openapi.yaml` (single-decision endpoint) |
| 4.2 | Batch requests use top-level defaults + per-entry overrides | implemented | merged in `mergeBatchEval`; missing required field after merge returns 400 |
| 4.3 | Search requests partially specify the request | deferred | the Search APIs in §5.3 are not yet implemented |

## §5 — Endpoints

### §5.1 — Single decision (`POST /access/v1/evaluation`)

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 5.1 | Endpoint accepts an EvaluationRequest, returns `{decision, context?, reasons?}` | implemented | `internal/server/api/http.go` `evaluateAccess`; Cedar is the default PDP |
| 5.1 | `decision` is a boolean | implemented | `policy.EvalResponse.Decision` |
| 5.1 | `reasons` (optional) lists policy identifiers that produced the decision | implemented | `policy.EvalResponse.Reasons` |
| 5.1 | `context` (optional) carries PDP-defined data on the response | partial | omega does not emit a response `context` today; reasons cover the equivalent use case for explainability |

### §5.2 — Batch evaluation (`POST /access/v1/evaluations`)

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 5.2 | Endpoint accepts a BatchEvaluationRequest, returns an ordered list of decisions | implemented | `internal/server/api/http.go` `evaluateAccessBatch` |
| 5.2 | Top-level subject / action / resource / context act as defaults | implemented | merged with each entry; per-eval override wins |
| 5.2 | Maximum batch size policy is implementation-defined | implemented | capped at 100 per `MaxBatchEvaluations`; `maxItems: 100` reflected in the OpenAPI schema |
| 5.2 | Per-decision audit is implementation-defined | implemented | one `access.evaluate` audit row per merged sub-request; payload carries `{request, response, batch:{index,size}}` |

### §5.3 — Subject / Resource / Action search

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 5.3 | `POST /access/v1/search/subject` | deferred | no global subject catalog; would require enumerating SVID issuance history or accepting a candidate list from the caller |
| 5.3 | `POST /access/v1/search/resource` | deferred | Cedar does not enumerate resources by default; a `candidates` extension is on the roadmap |
| 5.3 | `POST /access/v1/search/action` | deferred | same |
| 5.3 | Pagination via `next_token` | not applicable | search itself not yet implemented |

## §6 — Response envelope

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 6.1 | Single-decision response shape | implemented | see §5.1 |
| 6.2 | Batch response is a parallel array under `evaluations` | implemented | `BatchEvalResponse.Evaluations` preserves request order |
| 6.3 | Optional `context` on responses | partial | omega emits `reasons` but not `context` (see §5.1) |

## §7 — Errors

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 7 | Errors use HTTP status codes + JSON `{error: string, ...}` body | implemented | `writeErr` in `internal/server/api/http.go` returns `{"error":"..."}` with the appropriate 4xx/5xx code |
| 7 | `400 Bad Request` for malformed input | implemented | JSON decode failures, missing required fields, invalid SPIFFE IDs |
| 7 | `503 Service Unavailable` for transient unavailability | implemented | non-leader replicas return 503 + `Retry-After: 1` on every leader-only write surface, the same gate that protects audit append |
| 7 | Authentication / authorization is out of scope for the spec | not applicable | omega does not ship caller authentication on the HTTP API in core; ingress / mesh / proxy is the operator's responsibility (documented in `docs/threat-model.md` §S2) |

## §8 — Discovery (`/.well-known/authzen-configuration`)

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 8 | Discovery document advertises supported endpoints | deferred | omega's `/.well-known/openid-configuration` covers OIDC-RP needs; an AuthZEN-specific discovery doc is straightforward to add (`getAuthzenDiscovery` mirroring `getOIDCDiscovery`) once a real caller asks |

## §9 — Security considerations

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 9.1 | Authentication of PDP callers | not applicable | terminated at the deployment layer; see `docs/threat-model.md` §S2 |
| 9.2 | Authorization of PDP callers | not applicable | same |
| 9.3 | Transport security | not applicable | TLS termination is the deployment's responsibility; documented in `docs/threat-model.md` |
| 9.4 | Audit | implemented | every decision appends a row to the tamper-evident audit log; `GET /v1/audit/verify` walks the hash chain |

## What is intentionally not implemented

- **Search APIs (§5.3).** Search relies on a global enumerable
  entity catalog. omega does not maintain one - Cedar policies
  may reference arbitrary `HttpPath`, `Resource`, etc. types
  whose value space is not known to the PDP. A `candidates`-list
  extension that takes operator-provided enumerations is on the
  [ROADMAP.md](../ROADMAP.md). Implementing the Search endpoints to
  always return empty would satisfy the wire format but mislead
  callers, so they stay 404 until there is a substantive answer.
- **Response `context` field.** Today omega emits `reasons` (the
  policy identifiers that produced the decision). The free-form
  `context` field is reserved for future explainability work; no
  caller has needed it yet.

## How this page is maintained

This page is updated whenever a change touches an AuthZEN-facing
surface. Reviewers ask for an update in the same PR for any change
that adds or modifies a `/access/v1/...` endpoint, or that flips a
row from `partial` to `implemented`. The companion page for SPIFFE
is at [conformance-spiffe.md](conformance-spiffe.md).
