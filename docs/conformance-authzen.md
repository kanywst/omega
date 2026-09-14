# OpenID AuthZEN 1.0 conformance

omega is positioned as an **AuthZEN 1.0 PDP**. This page is the honest section-by-section conformance audit against the [OpenID AuthZEN Authorization API 1.0 Final Specification](https://openid.net/specs/authorization-api-1_0-final.html) (approved 2026-01-12), so reviewers and integrators can answer "exactly which parts of AuthZEN does omega implement today" without reading the source.

Status legend:

- **implemented** — omega ships the surface and the existing tests exercise it.
- **partial** — omega ships some of the surface; gaps are listed in the notes column.
- **deferred** — the spec section is in scope eventually but is not yet implemented.
- **not applicable** — the section governs callers, not PDPs, or is out of scope for the current charter.

Spec version audited:

| Spec | Version | Source |
| --- | --- | --- |
| AuthZEN Authorization API | 1.0 Final (2026-01-12) | <https://openid.net/specs/authorization-api-1_0-final.html> |

Section numbers below are the Final Specification's own. Earlier revisions of this page numbered its sections against a pre-Final draft — Search in particular was cited as §5.3 where the Final text has §8 — so any external reference to the old numbering will not line up.

## §5 — Information Model

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 5.1 | Subject is `{type, id, properties?}` | implemented | `policy.EvalRequest.Subject` is the same shape |
| 5.2 | Resource is `{type, id, properties?}` | implemented | `policy.EvalRequest.Resource` |
| 5.3 | Action is `{name, properties?}` | implemented | `policy.EvalRequest.Action`; maps to Cedar's `Action::"name"` |
| 5.4 | Context is a free-form JSON object | implemented | `policy.EvalRequest.Context map[string]any`. Values are bridged to Cedar primitives; a fractional number is rejected rather than truncated, because Cedar has no float type |
| 5.5 | Decision is a boolean, with optional decision context | partial | `policy.EvalResponse.Decision` is the boolean. omega emits `reasons` (the policy ids that produced the decision) but not the free-form response `context` |

## §6 — Access Evaluation API (`POST /access/v1/evaluation`)

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 6.1 | Request carries exactly one subject, one action, one resource | implemented | enforced by the JSON schema in `api/openapi.yaml`; handler is `evaluateAccess` in `internal/server/api/http.go` |
| 6.2 | Response is `{decision, context?, reasons?}` with a boolean `decision` | implemented | `policy.EvalResponse`; Cedar is the default PDP |
| 6.2 | `reasons` (optional) lists policy identifiers | implemented | `policy.EvalResponse.Reasons`, stable ids resolved from `@id(...)` or a filename-stem prefix |
| 6.2 | `context` (optional) carries PDP-defined data on the response | partial | not emitted; `reasons` covers the explainability use case |

## §7 — Access Evaluations API (`POST /access/v1/evaluations`)

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 7.1 | Endpoint accepts a batch request, returns an ordered list of decisions | implemented | `evaluateAccessBatch` |
| 7.1.1 | Top-level subject / action / resource / context act as defaults | implemented | merged in `mergeBatchEval`; per-evaluation override wins, and a required field still missing after the merge is a 400 |
| 7.1.2 | Evaluations options | deferred | omega evaluates every entry and always returns the full parallel array; the spec's optional short-circuit semantics are not implemented |
| 7.2 | Response is a parallel array under `evaluations` | implemented | `BatchEvalResponse.Evaluations` preserves request order |
| 7.2 | Maximum batch size is implementation-defined | implemented | capped at 100 per `MaxBatchEvaluations`; `maxItems: 100` reflected in the OpenAPI schema |
| — | Per-decision audit (implementation-defined) | implemented | one `access.evaluate` audit row per merged sub-request; payload carries `{request, response, batch:{index,size}}` |

## §8 — Search APIs

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 8.1 | A search returns entities that would correspond to a permitted decision | implemented | every candidate is run through the same PDP path as `POST /access/v1/evaluation` and kept only on `allow`, so a result re-submitted to Access Evaluation returns `true` for as long as the policy and context hold |
| 8.1 | Search SHOULD traverse intermediate attributes and relationships transitively | implemented | Cedar resolves `in` against the entity store's `parents`, so group membership and resource hierarchies are followed during evaluation |
| 8.2 | Pagination via opaque `next_token` | implemented | `page.token` / `page.limit` in, `page.next_token` / `page.count` out. See the deviation note below on what a page is a page *of* |
| 8.2 | All fields except the token MUST be identical across a paginated sequence; PDP SHOULD error otherwise | implemented | the token carries a SHA-256 fingerprint of the request with `page.token` removed; a mismatch is a 400. Stateless, so any replica can serve the next page |
| 8.2.2 | `next_token` is REQUIRED and MUST be empty on the last page | implemented | `SearchPageResponse.NextToken` has no `omitempty` |
| 8.2.2 | `total` (optional) | not applicable | never emitted; see the deviation note |
| 8.3 | Response carries `results` | implemented | `SubjectSearchResponse` / `ResourceSearchResponse` / `ActionSearchResponse` |
| 8.4 | `POST /access/v1/search/subject` | implemented | pattern shape (`subject: {type}`) under `--authzen-search-entity-store`; candidate list (`subjects: [...]`) always |
| 8.4.1 | Subject `id` SHOULD be omitted and MUST be ignored if present | implemented | only `subject.type` is read |
| 8.5 | `POST /access/v1/search/resource` | implemented | same two shapes, on `resource` / `resources` |
| 8.6 | `POST /access/v1/search/action` | implemented | per 8.6.1 the spec shape carries no `action` key at all, so omitting `actions` selects enumeration |

## §9 — Policy Decision Point Metadata

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 9.1.1 | Endpoint parameters use the registered names | implemented | `policy_decision_point`, `access_evaluation_endpoint`, `access_evaluations_endpoint`, `search_subject_endpoint`, `search_resource_endpoint`, `search_action_endpoint`. Through 0.4.0 the three Search names were emitted reversed (`subject_search_endpoint`), which §9.1.1 notes is indistinguishable to a PEP from a PDP that cannot serve Search at all |
| 9.1.2 | Capabilities parameters | deferred | omega does not advertise `supported_capabilities`; it declares no capability URNs, and the `page.properties` extension point that would need one is not implemented |
| 9.1.3 | Signature parameter | deferred | metadata is served unsigned |
| 9.2 | Metadata published at `/.well-known/authzen-configuration` | implemented | the PDP base is `--issuer-url` (canonical, validated `https`); the handler returns `404` when it is not set, so the base cannot be sourced from a spoofed `Host` header |

## §10 — Transport

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 10.1.1 | JSON serialization over HTTPS | implemented | `writeJSON` sets `application/json`; TLS termination is the deployment's responsibility |
| 10.1.2 | Errors use the defined HTTP status codes | implemented | `writeErr` returns `{"error":"..."}` with a 4xx/5xx code: 400 for malformed input, missing required fields and invalid SPIFFE IDs |
| 10.1.2 | A denial is `200` with `{"decision": false}`, not an HTTP error | implemented | evaluation handlers only return non-200 for transport / validation failures |
| 10.1.3 | Request identification | deferred | omega does not read or echo a request id header; correlation is via the OTel trace context it already propagates |
| — | `503 Service Unavailable` for transient unavailability | implemented | non-leader replicas return 503 + `Retry-After: 1` on every leader-gated surface, the same gate that protects audit append |

## §11 — Security Considerations

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 11.1 | Communication integrity and confidentiality | not applicable | TLS termination is the deployment's responsibility; see `docs/threat-model.md` |
| 11.2 | Policy confidentiality and sender authentication | not applicable | caller authentication on the HTTP API is terminated at the deployment layer (ingress / mesh / proxy); see `docs/threat-model.md` §S2 |
| 11.3 | Sender authentication failure | not applicable | same |
| 11.7 | Availability and denial of service | implemented | batch and search are both capped at 100 evaluations per request (`MaxBatchEvaluations`, `MaxSearchCandidates`), and search pages the candidate window *before* evaluating so one request cannot enumerate an unbounded store |
| — | Audit | implemented | every decision appends a row to the tamper-evident audit log; `GET /v1/audit/verify` walks the hash chain |

## Deviations worth reading before integrating

- **Search needs an enumerable search space, and omega's is the Cedar entity store.** The spec leaves candidate enumeration to the PDP and says nothing about what to do when the search space cannot be resolved — earlier revisions of this page claimed §5.3.2 required an error there, which is not in the Final text. Cedar has no global directory, so omega offers two ways to name the space: an explicit candidate list (an omega extension, always available), or `--authzen-search-entity-store`, which resolves the spec's pattern shape against the entities declared in `--policy-dir/entities.json`. The flag is off by default because turning it on makes `entities.json` the definition of who exists: an identity it does not declare is invisible to enumeration, and that is a claim an operator should make deliberately.
- **Enumerating a type the store does not declare is a 400, not an empty `results`.** The spec permits an empty result set, but "this PDP has never heard of type `user`" and "you may act on none of them" are different answers, and a PEP cannot tell them apart from `[]`.
- **A page is a window of the search space, not of the matches.** Candidates are evaluated only inside the requested window, which is what bounds PDP work and audit rows per request. The consequence is that a page MAY come back with fewer results than its `limit`, or with none at all, while later pages still hold results — which is exactly the loop `next_token` is specified to drive. It also means `total` cannot be reported honestly (the number of matches across all pages is unknown until they have all been evaluated), so omega omits it rather than emitting the size of the search space under a key the spec defines as the number of matching results.
- **Response `context` field.** omega emits `reasons` (the policy identifiers that produced the decision). The free-form `context` field is reserved for future explainability work; no caller has needed it yet.

## How this page is maintained

This page is updated whenever a change touches an AuthZEN-facing surface. Reviewers ask for an update in the same PR for any change that adds or modifies a `/access/v1/...` endpoint, or that flips a row from `partial` to `implemented`. Claims about what the spec requires are checked against the spec text itself rather than from memory — the audit that produced the current revision found two that were not in it. The companion page for SPIFFE is at [conformance-spiffe.md](conformance-spiffe.md).
