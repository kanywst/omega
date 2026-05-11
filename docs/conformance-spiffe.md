# SPIFFE conformance

omega is positioned as **SPIFFE / SPIRE compatible**. This page is
the honest section-by-section conformance audit against the
[SPIFFE specifications](https://github.com/spiffe/spiffe) (Workload
API, X.509-SVID, JWT-SVID, Trust Bundle Format, Federation), so
operators and reviewers can answer "exactly which parts of SPIFFE
does omega implement today" without reading the source.

Status legend:

- **implemented** — omega ships the surface and the existing tests
  exercise it.
- **partial** — omega ships some of the surface; gaps are listed in
  the notes column.
- **deferred** — the spec section is out of scope for the current
  charter; see [non-goals.md](non-goals.md) when applicable.

Spec versions audited:

| Spec | Version | Source |
| --- | --- | --- |
| SPIFFE ID | 1.0 (2020-09) | <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md> |
| SPIFFE Workload API | 1.0 (2020-09) | <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md> |
| X.509-SVID | 1.0 (2020-09) | <https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md> |
| JWT-SVID | 1.0 (2020-09) | <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md> |
| SPIFFE Trust Domain & Bundle | 1.0 (2020-09) | <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md> |
| SPIFFE Federation | 1.0 (2020-09) | <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md> |

## SPIFFE Workload API

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 3 | Workload API is a gRPC service over a UDS | implemented | `omega agent` serves `SpiffeWorkloadAPI` over `--socket` (default `/tmp/omega-agent.sock`); `peercred` attestor maps caller UID to SPIFFE ID |
| 4.1 | `FetchX509SVID` streaming RPC | implemented | `internal/agent/workloadapi/server.go` |
| 4.2 | `FetchX509Bundles` streaming RPC | implemented | streams updates when the local trust bundle changes |
| 4.3 | `FetchJWTSVID` unary RPC with audience | implemented | forwards to the control plane's `POST /v1/svid/jwt` |
| 4.4 | `ValidateJWTSVID` unary RPC | implemented | `internal/agent/workloadapi/server.go` `ValidateJWTSVID`; the agent verifies the token locally against the JWKS cached from the control plane (1-minute TTL, single-flight refresh — so a burst of validations costs one `GET /v1/jwt/bundle` per minute, not one per call) |
| 4.5 | `FetchJWTBundles` streaming RPC | implemented | exposes the trust domain's JWKS |
| 5 | Security: agent authenticates the caller via OS-level metadata | implemented | `SO_PEERCRED` on Linux; documented residual risk in `docs/threat-model.md` §S1 |
| 6 | Workload identity is asserted by an SVID | implemented | every fetch returns at least one SPIFFE ID |

## SPIFFE ID

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 2.1 | SPIFFE ID URI: `spiffe://<trust-domain>/<path>` | implemented | enforced via `github.com/spiffe/go-spiffe/v2/spiffeid` everywhere we accept an ID |
| 2.2 | Trust domain DNS-like labels | implemented | validated by `spiffeid.TrustDomainFromString` |
| 2.3 | Path component constraints | implemented | validated by `spiffeid.FromString` |
| 2.4 | Trust domain != SPIFFE ID (root has no path) | implemented | same |

## X.509-SVID

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 4.1 | Single SPIFFE ID in `subjectAltName.URIs` | implemented | `internal/server/identity/authority.go` `IssueSVID` |
| 4.2 | Subject DN: at most one `CN` derived from SPIFFE path | implemented | `localAuthority.signTemplate` |
| 4.3 | KeyUsage: digitalSignature, keyEncipherment when RSA | implemented | template sets `KeyUsageDigitalSignature` |
| 4.4 | ExtendedKeyUsage: serverAuth + clientAuth | implemented | mTLS is the default consumer |
| 4.5 | Basic constraints: CA=false | implemented | leaf only |
| 4.6 | NotBefore / NotAfter; default validity ≤ 24h | implemented | omega defaults to 30 minutes (`svidValidity`); see [ADR 0003](adr/0003-short-lived-svids-no-revocation.md) for the rotation-as-revocation rationale |
| 5 | Trust bundle is a set of PEM-encoded CA certs | implemented | `GET /v1/bundle` returns the PEM bundle |
| 6 | Validation: leaf chains to a CA in the bundle | implemented | `go-spiffe`'s X509Source does the chain build on the consumer side |
| 7 | Revocation | deferred | by design; short-lived rotation replaces CRL/OCSP per [ADR 0003](adr/0003-short-lived-svids-no-revocation.md) |

## JWT-SVID

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 3 | Issued as a JWS, alg from `RS256, ES256, …` | implemented | omega issues ES256 |
| 4.1 | `sub` claim is the SPIFFE ID | implemented | `internal/server/identity/jwt.go` |
| 4.2 | `aud` claim is the intended audience(s) | implemented | required field on issuance |
| 4.3 | `exp` claim within reasonable window | implemented | default 5 min, max 24 h |
| 4.4 | `iat` claim present | implemented | same |
| 4.5 | Optional `iss`, `jti` | partial | `jti` is always set; `iss` is opt-in via `--issuer-url` for OIDC-RP interop |
| 5 | JWT bundle is a JWKS | implemented | `GET /v1/jwt/bundle` returns `application/jwk-set+json` |
| 6 | Validation: verify signature against JWKS, check sub/aud/exp/nbf | implemented | `Authority.ValidateJWTSVID` |
| 7 | Token binding (RFC 8705) | implemented | `cnf.x5t#S256` via `--bind-cert-thumbprint`; checked by `ValidatePresentedCertBinding` |

## SPIFFE Bundle Format

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 4.1 | JWK Set with extended keys | partial | omega returns a standard RFC 7517 JWKS; the SPIFFE bundle JSON format (with `keys[].use`, `spiffe_sequence`, `spiffe_refresh_hint`) is not yet emitted - X.509 anchors are served as PEM at `/v1/bundle` and JWT anchors as JWKS at `/v1/jwt/bundle` |
| 5.1 | X.509 trust anchors | implemented | PEM at `/v1/bundle` |
| 5.2 | JWT signer keys | implemented | JWKS at `/v1/jwt/bundle` |
| 6 | Sequence / refresh hints | deferred | the `/v1/federation/bundles` endpoint serves a map of trust domain → PEM and is polled by peers; explicit refresh-hint emission is on the roadmap |

## SPIFFE Federation

| Section | Requirement | Status | omega notes |
| --- | --- | --- | --- |
| 4 | Trust bundle endpoint per trust domain | implemented | `GET /v1/bundle` (own anchors) and `GET /v1/federation/bundles` (own + cached peer anchors) |
| 5 | Trust bundle endpoint profile: HTTPS, signed | partial | omega serves bundles over HTTP/JSON by default; TLS termination is the deployment's responsibility (documented in `docs/threat-model.md` §S2). Signed bundle profile (HTTPS_SPIFFE_WEB or HTTPS_WEB) is consumer-side, not server-side, so omega satisfies this through whatever ingress/proxy fronts the API |
| 6 | Federation discovery / bundle refresh | implemented | `omega server --federate-with name=peer.example,url=https://peer.example/v1/bundle` polls peers with an exponential-backoff retry; cached bundles surface in `GET /v1/federation/bundles` |
| 7 | Trust domain membership changes propagate | implemented | re-fetch on poll picks up rotations |

## What is intentionally not implemented

- **CRL / OCSP / JTI deny list.** Per [ADR 0003](adr/0003-short-lived-svids-no-revocation.md),
  rotation replaces revocation. Same call SPIRE made.
- **Native SPIFFE Bundle Format with sequence + refresh hints.**
  Standard JWKS + PEM bundle is what every current consumer reads.
  A formal SPIFFE-bundle-JSON emitter is tracked in [ROADMAP.md](../ROADMAP.md).

## How this page is maintained

This page is updated whenever a change touches a spec-facing surface.
Reviewers ask for an update in the same PR for any change that
adds or modifies an endpoint listed above, or that flips a row
from `partial` to `implemented`. The companion page for AuthZEN
is at [conformance-authzen.md](conformance-authzen.md).
