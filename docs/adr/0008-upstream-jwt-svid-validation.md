# ADR 0008: Consume the upstream JWKS to validate upstream JWT-SVIDs

## Status

Accepted.

## Context

[ADR 0007](0007-pluggable-identity-source.md) introduced the
`spire-upstream` source as a non-issuing, validation-only identity
source: Omega consumes the upstream X.509 trust bundle, runs no CA, and
applies the authorization + audit layer over upstream-issued SVIDs. It
deliberately deferred one half of the SPIFFE credential set — JWT-SVIDs.
In that first cut `JWTBundle` served an empty JWKS so the combined
SPIFFE bundle document stayed well-formed, and the validation methods
reported they could not run. ADR 0007 recorded "implement upstream
JWT-SVID validation (consume the upstream JWKS)" as an explicit
follow-up obligation before claiming end-to-end Human / AI-agent JWT
flows under `spire-upstream`. This ADR records how that obligation is
met.

The asymmetry mattered: agents validate JWT-SVIDs **locally** against
the JWKS they pull from the control plane (`/v1/jwt/bundle`). With an
empty JWKS in upstream mode that local validation could never succeed,
so an upstream SPIRE / Istio deployment that minted JWT-SVIDs had no
working JWT path through Omega.

## Decision

The `spire-upstream` source consumes an **upstream JWKS** supplied by
the operator and uses it as the JWT trust anchor, mirroring how the
X.509 bundle is wired.

- A new optional flag, `--identity-source-jwt-bundle`, points at the
  upstream trust domain's JWT bundle (an RFC 7517 JWKS). It is loaded
  from a file at boot with no network dependency, exactly like
  `--identity-source-bundle`. Omitting it keeps upstream consumption
  X.509-only — the prior behaviour — so existing deployments are
  unaffected.
- `JWTBundle` now serves the upstream signing keys at `/v1/jwt/bundle`,
  so agents pull them and validate upstream JWT-SVIDs locally, and the
  combined SPIFFE bundle endpoint carries them.
- `ValidateJWTSVID`, `ParseJWTSVIDClaims`, and
  `ValidatePresentedCertBinding` verify a presented token against the
  consumed keys: select the key by the token's `kid`, check the
  signature, enforce `exp` / `nbf` / `iat` (and audience where
  required), and confirm the subject is a member of the upstream trust
  domain. The cert-binding path keeps the RFC 8705 `cnf.x5t#S256` check.
- When no upstream JWKS was supplied these methods return a distinct
  `ErrUpstreamJWTNotConfigured` rather than the issuance error, so an
  X.509-only deployment gets a precise "not configured" signal instead
  of a misleading "issuance unsupported".

Only EC P-256 (ES256) keys are consumed, matching Omega's existing
JWT-SVID path — issuance, the agent's local validator — and the SPIRE /
Istio defaults. Keys that are structurally not ours — other key types,
other curves, or non-signing (`use` other than `sig`) keys — are ignored
per RFC 7517 §5, so a heterogeneous upstream JWKS (mixed EC / RSA during
a key transition, an encryption key beside the signer) stays usable as
long as it carries at least one EC P-256 signing key. A bundle that
yields no usable signing key fails at boot rather than serving an empty
JWKS by surprise.

A *recognised* EC P-256 signing key that cannot be consumed — a bad or
off-curve coordinate, a missing `kid`, a duplicate `kid` — is a corrupt
trust anchor, not a foreign one, and fails closed at boot rather than
being silently dropped.

The issuance posture from ADR 0007 is unchanged: this source still runs
no CA, and the issuance / token-exchange routes still return **501**.
Consuming the upstream JWKS adds **validation**, not minting.

## Consequences

Easier:

- Upstream JWT-SVIDs now have a working end-to-end path through Omega:
  agents validate them locally against the consumed upstream keys, so
  Human / AI-agent JWT flows can run under `spire-upstream`.
- The wiring mirrors the X.509 bundle — file-based, no boot-time network
  dependency — so an operator already running upstream SPIFFE configures
  it with material they have.

Harder:

- The operator now supplies and rotates a second piece of upstream trust
  material (the JWKS) when they want JWT flows. Rotation is a file swap
  plus restart, the same lifecycle as the X.509 bundle.
- Only EC P-256 is consumed. An upstream domain whose JWT-SVIDs are
  signed with RSA or another curve has those keys ignored, so those
  tokens cannot be validated until that algorithm support is added — the
  JWKS still loads as long as it also carries an EC P-256 signing key.

New obligations:

- Keep the consumed-JWKS path and the agent's local validator on the
  same algorithm set; widening one without the other reintroduces the
  "unknown kid" failure this ADR removed.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes — the JWT issuer is the same upstream system ADR 0007 placed in the
Plugin seam. This ADR extends that source from X.509-only consumption to
full SPIFFE credential consumption (X.509 + JWT) without changing the
non-issuing model.
