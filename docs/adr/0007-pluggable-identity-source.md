# ADR 0007: Pluggable identity source - issue or consume, never re-implement

## Status

Accepted.

## Context

[ADR 0005](0005-ca-plugin-architecture.md) made the `Authority`
interface the CA-backend seam: it selects *where signing happens*
(disk / Vault PKI / step-ca) while Omega remains the issuer. A
separate axis is whether Omega issues identities *at all*. The
project's direction is to stop re-implementing SPIRE and instead let
Omega consume SPIFFE identities an upstream issuer (SPIRE / Istio)
already mints, keeping only the durable wedge - the SPIFFE ID as a
first-class AuthZEN subject with a cross-cutting audit trail.

`identity.Source` was introduced above `Authority` as that seam, with
the built-in (issuing) source as the only implementation and the
self-signed disk CA marked dev/eval-only. This ADR records how the
second source - `spire-upstream` - consumes, and which model was
deliberately *not* chosen.

The credential path already favours consumption: client mTLS is
verified against the operator-supplied `--client-ca` pool, not Omega's
own root, and `requireSPIFFEAuth` derives the caller identity from the
verified cert's URI SAN. The AuthZEN PDP takes the subject SPIFFE ID
from the request body regardless of who issued it. So the authz + audit
layer can already run on upstream-issued identities; what an upstream
source must add is on the *issuance* side.

## Decision

`spire-upstream` is a **non-issuing, validation-only** source.

- It carries the upstream trust domain and its X.509 trust bundle,
  loaded from a file (`--identity-source-bundle`, the same PEM material
  an operator wires into `--client-ca`). `--trust-domain` names the
  upstream domain. No network dependency at boot.
- `BundlePEM` / `TrustDomain` serve the upstream root, so `/v1/bundle`,
  federation, and downstream peers chain to the upstream CA.
- Every minting / local-signing method returns `ErrIssuanceUnsupported`;
  the API layer wraps the issuance and token-exchange routes
  (`/v1/svid`, `/v1/svid/jwt`, `/v1/attest/k8s`, `/v1/token/exchange`,
  `/v1/oidc/exchange`) so they report **501** in this mode.
- Upstream JWT-SVID authorities are not consumed yet: `JWTBundle` serves
  an empty JWKS so the combined SPIFFE bundle document stays valid.
  Validating upstream JWT-SVIDs is a follow-up.

The rejected alternative was an **issuance proxy** that forwards CSRs to
upstream SPIRE. SPIRE has no generic CSR-signing API - it issues via its
own attestation - so a proxy would re-wrap (effectively re-implement)
SPIRE, which is exactly the burden this direction sheds.

## Consequences

Easier:

- Omega stops owning a CA in this mode; workloads get SVIDs from the
  upstream SPIRE / Istio agent, and Omega is the authz + audit layer on
  top - the wedge, without the issuance maintenance load.
- File-based bundle wiring mirrors `--client-ca`, so an operator already
  running upstream SPIFFE configures it with material they have.

Harder:

- JWT-SVID flows (token exchange, OIDC exchange, local JWT issuance) are
  unavailable in `spire-upstream` mode until upstream JWKS consumption
  lands; those routes return 501.
- The mode trades the zero-dependency `make demo` issuance funnel for a
  real upstream; built-in remains the default so the demo path is
  unchanged.

New obligations:

- Implement upstream JWT-SVID validation (consume the upstream JWKS) as a
  follow-up before claiming end-to-end Human / AI-agent JWT flows under
  `spire-upstream`.
- Keep the 501 surface honest: a route that starts depending on local
  signing must be added to the issuing-only guard.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes - the identity issuer is an upstream system. `Source` is the Plugin
seam for it: built-in issuing default, external (upstream-SPIFFE)
implementation. This ADR records the consume model and the conscious
rejection of an issuance proxy.
